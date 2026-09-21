"""Wait for the G4 TRIAL certificate email over IMAP and unpack it.

The g4trial.pkipartners.nl embed form emails a zip containing the issued
certificate a few minutes after a successful submission. This polls the
configured mailbox for that email, downloads the zip, extracts it into
{OUTPUT_FOLDER}/{oin}-{cn}-{datetime}/, converts the DER-encoded .cer file
to a PEM .crt, and writes the PFX password (shown on the submit
confirmation page, not in the email) alongside it.
"""

import email
import imaplib
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from email.header import decode_header
from email.utils import parsedate_to_datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization

SAFE_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _slugify(value: str) -> str:
    value = value.strip().replace(" ", "_")
    value = SAFE_CHARS_RE.sub("_", value)
    return value.strip("_") or "unnamed"


def _decode(value) -> str:
    if value is None:
        return ""
    decoded = ""
    for text, enc in decode_header(value):
        if isinstance(text, bytes):
            decoded += text.decode(enc or "utf-8", errors="replace")
        else:
            decoded += text
    return decoded


def _find_matching_uid(imap: imaplib.IMAP4_SSL, sender: str, not_before: datetime):
    status, data = imap.search(None, "UNSEEN", "FROM", f'"{sender}"')
    if status != "OK" or not data or not data[0]:
        return None

    for num in data[0].split():
        status, msg_data = imap.fetch(num, "(BODY.PEEK[HEADER.FIELDS (DATE)])")
        if status != "OK" or not msg_data or not msg_data[0]:
            continue
        header = email.message_from_bytes(msg_data[0][1])
        date_str = header.get("Date")
        msg_date = None
        if date_str:
            try:
                msg_date = parsedate_to_datetime(date_str)
            except (TypeError, ValueError):
                msg_date = None
        if msg_date is not None:
            if msg_date.tzinfo is None:
                msg_date = msg_date.replace(tzinfo=timezone.utc)
            if msg_date < not_before:
                continue
        return num

    return None


def _extract_zip_attachment(imap: imaplib.IMAP4_SSL, uid: bytes):
    status, msg_data = imap.fetch(uid, "(RFC822)")
    if status != "OK" or not msg_data or not msg_data[0]:
        raise RuntimeError("Failed to fetch the matching email.")

    msg = email.message_from_bytes(msg_data[0][1])
    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue
        filename = _decode(filename)
        if filename.lower().endswith(".zip"):
            return filename, part.get_payload(decode=True)

    raise RuntimeError("No .zip attachment found in the matching email.")


def _convert_cer_to_crt(cer_path: Path, crt_path: Path) -> None:
    cert = x509.load_der_x509_certificate(cer_path.read_bytes())
    crt_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def wait_and_process(
    config: dict, cn: str, oin: str, pfx_password: str, not_before: datetime
) -> Path:
    username = config["MAIL_USERNAME"]
    password = config["MAIL_PASSWORD"]
    server = config["MAIL_SERVER"]
    sender = config.get("MAIL_SENDER", "g4trial@pkipartners.nl")
    output_root = Path(config.get("OUTPUT_FOLDER", "./output"))
    poll_interval = float(config.get("MAIL_POLL_INTERVAL", "15"))
    timeout = float(config.get("MAIL_TIMEOUT", "600"))

    print(
        f"Waiting for certificate email from {sender} "
        f"(checking every {poll_interval:.0f}s, timeout {timeout:.0f}s)..."
    )

    deadline = time.monotonic() + timeout
    imap = imaplib.IMAP4_SSL(server)
    try:
        imap.login(username, password)
        while True:
            imap.select("INBOX")
            uid = _find_matching_uid(imap, sender, not_before)
            if uid:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"No email from {sender} arrived within {timeout:.0f}s.")
            time.sleep(poll_interval)

        filename, zip_bytes = _extract_zip_attachment(imap, uid)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        out_dir = output_root / f"{_slugify(oin)}-{_slugify(cn)}-{timestamp}"
        out_dir.mkdir(parents=True, exist_ok=True)

        zip_path = out_dir / filename
        zip_path.write_bytes(zip_bytes)

        with zipfile.ZipFile(zip_path) as zf:
            zf.extractall(out_dir)

        cer_files = sorted(out_dir.glob("*.cer"))
        if not cer_files:
            print("Warning: no .cer file found in the zip; skipping PEM conversion.", file=sys.stderr)
        for cer_file in cer_files:
            _convert_cer_to_crt(cer_file, cer_file.with_suffix(".crt"))

        (out_dir / "pfx-password.txt").write_text(pfx_password + "\n")

        imap.store(uid, "+FLAGS", "\\Seen")

        return out_dir
    finally:
        try:
            imap.logout()
        except Exception:
            pass
