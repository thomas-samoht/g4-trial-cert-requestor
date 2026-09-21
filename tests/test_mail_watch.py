import datetime as dt
import io
import zipfile
from email.header import Header
from email.message import EmailMessage
from unittest import mock

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import mail_watch

# --- _slugify ---


def test_slugify_replaces_spaces_and_unsafe_chars():
    assert mail_watch._slugify("Some Organization") == "Some_Organization"
    assert mail_watch._slugify("weird/name:here") == "weird_name_here"


def test_slugify_falls_back_to_unnamed_when_empty():
    assert mail_watch._slugify("!!!") == "unnamed"


# --- _decode ---


def test_decode_returns_empty_string_for_none():
    assert mail_watch._decode(None) == ""


def test_decode_passes_through_plain_ascii():
    assert mail_watch._decode("cert.zip") == "cert.zip"


def test_decode_handles_encoded_word_header():
    encoded = Header("café.zip", "utf-8").encode()
    assert mail_watch._decode(encoded) == "café.zip"


# --- _find_matching_uid ---


def _header_bytes(date_str: str | None) -> bytes:
    msg = EmailMessage()
    if date_str is not None:
        msg["Date"] = date_str
    return msg.as_bytes()


def test_find_matching_uid_returns_none_when_no_messages():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b""])
    result = mail_watch._find_matching_uid(imap, "sender@example.com", dt.datetime.now(dt.UTC))
    assert result is None


def test_find_matching_uid_skips_messages_before_not_before():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1"])
    imap.fetch.return_value = (
        "OK",
        [(b"1 (...)", _header_bytes("Mon, 01 Jan 2024 00:00:00 +0000"))],
    )

    not_before = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    result = mail_watch._find_matching_uid(imap, "sender@example.com", not_before)
    assert result is None


def test_find_matching_uid_returns_uid_for_message_after_not_before():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1"])
    imap.fetch.return_value = (
        "OK",
        [(b"1 (...)", _header_bytes("Mon, 01 Jan 2026 00:00:00 +0000"))],
    )

    not_before = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    result = mail_watch._find_matching_uid(imap, "sender@example.com", not_before)
    assert result == b"1"


def test_find_matching_uid_skips_messages_with_failed_fetch():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1 2"])
    imap.fetch.side_effect = [
        ("NO", None),
        ("OK", [(b"2 (...)", _header_bytes("Mon, 01 Jan 2026 00:00:00 +0000"))]),
    ]

    not_before = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    result = mail_watch._find_matching_uid(imap, "sender@example.com", not_before)
    assert result == b"2"


def test_find_matching_uid_treats_unparseable_date_as_match():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1"])
    # Built as raw header bytes because EmailMessage's Date setter validates
    # and silently drops values it can't parse, which would defeat the point
    # of this test.
    imap.fetch.return_value = ("OK", [(b"1 (...)", b"Date: not-a-date\r\n\r\n")])

    not_before = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    result = mail_watch._find_matching_uid(imap, "sender@example.com", not_before)
    assert result == b"1"


def test_find_matching_uid_replaces_missing_tzinfo():
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1"])
    imap.fetch.return_value = (
        "OK",
        [(b"1 (...)", _header_bytes("Mon, 01 Jan 2026 00:00:00 -0000"))],
    )

    not_before = dt.datetime(2025, 1, 1, tzinfo=dt.UTC)
    result = mail_watch._find_matching_uid(imap, "sender@example.com", not_before)
    assert result == b"1"


# --- _extract_zip_attachment ---


def test_extract_zip_attachment_raises_when_fetch_fails():
    imap = mock.Mock()
    imap.fetch.return_value = ("NO", None)
    with pytest.raises(RuntimeError, match="Failed to fetch"):
        mail_watch._extract_zip_attachment(imap, b"1")


def test_extract_zip_attachment_raises_when_no_zip_found():
    msg = EmailMessage()
    msg.set_content("plain body, no attachment")
    imap = mock.Mock()
    imap.fetch.return_value = ("OK", [(b"1 (...)", msg.as_bytes())])
    with pytest.raises(RuntimeError, match="No .zip attachment"):
        mail_watch._extract_zip_attachment(imap, b"1")


def test_extract_zip_attachment_returns_filename_and_bytes():
    msg = EmailMessage()
    msg.set_content("See attached.")
    msg.add_attachment(
        b"zip-bytes-here", maintype="application", subtype="zip", filename="cert.zip"
    )
    imap = mock.Mock()
    imap.fetch.return_value = ("OK", [(b"1 (...)", msg.as_bytes())])

    filename, payload = mail_watch._extract_zip_attachment(imap, b"1")

    assert filename == "cert.zip"
    assert payload == b"zip-bytes-here"


# --- _convert_cer_to_crt ---


def _build_der_cert() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test.example.nl")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.UTC))
        .not_valid_after(dt.datetime.now(dt.UTC) + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def test_convert_cer_to_crt_produces_matching_pem(tmp_path):
    der_bytes = _build_der_cert()
    cer_path = tmp_path / "cert.cer"
    cer_path.write_bytes(der_bytes)
    crt_path = tmp_path / "cert.crt"

    mail_watch._convert_cer_to_crt(cer_path, crt_path)

    loaded = x509.load_pem_x509_certificate(crt_path.read_bytes())
    assert loaded.public_bytes(serialization.Encoding.DER) == der_bytes


# --- wait_and_process ---


def _zip_bytes(name: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr(name, content)
    return buf.getvalue()


def _cert_email_bytes(zip_bytes: bytes, date: dt.datetime) -> bytes:
    msg = EmailMessage()
    msg["Subject"] = "Your G4 TRIAL certificate"
    msg["Date"] = date.strftime("%a, %d %b %Y %H:%M:%S +0000")
    msg.set_content("See attached.")
    msg.add_attachment(zip_bytes, maintype="application", subtype="zip", filename="cert.zip")
    return msg.as_bytes()


def _fake_imap(msg_bytes: bytes) -> mock.Mock:
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b"1"])
    imap.fetch.return_value = ("OK", [(b"1 (...)", msg_bytes)])
    return imap


def _base_config(tmp_path) -> dict:
    return {
        "MAIL_USERNAME": "you@example.com",
        "MAIL_PASSWORD": "secret",
        "MAIL_SERVER": "mail.example.com",
        "OUTPUT_FOLDER": str(tmp_path),
        "MAIL_POLL_INTERVAL": "0",
        "MAIL_TIMEOUT": "5",
    }


def test_wait_and_process_downloads_and_converts_certificate(tmp_path):
    der_bytes = _build_der_cert()
    msg_bytes = _cert_email_bytes(_zip_bytes("cert.cer", der_bytes), dt.datetime.now(dt.UTC))
    imap = _fake_imap(msg_bytes)

    with mock.patch.object(mail_watch.imaplib, "IMAP4_SSL", return_value=imap):
        out_dir = mail_watch.wait_and_process(
            _base_config(tmp_path),
            "Some Org",
            "00000003123456780000",
            "trialG4-secret",
            dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1),
        )

    assert (out_dir / "pfx-password.txt").read_text() == "trialG4-secret\n"
    crt_files = list(out_dir.glob("*.crt"))
    assert len(crt_files) == 1
    loaded = x509.load_pem_x509_certificate(crt_files[0].read_bytes())
    assert loaded.public_bytes(serialization.Encoding.DER) == der_bytes
    imap.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")
    imap.logout.assert_called_once()


def test_wait_and_process_warns_when_no_cer_file(tmp_path, capsys):
    msg_bytes = _cert_email_bytes(_zip_bytes("readme.txt", b"not a cert"), dt.datetime.now(dt.UTC))
    imap = _fake_imap(msg_bytes)

    with mock.patch.object(mail_watch.imaplib, "IMAP4_SSL", return_value=imap):
        out_dir = mail_watch.wait_and_process(
            _base_config(tmp_path),
            "Some Org",
            "00000003123456780000",
            "trialG4-secret",
            dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1),
        )

    assert "no .cer file found" in capsys.readouterr().err
    assert list(out_dir.glob("*.crt")) == []
    assert (out_dir / "pfx-password.txt").exists()


def test_wait_and_process_raises_timeout_error(tmp_path):
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b""])

    config = _base_config(tmp_path)
    config["MAIL_TIMEOUT"] = "0"

    with (
        mock.patch.object(mail_watch.imaplib, "IMAP4_SSL", return_value=imap),
        pytest.raises(TimeoutError),
    ):
        mail_watch.wait_and_process(
            config,
            "Some Org",
            "00000003123456780000",
            "trialG4-secret",
            dt.datetime.now(dt.UTC),
        )

    imap.logout.assert_called_once()


def test_wait_and_process_polls_again_when_no_match_yet(tmp_path):
    der_bytes = _build_der_cert()
    msg_bytes = _cert_email_bytes(_zip_bytes("cert.cer", der_bytes), dt.datetime.now(dt.UTC))
    imap = mock.Mock()
    imap.search.side_effect = [("OK", [b""]), ("OK", [b"1"])]
    imap.fetch.return_value = ("OK", [(b"1 (...)", msg_bytes)])

    with (
        mock.patch.object(mail_watch.imaplib, "IMAP4_SSL", return_value=imap),
        mock.patch.object(mail_watch.time, "sleep") as sleep_mock,
    ):
        out_dir = mail_watch.wait_and_process(
            _base_config(tmp_path),
            "Some Org",
            "00000003123456780000",
            "trialG4-secret",
            dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1),
        )

    sleep_mock.assert_called_once()
    assert (out_dir / "pfx-password.txt").exists()


def test_wait_and_process_ignores_logout_errors(tmp_path):
    imap = mock.Mock()
    imap.search.return_value = ("OK", [b""])
    imap.logout.side_effect = OSError("connection already closed")

    config = _base_config(tmp_path)
    config["MAIL_TIMEOUT"] = "0"

    with (
        mock.patch.object(mail_watch.imaplib, "IMAP4_SSL", return_value=imap),
        pytest.raises(TimeoutError),
    ):
        mail_watch.wait_and_process(
            config,
            "Some Org",
            "00000003123456780000",
            "trialG4-secret",
            dt.datetime.now(dt.UTC),
        )

    imap.logout.assert_called_once()
