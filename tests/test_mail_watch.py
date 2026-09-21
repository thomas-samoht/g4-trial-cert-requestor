import datetime as dt
from email.message import EmailMessage
from unittest import mock

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


# --- _convert_cer_to_crt ---


def test_convert_cer_to_crt_produces_matching_pem(tmp_path):
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

    cer_path = tmp_path / "cert.cer"
    cer_path.write_bytes(cert.public_bytes(serialization.Encoding.DER))
    crt_path = tmp_path / "cert.crt"

    mail_watch._convert_cer_to_crt(cer_path, crt_path)

    loaded = x509.load_pem_x509_certificate(crt_path.read_bytes())
    assert loaded.serial_number == cert.serial_number
