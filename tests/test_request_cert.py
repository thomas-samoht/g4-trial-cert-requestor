import sys
from pathlib import Path
from unittest import mock

import pytest

import mail_watch
import request_cert

# --- validate_oin ---


def test_validate_oin_accepts_valid_oin():
    assert request_cert.validate_oin("00000003123456780000") == "00000003123456780000"


def test_validate_oin_rejects_invalid_oin():
    with pytest.raises(SystemExit):
        request_cert.validate_oin("not-an-oin")


# --- validate_domain ---


def test_validate_domain_accepts_valid_domain():
    assert request_cert.validate_domain("test.example.nl") == "test.example.nl"


@pytest.mark.parametrize("domain", ["*.example.nl", "no-dots", ""])
def test_validate_domain_rejects_invalid_domain(domain):
    with pytest.raises(SystemExit):
        request_cert.validate_domain(domain)


# --- validate_email ---


def test_validate_email_accepts_valid_email():
    assert request_cert.validate_email("you@example.com") == "you@example.com"


@pytest.mark.parametrize("email", ["not-an-email", "missing-domain@", "@missing-user.com"])
def test_validate_email_rejects_invalid_email(email):
    with pytest.raises(SystemExit):
        request_cert.validate_email(email)


# --- extract_pfx_password ---


def test_extract_pfx_password_finds_password():
    html = (
        "Het <strong>wachtwoord</strong> van uw certificaat is: "
        "<strong><code>trialG4-PKIpartners</code>"
    )
    assert request_cert.extract_pfx_password(html) == "trialG4-PKIpartners"


def test_extract_pfx_password_returns_none_when_absent():
    assert request_cert.extract_pfx_password("<html>no password here</html>") is None


# --- warn_if_too_long ---


def test_warn_if_too_long_warns_for_long_cn(capsys):
    request_cert.warn_if_too_long("x" * 60)
    captured = capsys.readouterr()
    assert "organization" in captured.err
    assert "longer than" in captured.err


def test_warn_if_too_long_silent_for_short_cn(capsys):
    request_cert.warn_if_too_long("Short Org")
    captured = capsys.readouterr()
    assert captured.err == ""


# --- load_config / require ---


def test_load_config_parses_key_values(tmp_path):
    config_path = tmp_path / "config.env"
    config_path.write_text('# a comment\n\nEMAIL="you@example.com"\nDOMAINS=test.example.nl\n')
    config = request_cert.load_config(config_path)
    assert config == {"EMAIL": "you@example.com", "DOMAINS": "test.example.nl"}


def test_load_config_missing_file_exits(tmp_path):
    with pytest.raises(SystemExit):
        request_cert.load_config(tmp_path / "does-not-exist.env")


def test_require_returns_value_when_present():
    assert request_cert.require({"EMAIL": "you@example.com"}, "EMAIL") == "you@example.com"


def test_require_exits_when_missing():
    with pytest.raises(SystemExit):
        request_cert.require({}, "EMAIL")


# --- main(): mail step is optional ---


# --- fetch_csrf_token ---


def test_fetch_csrf_token_exits_when_token_missing():
    session = mock.Mock()
    resp = mock.Mock(text="<html>no token here</html>")
    resp.raise_for_status = mock.Mock()
    session.get.return_value = resp

    with pytest.raises(SystemExit):
        request_cert.fetch_csrf_token(session)


def _mock_session(submit_ok=True, submit_status=200, submit_text=None):
    embed_resp = mock.Mock(text='name="csrf_token" value="abc123"')
    embed_resp.raise_for_status = mock.Mock()

    submit_resp = mock.Mock(status_code=submit_status, ok=submit_ok)
    submit_resp.text = (
        submit_text
        if submit_text is not None
        else "wachtwoord</strong> is: <code>trialG4-secret</code>"
    )

    session = mock.Mock()
    session.get.return_value = embed_resp
    session.post.return_value = submit_resp
    return session


def _write_config(tmp_path: Path, extra: str = "") -> Path:
    config_path = tmp_path / "config.env"
    config_path.write_text("EMAIL=you@example.com\nDOMAINS=test.example.nl\n" + extra)
    return config_path


def _run_main(config_path: Path, cn: str = "Some Org"):
    argv = [
        "request_cert.py",
        cn,
        "00000003123456780000",
        "--config",
        str(config_path),
    ]
    with mock.patch.object(sys, "argv", argv):
        request_cert.main()


def test_main_skips_mail_wait_when_mail_server_unset(tmp_path, capsys):
    config_path = _write_config(tmp_path)

    with (
        mock.patch.object(request_cert.requests, "Session", return_value=_mock_session()),
        mock.patch.object(mail_watch, "wait_and_process") as wait_mock,
    ):
        _run_main(config_path)

    wait_mock.assert_not_called()
    assert "skipping wait for certificate email" in capsys.readouterr().out


def test_main_waits_for_mail_when_mail_server_set(tmp_path):
    config_path = _write_config(
        tmp_path,
        extra="MAIL_USERNAME=you@example.com\nMAIL_PASSWORD=secret\nMAIL_SERVER=mail.example.com\n",
    )

    with (
        mock.patch.object(request_cert.requests, "Session", return_value=_mock_session()),
        mock.patch.object(
            mail_watch, "wait_and_process", return_value=Path("./output/fake")
        ) as wait_mock,
    ):
        _run_main(config_path)

    wait_mock.assert_called_once()


def test_main_exits_when_cn_too_short(tmp_path):
    config_path = _write_config(tmp_path)

    with pytest.raises(SystemExit):
        _run_main(config_path, cn="x")


def test_main_exits_when_submit_fails(tmp_path, capsys):
    config_path = _write_config(tmp_path)
    session = _mock_session(submit_ok=False, submit_status=500, submit_text="server error")

    with (
        mock.patch.object(request_cert.requests, "Session", return_value=session),
        pytest.raises(SystemExit),
    ):
        _run_main(config_path)

    assert "Request failed" in capsys.readouterr().out


def test_main_exits_when_pfx_password_missing(tmp_path):
    config_path = _write_config(tmp_path)
    session = _mock_session(submit_text="no password here")

    with (
        mock.patch.object(request_cert.requests, "Session", return_value=session),
        pytest.raises(SystemExit),
    ):
        _run_main(config_path)
