#!/usr/bin/env python3
"""Request a G4 TRIAL certificate from https://g4trial.pkipartners.nl by CN and OIN.

Replicates the POST that the embed form at /embed sends to /submit
(see cert-form.js on that page). Always uses the profile
"Private TLS Generic Devices Organization Validated ServerAuthentication"
(G4TRIALEEPrivGTLSSYS2025), the only profile that takes a domain name and
an OIN.
"""

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

import mail_watch

BASE_URL = "https://g4trial.pkipartners.nl"
EMBED_URL = f"{BASE_URL}/embed"
SUBMIT_URL = f"{BASE_URL}/submit"

PROFILE = "G4TRIALEEPrivGTLSSYS2025"
COUNTRY = "NL"

# Same rules as cert-form.js on the embed page.
OIN_PATTERN = re.compile(r"^000000[0-9]{2}[0-9]{8,9}0{3,4}$")
DOMAIN_PATTERN = re.compile(r"^(?!\*\.)[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")
EMAIL_PATTERN = re.compile(r"^\S+@\S+\.\S+$")
CSRF_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')
# The submit confirmation page shows the PFX password in an
# alert-success block, e.g.:
#   Het <strong>wachtwoord</strong> van uw ... certificaat is: <strong><code>trialG4-PKIpartners</code>
PASSWORD_RE = re.compile(r"wachtwoord</strong>.*?<code>([^<]+)</code>", re.DOTALL)

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent / "config.env"


def load_config(path: Path) -> dict:
    if not path.exists():
        sys.exit(
            f"Config file not found: {path}\n"
            f"Copy config.example.env to {path.name} and fill in EMAIL."
        )
    config = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        config[key.strip()] = value.strip().strip('"').strip("'")
    return config


def require(config: dict, key: str) -> str:
    value = config.get(key)
    if not value:
        sys.exit(f"Missing required config value: {key} (set it in config.env)")
    return value


def validate_oin(oin: str) -> str:
    oin = oin.strip().upper()
    if not OIN_PATTERN.match(oin):
        sys.exit(
            "Invalid OIN: expected 20 digits in the form 000000XX + 8-9 digits + 0-padding, "
            "e.g. 00000003123456780000.\n"
            "Look it up at https://oinregister.logius.nl/oin-register if unsure."
        )
    return oin


def validate_domain(domain: str) -> str:
    domain = domain.strip()
    if not DOMAIN_PATTERN.match(domain):
        sys.exit(f"Invalid domain in config DOMAINS: {domain!r}")
    return domain


def validate_email(email: str) -> str:
    email = email.strip()
    if not EMAIL_PATTERN.match(email):
        sys.exit(f"Invalid email in config EMAIL: {email!r}")
    return email


def extract_pfx_password(html: str) -> str | None:
    match = PASSWORD_RE.search(html)
    return match.group(1).strip() if match else None


def fetch_csrf_token(session: requests.Session) -> str:
    resp = session.get(EMBED_URL, timeout=30)
    resp.raise_for_status()
    match = CSRF_RE.search(resp.text)
    if not match:
        sys.exit("Could not find csrf_token on the embed page; the site may have changed.")
    return match.group(1)


FIELD_LIMITS = {
    "organization": 55,
    "locality": 64,
    "firstName": 20,
    "lastName": 40,
}


def warn_if_too_long(cn: str) -> None:
    for field, limit in FIELD_LIMITS.items():
        if len(cn) > limit:
            print(
                f"Warning: CN is {len(cn)} chars, longer than the {limit}-char limit "
                f"of the '{field}' field. The server may reject or truncate it.",
                file=sys.stderr,
            )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Request a G4 TRIAL certificate from PKIpartners (CN + OIN only; "
        "everything else comes from config.env)."
    )
    parser.add_argument("cn", nargs="?", help="Common Name")
    parser.add_argument("oin", nargs="?", help="Organisatie Identificatienummer (20 digits)")
    parser.add_argument(
        "--config",
        default=str(DEFAULT_CONFIG_PATH),
        help="Path to config.env (default: config.env next to this script)",
    )
    args = parser.parse_args()

    cn = (args.cn or input("CN: ")).strip()
    oin_raw = (args.oin or input("OIN: ")).strip()

    if len(cn) < 2:
        sys.exit("CN must be at least 2 characters.")
    warn_if_too_long(cn)

    oin = validate_oin(oin_raw)

    config = load_config(Path(args.config))
    email = validate_email(require(config, "EMAIL"))
    domains = validate_domain(config.get("DOMAINS", "test.example.com"))
    phone = config.get("PHONE", "+31 6 12345678")
    key_size = config.get("KEY_SIZE", "4096")

    # Mail polling is optional: only require the mailbox settings if
    # MAIL_SERVER is configured. Fail before submitting anything if it's
    # configured but incomplete - a submitted request whose email can't
    # be fetched is wasted.
    mail_enabled = bool(config.get("MAIL_SERVER"))
    if mail_enabled:
        require(config, "MAIL_USERNAME")
        require(config, "MAIL_PASSWORD")
        require(config, "MAIL_SERVER")

    session = requests.Session()
    csrf_token = fetch_csrf_token(session)

    data = {
        "csrf_token": csrf_token,
        "embed": "1",
        "profile": PROFILE,
        "key_size": key_size,
        "organization": cn,
        "locality": cn,
        "country": COUNTRY,
        "orgIdType": "OIN",
        "orgIdValue": oin,
        "firstName": cn,
        "lastName": cn,
        "email": email,
        "phone": phone,
        "domains": domains,
        "website": "",  # honeypot; must stay empty
        "terms": "on",
    }

    not_before = datetime.now(timezone.utc)
    resp = session.post(SUBMIT_URL, data=data, headers={"Referer": EMBED_URL}, timeout=30)

    print(f"HTTP {resp.status_code}")
    if not resp.ok:
        print("Request failed. Response body:")
        print(resp.text[:2000])
        sys.exit(1)

    pfx_password = extract_pfx_password(resp.text)
    if not pfx_password:
        sys.exit(
            "Request submitted, but could not find the PFX password on the confirmation "
            "page; the site may have changed. Aborting before waiting for the email."
        )

    print("Request submitted.")
    print(f"PFX password: {pfx_password}")

    if not mail_enabled:
        print("MAIL_SERVER not configured; skipping wait for certificate email.")
        return

    out_dir = mail_watch.wait_and_process(config, cn, oin, pfx_password, not_before)
    print(f"Done. Certificate files saved to: {out_dir}")


if __name__ == "__main__":
    main()
