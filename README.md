# g4-trial-cert-requestor

Command-line automation for requesting a G4 TRIAL certificate from
[g4trial.pkipartners.nl](https://g4trial.pkipartners.nl/embed), waiting
for the resulting email, and unpacking the certificate, without ever
touching the web form or a mail client.

It always requests the profile **Private TLS Generic Devices Organization
Validated ServerAuthentication (44.35.11)** (`G4TRIALEEPrivGTLSSYS2025`).

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```bash
cp config.example.env config.env
```

Edit `config.env` and fill in:

- `EMAIL`: where the certificate is sent (also the account the mailbox
  settings below must read from).
- `MAIL_USERNAME` / `MAIL_PASSWORD` / `MAIL_SERVER`: IMAP login for that
  mailbox (e.g. `mail.server.com`).

`DOMAINS`, `PHONE`, `KEY_SIZE`, `MAIL_SENDER`, `MAIL_POLL_INTERVAL`,
`MAIL_TIMEOUT`, and `OUTPUT_FOLDER` have working defaults but can be
overridden there too. `config.env` is gitignored, so none of this is
committed.

## Usage

```bash
uv run request_cert.py
```

`uv run` creates the virtualenv and installs dependencies automatically
on first use.

You'll be prompted for:

1. **CN**: used as-is for the organization, locality, first name, and
   last name fields on the request.
2. **OIN**: the 20-digit Organisatie Identificatienummer, format
   `000000XX` + 8-9 digits + zero-padding (e.g. `00000003123456780000`).
   Look it up at the
   [Centrale OIN Raadpleegvoorziening](https://oinregister.logius.nl/oin-register)
   if you don't have it handy.

Or pass both as arguments to skip the prompts:

```bash
uv run request_cert.py "Some Organization" 00000003123456780000
```

The script then submits the request, waits (polling IMAP) for the reply
from `g4trial@pkipartners.nl`, and unpacks it.

## Output

Each run creates `{OUTPUT_FOLDER}/{oin}-{cn}-{datetime}/` containing:

- Everything from the emailed zip as-is: the `.key` (private key), `.pfx`
  (password-protected bundle), `.p7b` (chain), and the original `.cer`.
- `<name>.crt`: the `.cer` converted from DER to PEM.
- `pfx-password.txt`: the PFX password, which is fixed per trial batch
  and shown only on the `/submit` confirmation page (not in the email),
  so it's captured and saved automatically.

## How it works

The `/embed` page's form posts directly to `/submit` (no AJAX/JSON, per
its `cert-form.js`). `request_cert.py`:

1. GETs `/embed` for a fresh CSRF token and session cookie.
2. POSTs the form fields to `/submit` with that token/cookie, using your
   CN/OIN plus the fixed values from `config.env`.
3. Parses the PFX password out of the confirmation page's
   `alert-success` block.
4. Hands off to `mail_watch.py`, which logs into the configured mailbox
   over IMAP, polls for an unread message from `MAIL_SENDER` received
   after the request was submitted, downloads its `.zip` attachment,
   extracts it, converts the `.cer` to PEM, writes the password file, and
   marks the email as read.

If PKIpartners changes the form, confirmation page, or email format, this
will need updating to match.
