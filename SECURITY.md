# Security Policy

## Supported Versions

This project does not use tagged releases. Only the latest commit on
`main` is supported; please update to it before reporting an issue.

## Reporting a Vulnerability

Please use GitHub's
[private vulnerability reporting](https://github.com/thomas-samoht/g4-trial-cert-requestor/security/advisories/new)
("Security" tab, "Report a vulnerability") instead of opening a public
issue. This keeps the report private until a fix is out.

You should get an initial response within a few days. If the issue is
confirmed, a fix will be pushed to `main` and the advisory will be
published once it's out.

## Sensitive Data Handled by This Tool

This is a CLI, not a service, so "security" here mostly means: what does
it write to disk, and how.

- `config.env` holds your mailbox password (`MAIL_PASSWORD`) in plain
  text. It's gitignored, but treat it like any other credentials file:
  don't commit it, don't share it, restrict its file permissions if your
  system allows it.
- Each run's output folder (`{OUTPUT_FOLDER}/{oin}-{cn}-{datetime}/`)
  contains the private key (`.key`), the password-protected bundle
  (`.pfx`), and `pfx-password.txt` with that bundle's password in plain
  text, side by side. That's unavoidable: PKIpartners only shows the PFX
  password once, on the `/submit` confirmation page, not in the email, so
  the script captures it there. Treat the whole output folder as
  sensitive, the same as you would any private key material.
- These are G4 **TRIAL** certificates, not for production use. Don't
  reuse trial private keys for anything that matters.

## Scope

This tool automates form submission and IMAP polling against
`g4trial.pkipartners.nl`. Vulnerabilities in that third-party service
itself are out of scope here; please report those to PKIpartners
directly.
