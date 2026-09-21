# Contributing

Thanks for considering a contribution to this project.

## Setup

Requires [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/thomas-samoht/g4-trial-cert-requestor.git
cd g4-trial-cert-requestor
cp config.example.env config.env
```

`uv sync` installs both the runtime and dev dependencies (pytest, ruff):

```bash
uv sync
```

## Running the tests

```bash
uv run pytest
```

## Linting and formatting

```bash
uv run ruff check .
uv run ruff format --check .
```

Run `uv run ruff format .` (without `--check`) to apply formatting fixes.

Markdown files are linted with
[markdownlint-cli2](https://github.com/DavidAnson/markdownlint-cli2), using
the rules in `.markdownlint-cli2.jsonc`. You can run it locally with:

```bash
npx markdownlint-cli2 "**/*.md"
```

## Submitting changes

1. Fork the repo and create a branch for your change.
2. Make sure `uv run pytest`, `uv run ruff check .`, and
   `uv run ruff format --check .` all pass.
3. Open a pull request using the provided template, filling in what you
   tested.

CI runs the same checks (tests, lint, format, markdown lint) on every pull
request, so it's worth running them locally first.

## Reporting bugs

Use the [bug report template](.github/ISSUE_TEMPLATE/bug_report.md) when
opening an issue. This project depends on the form and email format at
`g4trial.pkipartners.nl` staying the same, so if something changed on their
end, please mention it.
