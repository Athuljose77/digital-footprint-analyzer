# Contributing

Thanks for considering a contribution to Digital Footprint Analyzer.

## Project principles

This project is local-first. Keep these rules intact:

- Do not upload collected scan evidence.
- Do not add telemetry, hidden analytics, or background network calls.
- Public lookups must only run after an explicit user action.
- Missing or unavailable data must be reported as a coverage gap, not silently
  treated as "nothing found".
- Do not weaken the sensitive-file blocklist in the browser module.
- Use synthetic data in tests, screenshots, and bug reports.

## Development setup

Requirements: Python 3.12+ and Git.

```bash
git clone https://github.com/Athuljose77/digital-footprint-analyzer.git
cd digital-footprint-analyzer
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Windows:

```bat
python -m venv .venv
.venv\Scripts\pip install --upgrade pip
.venv\Scripts\pip install -r requirements.txt
run_app.bat
```

Run the app:

```bash
.venv/bin/python app/main.py
```

## Finding work

Look for issues labeled `good first issue` for a scoped starting point, or
`help wanted` for larger changes. Comment on an issue before starting so effort
is not duplicated. For a new idea, open a feature request that describes the
user problem, the proposed behaviour, and how the change would report
limitations or unavailable data.

## Tests

The test suite is offline-safe. Network fetchers are injected, Qt runs in
offscreen mode, and preferences/databases are redirected to temporary paths.

```bash
QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest app/tests/ -q -p no:cacheprovider
```

Please add or update tests for behaviour changes. A pull request should not
reduce the existing test coverage or introduce live network dependencies into
the test suite.

## Code style

- Follow the existing structure and naming conventions.
- Keep changes focused; avoid unrelated refactors in the same pull request.
- Prefer the standard library unless a dependency is clearly justified.
- Keep public lookup code bounded: validate input, use timeouts, cap response
  sizes, and never use a shell for subprocesses.
- Sanitize text before it reaches storage, reports, or the UI.
- When adding a new collector, define its coverage and failure states.

## Pull requests

Include:

- A short explanation of the problem.
- What changed and why.
- How it was tested, including the command used.
- Screenshots for visible UI changes, using synthetic data.
- Any new limitations or coverage gaps.

Small, reviewable pull requests are preferred over large rewrites.

## Reporting bugs and security issues

Use the GitHub issue templates for ordinary bugs and feature requests. Do not
open a public issue for a security vulnerability; see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contribution is licensed under the
project's MIT License.
