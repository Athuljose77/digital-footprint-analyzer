# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) once
releases are tagged.

## [Unreleased]

### Added

- A clearly labeled demo mode that loads a synthetic Full Scan into the real
  assessment, evidence, action, and export views without scanning or writing
  to persisted scan history or action state.
- A synthetic sample report in PDF, JSON, and CSV formats, with a script to
  regenerate it from demo data.

## [1.0.1] - 2026-11-03

### Added

- An installable `digital-footprint-analyzer` package with the `dfa` and
  `digital-footprint-analyzer` GUI commands.
- Windows CI alongside the existing Linux workflow.

### Changed

- PDF reports now use the platform system font instead of a hard-coded
  `Helvetica` family.
- Tests are platform-neutral and fall back to `pypdf` when Qt's PDF text
  extractor returns an empty string on Windows.

## [1.0.0] - 2026-11-03

### Added

- Local-first System, Browser, File Metadata, and Full Scan modules.
- Explainable `exposure-v1` assessment with coverage-aware scoring.
- Evidence, Actions, and History pages.
- Local SQLite history and action-state storage.
- PDF, JSON, and CSV report exports.
- Offscreen Qt test suite with injected network fetchers and temporary data
  directories.
- Open-source project documentation: license, contribution guide, security
  policy, code of conduct, changelog, roadmap, and GitHub issue/PR templates.
- GitHub Actions test workflow for the Linux offscreen desktop suite.
- Screenshots and platform support notes in the README.

### Changed

- Removed the optional FastAPI backend and React web client. The desktop
  application is now the delivered product and runs as a single local process.
- Moved the email and username lookup services into `app/services/` so public
  lookups remain available in-process without a server.
- Updated architecture and privacy documentation for the desktop-only design.
- Added a root `requirements.txt` and switched the Windows launcher to `.venv`.

### Removed

- Backend API routes, API-only limits/analyzer code, API tests, and the
  backend/frontend development setup.
