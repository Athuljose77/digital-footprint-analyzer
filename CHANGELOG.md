# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/) once
releases are tagged.

## [Unreleased]

### Added

- Open-source project documentation: license, contribution guide, security
  policy, code of conduct, changelog, roadmap, and GitHub issue/PR templates.
- GitHub Actions test workflow for the offscreen desktop suite on Linux and
  Windows.
- Screenshots and platform support notes in the README.
- An installable `digital-footprint-analyzer` package with the `dfa` and
  `digital-footprint-analyzer` commands.

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

## [1.0.0] - 2026-11-03

### Added

- Local-first System, Browser, File Metadata, and Full Scan modules.
- Explainable `exposure-v1` assessment with coverage-aware scoring.
- Evidence, Actions, and History pages.
- Local SQLite history and action-state storage.
- PDF, JSON, and CSV report exports.
- Offscreen Qt test suite with injected network fetchers and temporary data
  directories.
