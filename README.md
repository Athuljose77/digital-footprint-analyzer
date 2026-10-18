# Digital Footprint Analyzer

A local-first desktop application (PySide6) for auditing your own digital
footprint. It inspects the machine it runs on and never sends collected
evidence anywhere: system scans, browser tracing, and file-metadata
extraction are entirely local.

## Features

| Module | What it collects |
|---|---|
| **System Footprint** | OS details, installed applications, running processes, startup items |
| **Browser Footprint** | Detected browsers, profiles, installed extensions, scan-coverage notes |
| **File Metadata** | Metadata from one explicitly selected file (never scanned recursively) |
| **Full Scan** | System + Browser together, with File Metadata only when a file is selected |
| **Public Lookup** | Email breach and username presence checks — the only features that use the network, and only when you start them |

Every scan separates **Findings** (potential exposures) from **Collected
Evidence** (raw records), and distinguishes scan-coverage gaps from confirmed
findings.

## Running

```bash
# Linux / macOS
backend/venv/bin/python app/main.py

# Windows
run_app.bat
```

The launcher expects the virtual environment at `backend\venv` (see
`.gitignore`).

## Settings

The **Settings** page is persisted with `QSettings` under
`DigitalFootprintAnalyzer / Preferences`:

| Setting | Effect |
|---|---|
| **Theme** — System default / Light / Dark | Switches the whole UI and every report color. "System default" follows the OS preference. |
| **High-contrast text selection** | Blue background with white text, legible in both themes |
| **Text scale** | 12 / 13 / 14 / 16 px |
| **Windows process collector** | `tasklist /V` only, with Toolhelp32 fallback, or plus executable-path enrichment |
| **Finding evidence preview cap** | How many evidence entries render inside each finding card (5 / 10 / 20 / unlimited) |
| **Public lookup network timeout** | Seconds (5 / 10 / 20) used by the email and username lookups |
| **Clear cached scan results** | Drops all in-memory results and resets the views |
| **Reset all settings** | Restores every preference above |

### Why the collector tiers matter

`tasklist /V` is the only flag that yields the **owning user account** and the
**process status**. Dropping it would silently replace real evidence with
placeholders, so the code keeps `/V` and, when tasklist fails, falls back to
the Win32 Toolhelp32 snapshot. Fields that fallback cannot supply are reported
as `Unavailable` — never guessed — so the evidence never overstates what was
actually read.

## Architecture

```
app/main.py               entrypoint; applies the saved theme before the first window
app/ui/theme.py           color tokens, application chrome, theme switching (single source of truth)
app/ui/icons.py           inline SVG line icons (no font or asset dependencies)
app/ui/main_window.py     all UI: dashboard, footprint views, report HTML, settings
app/ui/workers.py         QThread scan worker
app/core/scan_controller.py  scan orchestration, incl. run_full_scan
app/core/findings_processor.py  canonical findings aggregation
app/core/findings/        optional modular rule processor
app/services/             system, browser, and file-metadata collectors
backend/                  FastAPI service for the email/username lookups
frontend/                 React + Vite web UI for the same API
```

Report HTML resolves every color through `R()` in `app/ui/theme.py`, so no
color literal lives in a widget or a formatter and light/dark cannot drift
apart.

## Tests

```bash
QT_QPA_PLATFORM=offscreen backend/venv/bin/python -m pytest app/tests/
```

The test suite redirects `QSettings` to a temporary directory, so running it
never reads or writes your real preferences file.
