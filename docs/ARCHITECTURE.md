# Architecture

How the Digital Footprint Analyzer is put together: what runs where, how a
scan travels from collectors to findings, scoring, storage, and exports, and
which parts are allowed to touch the network.

The guiding constraint is **local-first**: scans run on your machine, results
are stored on your machine, and the only outbound requests are the public
lookup modules (username and email), which ask public sources about a handle
or address you typed in. See [PRIVACY.md](PRIVACY.md) for the exact
promises; this document shows how the code keeps them.

## System context

```mermaid
flowchart LR
    user(["User"])

    subgraph machine["Your computer — local-first"]
        app["Desktop app<br/>PySide6 (app/)"]
        data["Local data<br/>history.db · actions.db · exports"]
        os["Operating system<br/>package databases, processes,<br/>startup entries, browser profiles,<br/>file metadata"]
    end

    subgraph net["Public internet — lookup scans only"]
        platforms["Public platforms<br/>profile pages"]
        breach["Email exposure check"]
    end

    api["Optional HTTP API<br/>FastAPI (backend/)"]
    clients["Other HTTP clients"]

    user --> app
    app --> os
    app --> data
    app -->|"username scan:<br/>discovery + page verification"| platforms
    app -->|"email scan"| breach
    clients --> api
    api --> platforms
    api --> breach
```

The FastAPI backend is a thin HTTP wrapper around the *same* service modules
the desktop app uses in-process (`backend/services/`). The desktop app never
needs the API running; it imports those services directly.

## Components

```mermaid
flowchart TB
    user(["User"])

    subgraph ui["Presentation — PySide6 (app/ui)"]
        mw["MainWindow<br/>home dashboard · scan forms · theming"]
        worker["ScanWorker (QThread)<br/>runs scans off the UI thread"]
        pages["Pages<br/>Assessment · Evidence · Actions · History"]
        theme["theme.py<br/>colour tokens + runtime switching"]
    end

    subgraph core["Orchestration — app/core"]
        sc["scan_controller<br/>run_* scan runners"]
        cov["scan_coverage<br/>per-module coverage"]
    end

    subgraph svc["Collectors and lookups"]
        sysv["system_service<br/>OS · apps · processes · startup"]
        brw["browser_service<br/>browser profiles"]
        fms["file_metadata_service<br/>file metadata"]
        eml["email_service<br/>email exposure check"]
        usv["username_service<br/>discovery + page verification"]
    end

    subgraph analysis["Analysis"]
        fp["findings_processor<br/>+ findings/rules"]
        cat["startup_catalogue<br/>offline entry explanations"]
        risk["risk<br/>exposure score (exposure-v1)"]
        rem["remediation<br/>catalogue · engine · store"]
    end

    subgraph storage["Local storage"]
        hist["history store<br/>SQLite history.db"]
        acts["remediation store<br/>SQLite actions.db"]
        prefs["QSettings<br/>theme & preferences"]
    end

    subgraph reporting["Reporting"]
        rb["reporting/builder"]
        exp["PDF · JSON · CSV exporters"]
    end

    models["models/common.py<br/>ScanResult · FootprintData · Finding · Risk"]

    user --> mw
    mw --> pages
    mw --> theme
    mw --> prefs
    mw --> worker
    worker --> sc
    sc --> sysv
    sc --> brw
    sc --> fms
    sc --> eml
    sc --> usv
    sc --> fp
    sc --> cov
    fp --> cat
    mw -->|"after a scan finishes"| risk
    mw --> rem
    mw --> hist
    rem --> acts
    pages --> hist
    pages -->|"export"| rb
    rb --> exp
    models -.-> sc
    models -.-> fp
    models -.-> risk
    models -.-> hist
    models -.-> rb
```

Every layer exchanges the plain data models in `app/models/common.py`
(`ScanResult`, `FootprintData`, `Finding`, `Risk`, `Recommendation`), so the
UI, scoring, storage, and exporters all read the same objects.

## Scan lifecycle

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant MW as MainWindow
    participant W as ScanWorker (QThread)
    participant SC as scan_controller
    participant SVC as Collectors / lookups
    participant FP as FindingsProcessor
    participant AS as Risk + remediation plan
    participant ST as history.db
    participant P as Pages

    U->>MW: choose a scan and press Run
    MW->>W: start ScanWorker(scan_type, target)
    W->>SC: run_*_scan() in its own event loop
    SC->>SVC: collect locally and/or look up publicly
    SVC-->>SC: raw results
    SC->>SC: map records to FootprintData
    SC->>FP: process_scan_result / process_module_results
    FP-->>SC: findings, evidence, coverage
    SC-->>W: ScanResult
    W-->>MW: result_ready signal
    MW->>AS: build_risk_summary + build_plan
    MW->>ST: record_scan(result, risk, target)
    MW->>P: set_assessment / show_result / refresh
    U->>P: review, act, export PDF/JSON/CSV
```

`MainWindow._record_scan_assessment` is the single place a finished scan
becomes an assessment: the score, the remediation plan, and the stored
history all come from there, so the dashboard, pages, exports, and history
can never disagree about the same scan.

### Full Scan aggregation

```mermaid
flowchart LR
    fs["run_full_scan"] --> sysr["run_system_scan"]
    fs --> brwr["run_browser_scan"]
    fs --> filr["run_file_metadata_scan<br/>only when a file was chosen"]
    sysr --> agg["process_module_results<br/>merge + deduplicate findings"]
    brwr --> agg
    filr --> agg
    agg --> covq["coverage_from_module_results"]
    agg --> pol{"any module PARTIAL,<br/>or browser unavailable?"}
    pol -->|"yes"| partial["status PARTIAL<br/>with honest reasons"]
    pol -->|"no"| done["status COMPLETED"]
```

A module that reports `PARTIAL` or `UNAVAILABLE` is surfaced as a limitation
rather than silently dropped; coverage findings keep the gap visible in
scoring and reports.

## Local storage

| Location | Contents |
|---|---|
| `$XDG_DATA_HOME/DigitalFootprintAnalyzer/history.db` | Scan history and comparison state (SQLite). Overrides: `DFA_DATA_DIR`, `DFA_HISTORY_DB`. |
| `$XDG_DATA_HOME/DigitalFootprintAnalyzer/actions.db` | Remediation marks: done / pending / dismissed (SQLite). |
| `QSettings("DigitalFootprintAnalyzer", "Preferences")` | Theme mode, high-contrast selection, font scale, scan preferences. |
| User-chosen path | Exported reports (PDF / JSON / CSV), built from the same `ScanResult`, `RiskSummary`, and remediation plan the UI shows. |

## Network surface

| Module | What leaves the machine | Guards |
|---|---|---|
| Username | The handle, plus profile-page requests: discovery runs a bundled Sherlock-style subprocess, then verification fetches public pages with `httpx`. | Public-address check and host/URL block reasons (SSRF), response size caps, timeouts, and candidates can never be counted as confirmed by mistake. |
| Email | The address, to a breach/exposure check service. | Input validation, timeout; failures are reported as errors, never as results. |
| System · Browser · File & Metadata | Nothing. All collection is local. | — |

## Backend API (optional)

```mermaid
flowchart LR
    clients["HTTP clients / web UI"] -->|"POST /analyze<br/>GET /username/name"| api["FastAPI app<br/>backend/app.py"]
    api --> lim["services/limits<br/>single-flight + timeout"]
    lim --> ana["services/analyzer<br/>validation + scoring"]
    ana --> usv["username_service"]
    ana --> eml["email_service"]
    api --> rtr["routes/username"]
    rtr --> usv
```

Requests are validated before anything runs (the API starts subprocesses and
makes outbound requests, so an unvalidated field would be a denial-of-service
surface). Busy and timeout conditions return honest `429` / `504` JSON, and
errors are never dressed up as results.

## Design rules the code keeps

- **Local-first by default.** Only Username and Email scans consult the
  public internet, and the app says so where it matters.
- **One source of truth for the score.** `app/core/risk` produces the single
  `RiskSummary` used by the dashboard, Assessment page, reports, and history.
- **One wording source per finding.** Startup findings share one title and
  description template; entry notes come from the offline
  `app/core/startup_catalogue.py`, and unrecognised entries are reported as
  unrecognised instead of guessed at.
- **Limitations are first-class.** Partial modules, unavailable collectors,
  methodology limits, and coverage gaps are shown, not hidden.
- **One theme system.** All colours flow through `app/ui/theme.py`; pages
  re-render HTML and re-apply templates on a runtime theme switch.

## Related documents

- [RISK_METHODOLOGY.md](RISK_METHODOLOGY.md) — how the exposure score is built.
- [PRIVACY.md](PRIVACY.md) — exactly what is stored and what is sent.
- [REPORT_SCHEMA.md](REPORT_SCHEMA.md) — the exported JSON/CSV/PDF contract.
