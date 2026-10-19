# Privacy

Digital Footprint Analyzer is a local-first tool. This document states exactly
what leaves your machine, what is stored on it, and how to get rid of what is
stored. It matches the code: `backend/services/email_service.py`,
`backend/services/username_service.py`, `app/core/history/`,
`app/core/remediation/store.py`, and `app/core/history/sanitize.py`.

## What leaves your machine

Nothing is sent anywhere unless you explicitly start one of the **Public
Lookup** actions. There is no telemetry, no analytics, no crash reporting, and
no update check.

| Action | External requests | Trigger |
|---|---|---|
| **Email lookup** | `GET https://api.xposedornot.com/v1/check-email/<url-encoded address>?details=true` — the address is the query; nothing else is sent | You enter an address on Public Lookup and start the lookup |
| **Username lookup** | Sherlock discovery queries the candidate platforms, then **one unauthenticated GET per candidate** to verify what the platform actually returned | You enter a handle on Public Lookup and start the lookup, with **Verify results** enabled (it is on by default; untick it to skip the verification pass) |
| **Full Scan** | **None.** System, Browser, and File Metadata modules are entirely local. | Full Scan never includes email or username lookups, even if you used them before |

Username verification bounds (`backend/services/username_service.py`):

- At most **40 candidates** are fetched, at most **5 in flight**;
- **8 s** per request and **30 s** for the whole pass; a 256 KB body cap per
  page;
- Redirects are followed manually, up to 4 hops, re-checking every hop and
  refusing to follow a redirect to a private/loopback/link-local address
  (this also limits DNS-rebinding, though it does not eliminate it);
- The requests carry an identifying User-Agent
  (`DigitalFootprintAnalyzer/1.0 (local, unauthenticated profile check)`);
- No credentials, cookies, or authenticated requests are ever used, and there
  is no attempt to guess passwords or enumerate accounts beyond the single
  unauthenticated page fetch per candidate.

Timeouts, rate limits, DNS/TLS failures, and blocked addresses are reported as
*failures of the check* (`inconclusive`), never as "profile does not exist" —
see "Honesty" below.

Optional backend/frontend: the FastAPI backend and the React frontend are for
the same public lookups. The backend binds locally; running it does not add
outbound traffic beyond the lookups above.

## What is stored locally

### Scan history (`history.db`)

One row per completed scan: scan type, status, timestamps, the exposure score
snapshot (score, band, methodology version, coverage key, confidence),
counts, module coverage, and the scan's findings. Evidence is kept as a short
preview (max 5 entries, 200 characters each; descriptions max 280) after
sanitization.

### Action state (`actions.db`)

One row per action you have marked: the stable action key, state
(`pending` / `completed` / `dismissed`), title, and when you marked it. This is
your bookkeeping; it is never sent anywhere and never treated as a technical
verification.

### Where the files live

Default locations (no Qt dependency, standard OS conventions):

| Platform | Directory |
|---|---|
| Linux | `$XDG_DATA_HOME/DigitalFootprintAnalyzer` or `~/.local/share/DigitalFootprintAnalyzer` |
| macOS | `~/.local/share/DigitalFootprintAnalyzer` (the app uses the same XDG convention on macOS) |
| Windows | `%LOCALAPPDATA%\DigitalFootprintAnalyzer` (fallback: `~\AppData\Local\DigitalFootprintAnalyzer`) |

The directory can be overridden with `DFA_DATA_DIR`, the history file with
`DFA_HISTORY_DB`, and the action file with `DFA_ACTIONS_DB` (all meant for
tests, packaging, and power users).

Preferences (theme, text scale, timeouts) live separately in `QSettings` under
`DigitalFootprintAnalyzer / Preferences`.

### What is never stored

Credentials, tokens, passwords, full filesystem paths, email local parts, and
raw evidence beyond the short previews. The raw scan result only exists in
memory; history keeps the sanitized record.

## Sanitization rules

Everything written through the history store or the report exporters passes
`app/core/history/sanitize.py` first:

- **Masked**: bearer tokens, API keys, passwords and similar `key: value`
  assignments; long opaque token-like runs; full filesystem paths (reduced to
  the file name); email local parts (`someone@example.com` →
  `s***@example.com`).
- **Kept**: GPS coordinates (a location finding is meaningless without them),
  domains and URLs (the actionable part of a finding), usernames as scanned.

## Honesty about verification

- A provider reporting something is a **lead**, not proof. Reports state
  "N finding(s) are reported but unverified".
- Username results are `confirmed`, `inconclusive`, or `not_found`. HTTP 200
  alone is never treated as proof: the page text is checked for missing/login
  markers outside scripts.
- Marking an action complete is recorded as "*Marked complete by you; this is
  your own mark, not a technical verification. Re-run the scan to check
  whether it is still detected.*" An action that disappeared from the latest
  scan is shown as "*Completed by you and no longer detected in the latest
  scan (your mark, not a technical verification).*"
- A scan with no usable module coverage shows no score and says so, rather
  than showing a misleading 0.

## Your control over local data

- **History page**: delete a single scan, or clear all history. Both act on
  `history.db` immediately.
- **Actions page**: reset an action's state, or clear all action state.
- **Settings**: "Clear cached scan results" drops in-memory results.
- **Files**: deleting `history.db` and `actions.db` (or the whole data
  directory) has the same effect as the UI actions.
- Uninstalling the application does not delete these files automatically;
  remove the data directory if you want them gone.

## Secrets in errors and reports

Error messages and exported reports never include credentials or raw paths:
export failures name the destination file and the OS error text only, and scan
failures surface a message, not a traceback. The report bundle is built from
the same sanitized history shapes described above.

## Known limits

- The verification pass follows redirects up to 4 hops. Client-rendered
  single-page apps can still end up `inconclusive` because the missing-profile
  marker is drawn by JavaScript after load.
- Private-address blocking (including on redirect) reduces but does not
  eliminate DNS-rebinding risk.
- This tool checks **your own** footprint. It performs no credential attacks
  and no intrusive enumeration.
