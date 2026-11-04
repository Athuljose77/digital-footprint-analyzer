# Troubleshooting

This guide explains the two things users most often ask about after a scan:
a module that did not fully run (a *coverage gap*), and a *permission error*.
It does not change how scans work; it explains how to read the result and
what to try next. The app never uploads evidence, and it never requires
administrator privileges to run.

## Reading a coverage gap

Every scan reports per-module coverage in the Assessment view and in exports.
The states are defined in `app/core/scan_coverage.py`:

| State | What it means | What it proves |
| --- | --- | --- |
| `completed` | The module ran fully. | Its findings are usable evidence. |
| `limited` | The module ran, with limitations. | Read the limitation notes; some sources were not seen. |
| `failed` | The module did not complete. | Absence of a finding here proves nothing. |
| `unavailable` | The module cannot run on this platform. | The area was not scanned at all. |
| `skipped` | The module was not started (for example, no file was selected for File & Metadata). | Nothing was scanned for that module. |
| `unknown` | No coverage data was recorded. | Treat as no evidence. |

A gap is not a clean bill of health. If a module is `failed`,
`unavailable`, `skipped`, or `unknown`, the exposure score withholds
certainty for that area instead of pretending the machine is clean. Re-run
only the affected module after fixing the cause below; a full re-scan is
not required to close a single gap.

## Coverage gaps by module

### System module shows `failed` or `limited`

- **Startup applications could not be inspected.** The scan reports this
  as a platform or permission constraint (see
  `app/core/findings/adapters.py`). Close any system-management tools that
  hold the startup registry or folders open, then re-run the System scan.
- **A source is listed under `sources_failed`.** That source alone was not
  read; other sources in the same module still contribute. Check the
  source name in the limitation notes to see which area is missing.

### Browser module shows `failed`, `limited`, or `sources_failed`

- **The browser is running.** Browser profiles, history, cookies, and
  extension data can be locked while the browser is open. Close the
  browser completely (including background processes), then re-run the
  Browser scan.
- **A profile or extension folder cannot be read.** The scan records a
  `Permission denied` error for that folder and continues with the rest.
  Check that the folder is owned by your user account and is not on a
  network drive or removable drive that is no longer attached.
- **No browsers were detected.** That is a coverage result, not an error:
  the scan searched the usual profile locations and found none. If you
  use a portable browser in a custom location, that location is not
  covered.

### File & Metadata shows `skipped` or a permission error

- **`skipped` is expected when no file was selected.** Select one file
  explicitly; the app never scans a folder recursively.
- **`Permission denied: Unable to read file.`** The selected file cannot
  be read by your user account (for example, a file owned by another user
  or on a drive you cannot read). Copying it elsewhere does not help if
  the copy is still unreadable; choose a file you own, or check the
  file's permissions first.

### Email or Username lookup is inconclusive

These are the only network features, and they run only when you start
them explicitly. An inconclusive result usually means the lookup was
blocked, rate-limited, or the address or username is not a public one;
it does not mean the account is safe or compromised. Wait and retry
once, and do not treat a blocked lookup as a completed check.

## Permission errors

Permission errors are recorded, not hidden: the scan continues with the
sources it can read and lists the unreadable ones in `sources_failed` or
in the limitation notes.

1. **Check ownership first.** Most permission errors mean the file or
   folder belongs to another user, to the system, or to a different
   account on a shared machine. Re-running as administrator is not the
   recommended fix: the browser service is designed to run without
   administrator privileges, and elevating the whole app would widen
   what it can read beyond what you asked it to scan.
2. **Close the program holding the file.** Browsers, mail clients, and
   other apps lock their own data files while running. Close the owner
   app, then re-run just that module.
3. **Check the export destination separately.** Exporting a report can
   fail with `There is no permission to write to '<folder>'` even when
   the scan itself succeeded. Choose a folder you can write to (for
   example, your Documents folder) and export again; you do not need to
   re-run the scan.
4. **Removable and network drives.** If a profile or file lives on a
   drive that is disconnected, the scan reports it as unavailable or
   failed. Reattach the drive and re-run, or accept the gap and note
   that the area was not covered.

## When to report a bug instead

Open an issue if, after the steps above:

- the same module fails on every re-run with no `sources_failed` entry
  and no limitation note explaining why;
- a coverage state contradicts the module's own output (for example,
  a module is marked `completed` but its findings are empty and no
  limitation is shown); or
- an export fails in a folder you can write to, with files you own.

Include the module name, its coverage state, the limitation or error
text shown, your operating system, and whether the browser or the
owning app was open during the scan. Do not include scan evidence,
file paths from other users' accounts, or exported reports containing
personal data.
