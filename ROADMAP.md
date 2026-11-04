# Roadmap

This roadmap describes intended direction, not guaranteed delivery dates.
Issues and pull requests are welcome for any item.

## Near term

- Keep the GitHub Actions test workflow green on Linux and Windows.
- Add a short demo GIF.
- Label beginner-friendly issues and document the first contribution path.
- Review dependency updates monthly.

## Recently completed

- Merged the cleaned desktop-only implementation into `main`.
- Published tagged `v1.0.0`, `v1.0.1`, and `v1.1.0` releases with install/run
  instructions.
- Added an editable package install and the `dfa` command.
- Added Linux and Windows CI coverage for the offscreen desktop suite.
- Added a synthetic sample report in PDF, JSON, and CSV formats.
- Added a synthetic demo scan mode that never writes to scan history.

## Later

- macOS support for System and Browser modules.
- Broader browser coverage with explicit coverage reporting.
- Signed Windows builds and a Linux package format.
- Accessibility review and keyboard-navigation checks.
- A small user study focused on whether findings and limitations are
  understandable.
- More report-localization options.

## Non-goals

- Uploading scan evidence to a cloud service.
- Automatically deleting files or changing system settings.
- Claiming complete coverage of a machine.
- Labelling a device or person as "safe" or "unsafe".

## How to propose work

Open a feature request describing the user problem, the proposed behaviour, and
how the change would report limitations or unavailable data. Changes that
weaken the local-first boundary need a strong justification.
