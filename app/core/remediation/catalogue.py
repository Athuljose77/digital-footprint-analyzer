"""The rule -> action catalogue.

Everything here is static: a finding's rule id (or, for findings produced
outside the rule engine, its finding type) selects exactly one action
template. There is no fallback advice, so an unrecognised finding produces no
action rather than a plausible-sounding guess.

Every documentation URL below was fetched and confirmed to resolve (HTTP 200)
before being included.
"""

import platform
from typing import Dict, List, Tuple

from app.core.remediation.models import DocLink

LINKS: Dict[str, DocLink] = {
    "hibp": DocLink(label="Have I Been Pwned — check an address against known breaches",
                    url="https://haveibeenpwned.com/"),
    "cisa_passwords": DocLink(
        label="CISA — use strong passwords",
        url="https://www.cisa.gov/secure-our-world/use-strong-passwords"),
    "cisa_mfa": DocLink(
        label="CISA — multi-factor authentication",
        url="https://www.cisa.gov/mfa"),
    "cisa_phishing": DocLink(
        label="CISA — recognize and report phishing",
        url="https://www.cisa.gov/secure-our-world/recognize-and-report-phishing"),
    "cisa_hub": DocLink(label="CISA — Secure Our World",
                        url="https://www.cisa.gov/secure-our-world"),
    "google_results": DocLink(
        label="Google — remove personal information from Search results",
        url="https://support.google.com/websearch/answer/12719076"),
    "instagram_privacy": DocLink(
        label="Instagram — account privacy settings",
        url="https://help.instagram.com/196883487377501"),
    "apple_login_items": DocLink(
        label="Apple — change login items on macOS",
        url="https://support.apple.com/guide/mac-help/mchlp2717/mac"),
    "autoruns": DocLink(
        label="Microsoft — Autoruns for reviewing startup entries",
        url="https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns"),
    "chrome_extensions": DocLink(
        label="Chrome — manage extensions",
        url="https://support.google.com/chrome_webstore/answer/2664769"),
    "firefox_addons": DocLink(
        label="Firefox — disable or remove add-ons",
        url="https://support.mozilla.org/en-US/kb/disable-or-remove-add-ons"),
    "exiftool": DocLink(
        label="ExifTool — inspect and strip file metadata",
        url="https://exiftool.org/"),
}


class ActionTemplate:
    """A static description of what to do about a class of finding."""

    def __init__(self, key_prefix: str, title: str, why: str,
                 steps: List[str], docs: List[DocLink],
                 subject: str = "fixed", note: str = ""):
        self.key_prefix = key_prefix
        self.title = title
        self.why = why
        self.steps = steps
        self.docs = docs
        # "fixed"  -> one action for the whole class
        # "suffix" -> one action per subject (breach service, platform, file)
        self.subject = subject
        self.note = note


def _system_docs() -> List[DocLink]:
    """Startup-entry documentation for the platform the app is running on."""
    system = platform.system().lower()
    if system == "darwin":
        return [LINKS["apple_login_items"]]
    if system == "windows":
        return [LINKS["autoruns"]]
    return []


def _profile_docs(subject: str) -> List[DocLink]:
    docs = [LINKS["google_results"], LINKS["cisa_phishing"]]
    platform_name = (subject or "").strip().lower()
    if platform_name in ("instagram", "instagram.com"):
        docs.insert(0, LINKS["instagram_privacy"])
    return docs


TEMPLATES: Dict[str, ActionTemplate] = {
    "rotate-exposed-password": ActionTemplate(
        key_prefix="rotate-exposed-password",
        subject="suffix",
        title="Change the exposed password for {subject}",
        why=("Credentials leaked in a breach stay useful to attackers for "
             "years, because people reuse passwords across services."),
        steps=[
            "Sign in to {subject} and change the password to one you have not "
            "used anywhere else.",
            "Change that same password on every other account that used it.",
            "Turn on two-factor authentication for the account.",
            "Review the account's recent activity and signed-in devices for "
            "anything you do not recognise.",
        ],
        docs=[LINKS["hibp"], LINKS["cisa_passwords"], LINKS["cisa_mfa"]],
    ),
    "review-public-profile": ActionTemplate(
        key_prefix="review-public-profile",
        subject="suffix",
        title="Review the public profile on {subject}",
        why=("A public profile can be linked back to you by anyone, and "
             "matching a username does not prove who controls the account."),
        steps=[
            "Open the profile and check exactly which details are public.",
            "Remove or restrict anything you do not want public — real name, "
            "employer, location, contact details, photos.",
            "If the account is not yours, report it to the platform as an "
            "impersonating account.",
            "If it is yours but unused, delete or deactivate it rather than "
            "leaving it exposed.",
        ],
        docs=[],  # filled per subject at build time
        note=("Ownership of this account is not verified by the scan. Confirm "
              "the account is yours before acting on it."),
    ),
    "review-startup-apps": ActionTemplate(
        key_prefix="review-startup-apps",
        title="Review the programs that start automatically",
        why=("Programs that start automatically run with your privileges at "
             "every boot or login, so anything unexpected keeps running until "
             "you remove it."),
        steps=[
            "Open your startup manager — Task Manager > Startup apps on "
            "Windows, Login Items on macOS, or your desktop's autostart list.",
            "Look up each entry you do not recognise before changing it; "
            "plenty of legitimate software starts with the system.",
            "Disable the entries you do not need.",
            "Remove anything you did not install, then re-run the system scan "
            "to confirm it is gone.",
        ],
        docs=[],  # filled per platform at build time
    ),
    "review-browser-extensions": ActionTemplate(
        key_prefix="review-browser-extensions",
        title="Review browser profiles and extensions",
        why=("Extensions can read and change everything on every page you "
             "open, and a leftover profile keeps saved sessions and autofill "
             "data on disk."),
        steps=[
            "Open your browser's extensions page and list what is installed.",
            "Remove extensions you do not use or do not recognise.",
            "Check the permissions of the ones you keep — anything that can "
            "'read and change all your data on all websites' deserves a "
            "second look.",
            "Remove browser profiles you no longer use, or clear their saved "
            "passwords and sessions.",
        ],
        docs=[LINKS["chrome_extensions"], LINKS["firefox_addons"]],
    ),
    "strip-file-metadata": ActionTemplate(
        key_prefix="strip-file-metadata",
        subject="suffix",
        title="Remove embedded metadata from {subject}",
        why=("Files carry information you did not intend to share — location, "
             "camera, author, and editing history — and it travels with the "
             "file wherever it is sent."),
        steps=[
            "Open the file's properties or details panel and look for "
            "location, camera, author, and company fields.",
            "Remove that data — most editors have 'remove location' or 'export "
            "without metadata', and a metadata tool can strip everything.",
            "Check the exported copy again: some editors write the metadata "
            "straight back out.",
            "Keep a private master copy if you need the original metadata "
            "later.",
        ],
        docs=[LINKS["exiftool"]],
    ),
}

# rule id -> template name
RULE_ACTIONS: Dict[str, str] = {
    "EML-BREACH-001": "rotate-exposed-password",
    "USR-PROFILE-001": "review-public-profile",
    "SYS-STARTUP-001": "review-startup-apps",
    "BRW-PROFILE-001": "review-browser-extensions",
    "FILE-GPS-001": "strip-file-metadata",
    "FILE-CAMERA-001": "strip-file-metadata",
}

# finding type -> template name, for findings created outside the rule engine
# (the runtime extractors build findings directly).
TYPE_ACTIONS: Dict[str, str] = {
    "Email Breach": "rotate-exposed-password",
    "Public Presence": "review-public-profile",
    "Startup Application": "review-startup-apps",
    "System Configuration": "review-startup-apps",
    "Browser Profile": "review-browser-extensions",
    "Browser Profile Detected": "review-browser-extensions",
    "Sensitive Metadata": "strip-file-metadata",
    "Device Metadata": "strip-file-metadata",
    "Embedded Geolocation": "strip-file-metadata",
}

# Coverage findings describe the scan, not the user: they get no action.
COVERAGE_TYPES: Tuple[str, ...] = (
    "Scan Limitation",
    "Scan Coverage",
    "Scan Warnings",
    "Unavailable Sources",
)


def template_for(finding) -> Tuple[str, "ActionTemplate"] | Tuple[None, None]:
    """Resolve the template for one finding, strictly by rule then type."""
    rule_id = str(getattr(finding, "rule_id", "") or "").strip().upper()
    if rule_id in RULE_ACTIONS:
        name = RULE_ACTIONS[rule_id]
        return name, TEMPLATES[name]
    finding_type = str(getattr(finding, "finding_type", "") or "").strip()
    if finding_type in TYPE_ACTIONS:
        name = TYPE_ACTIONS[finding_type]
        return name, TEMPLATES[name]
    return None, None


def resolved_docs(template_name: str, subject: str) -> List[DocLink]:
    """Documentation for a template, resolved for the subject/platform."""
    if template_name == "review-public-profile":
        return _profile_docs(subject)
    if template_name == "review-startup-apps":
        return _system_docs()
    return list(TEMPLATES[template_name].docs)
