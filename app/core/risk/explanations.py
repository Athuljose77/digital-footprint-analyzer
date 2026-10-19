"""Fixed "why this matters" text, keyed by rule and finding type.

These are static explanations of why a class of finding deserves attention.
They are never generated per scan, so the wording in a report cannot drift
from the wording in the UI, and an explanation can never claim more than the
rule itself establishes.
"""

WHY_IT_MATTERS = {
    # Rule ids take priority.
    "EML-BREACH-001": (
        "The address appears in a breach data set. Credentials exposed in old "
        "breaches are still reused, so an old leak can open a current account."
    ),
    "USR-PROFILE-001": (
        "A public profile links this handle to a person or brand. Public "
        "profiles are a common starting point for impersonation and phishing."
    ),
    "SYS-STARTUP-001": (
        "Programs that start automatically run with your privileges at every "
        "boot or login, so an unexpected entry keeps running until removed."
    ),
    "BRW-PROFILE-001": (
        "Local browser profiles and extensions hold session tokens, autofill "
        "data, and history; extensions can additionally read every page."
    ),
    "FILE-GPS-001": (
        "Embedded coordinates record where the file was created. Sharing the "
        "file shares that location with whoever receives it."
    ),
    "FILE-CAMERA-001": (
        "Device metadata ties a file to specific hardware or software, which "
        "can connect separate documents back to one device."
    ),
    # Finding-type fallbacks for findings created outside the rule engine.
    "Email Breach": (
        "The address appears in a breach data set. Credentials exposed in old "
        "breaches are still reused, so an old leak can open a current account."
    ),
    "Public Presence": (
        "Public accounts under this handle can be linked to you, and matching "
        "a username does not prove who controls the account."
    ),
    "System Configuration": (
        "Persistent local configuration determines what runs on this machine "
        "without your involvement."
    ),
    "Sensitive Metadata": (
        "Files that carry embedded metadata disclose context about you and "
        "your device when they are shared."
    ),
}

DEFAULT_WHY = (
    "This record was collected from your own device or from a public source "
    "and is listed so you can review it."
)

# Standing limits of the exposure methodology. These are true of every scan,
# whatever it found, so the assessment and the reports always state them
# instead of showing an empty limitations section when nothing went wrong.
METHODOLOGY_LIMITS = (
    "Only the modules listed under coverage ran. Anything they cannot see was "
    "not assessed.",
    "Not detecting a finding is not evidence that the exposure does not exist.",
    "Findings that a provider merely reported are leads until you verify them.",
)


def methodology_limits():
    """The methodology's standing limits, for UI and report text."""
    return list(METHODOLOGY_LIMITS)

# Coverage findings describe the scan, not the user.
COVERAGE_WHY = "This records a limit of the scan itself, not an exposure."

_COVERAGE_TYPES = (
    "Scan Limitation",
    "Scan Coverage",
    "Scan Warnings",
    "Unavailable Sources",
)


def why_it_matters(finding) -> str:
    """Explanation text for one finding."""
    finding_type = str(getattr(finding, "finding_type", "") or "").strip()
    if finding_type in _COVERAGE_TYPES:
        return COVERAGE_WHY
    rule_id = str(getattr(finding, "rule_id", "") or "").strip().upper()
    if rule_id and rule_id in WHY_IT_MATTERS:
        return WHY_IT_MATTERS[rule_id]
    if finding_type in WHY_IT_MATTERS:
        return WHY_IT_MATTERS[finding_type]
    return DEFAULT_WHY
