"""Offline explanations for common autostart ("startup") entries.

The catalogue maps lowercased substrings found in an entry's name or command
to a one-sentence, plain-language summary. It exists so startup findings
explain themselves without any network call: the app promises that scan data
never leaves the device, so explanations have to come from data shipped with
the app rather than from a remote service.

Adding an entry is cheap and safe: patterns are matched in order, the first
hit wins, and anything unmatched is honestly reported as "not recognised"
instead of guessed at.
"""
import re
from typing import Optional


def _normalize(text: str) -> str:
    """Fold hyphens/underscores so 'spice-vdagent' matches 'Spice vdagent'."""
    return re.sub(r"[-_]+", " ", text)


# (patterns, summary). Patterns are lowercased substrings tested against the
# entry's name and command together; the first matching group wins.
_ENTRIES = (
    (("gnome-keyring", "certificate and key storage", "secret storage service",
      "ssh key agent"),
     "GNOME's password and keyring service; stores saved passwords, keys, "
     "and certificates for your desktop."),
    (("localsearch", "tracker-miner"),
     "Desktop file indexer behind system search; normal, though it reads "
     "files in the background."),
    (("gsd-disk-utility", "gnome-disk-utility"),
     "Disk-utility notification helper that is part of the standard GNOME "
     "desktop."),
    (("spice-vdagent",),
     "Guest tools for SPICE virtual machines; only needed when this system "
     "runs inside a VM."),
    (("xdg-user-dirs",),
     "Keeps your Documents, Pictures, and other folder names in sync; runs "
     "once at login."),
    (("geoclue",),
     "Location service used by maps, weather, and similar apps; disable it "
     "if you do not want location features."),
    (("evolution-alarm", "evolution-data-server"),
     "Calendar and reminder service for the desktop."),
    (("vmware-user", "vmware-tools"),
     "VMware Tools guest agent; only needed when this system runs inside "
     "VMware."),
    (("vboxclient", "vboxservice", "virtualbox"),
     "VirtualBox guest additions; only needed when this system runs inside "
     "VirtualBox."),
    (("orca",),
     "Screen reader for accessibility; needed only if you use one."),
    (("snap userd", "snap user application", "snapd"),
     "Snap package framework; normal on systems that use Snap apps."),
    (("at-spi",),
     "Accessibility support service used by screen readers and other "
     "assistive tools."),
    (("imsettings", "im-config", "ibus", "fcitx"),
     "Input-method starter for keyboard layouts and typing in some "
     "languages."),
    (("abrt",),
     "Crash-reporting applet (Fedora and related distributions); it only "
     "acts when something fails."),
    (("seapplet", "selinux"),
     "SELinux troubleshooter applet from Fedora-style distributions."),
    (("liveinst",),
     "Leftover from the operating-system installer; usually safe to "
     "remove."),
    (("packagekit", "gnome-software", "update-notifier", "mintupdate",
      "dnf-automatic"),
     "Software update notifier; part of keeping the system up to date."),
    (("nm-applet", "networkmanager"),
     "Network tray applet for managing connections."),
    (("blueman", "bluetooth"),
     "Bluetooth applet and pairing support."),
    (("pulseaudio", "pipewire", "wireplumber"),
     "Desktop audio system."),
    (("ssh-agent",),
     "Keeps your SSH keys unlocked for this login session."),
    (("onedrive",),
     "Microsoft OneDrive cloud sync; only worth running if you use "
     "OneDrive."),
    (("dropbox",),
     "Dropbox cloud sync; only worth running if you use Dropbox."),
    (("discord", "slack", "spotify", "steam", "telegram", "signal", "teams"),
     "Third-party chat or media app set to start with the system; keep it "
     "only if you want it always running."),
    (("kdeconnect", "gsconnect"),
     "Phone-integration app; keep it only if you pair a phone with this "
     "computer."),
    (("redshift", "gammastep"),
     "Adjusts screen colour temperature to reduce eye strain."),
    (("xscreensaver", "light-locker", "gnome-screensaver"),
     "Screen locker; part of the standard desktop."),
    (("system-config-printer",),
     "Printer tray applet."),
    (("securityhealthsystray", "windows security"),
     "Windows Security system tray icon."),
    (("ctfmon",),
     "Windows text-input helper; standard."),
    (("itunes", "apple software update"),
     "Apple software update helper; only needed if you use Apple apps on "
     "this PC."),
    (("realtek",),
     "Audio driver utility installed with the PC's sound hardware."),
    (("jusched", "java update"),
     "Java update checker; usually safe to disable."),
    (("adobe",),
     "Adobe updater or helper utility."),
)


def explain(entry: object) -> Optional[str]:
    """Return a plain-language summary for an autostart entry, or None.

    Args:
        entry: the entry's name, command, or record line. Matched
            case-insensitively against the catalogue's patterns.
    """
    haystack = _normalize(str(entry or "").lower())
    if not haystack.strip():
        return None
    for patterns, summary in _ENTRIES:
        if any(_normalize(pattern) in haystack for pattern in patterns):
            return summary
    return None
