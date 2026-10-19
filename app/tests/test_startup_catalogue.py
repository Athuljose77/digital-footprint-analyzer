"""Tests for the offline startup-entry explanation catalogue.

The catalogue is what makes startup findings self-explanatory without any
network call; these tests pin down its coverage (including a real-world
Fedora desktop list) and its honesty about unrecognised entries.
"""
import os
import sys
import unittest

sys.path.insert(
    0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
)

from app.core.startup_catalogue import explain


# The startup list from a real Fedora desktop scan (name + command), used as
# a coverage regression: every one of these must get an explanation.
REAL_WORLD_ENTRIES = [
    "Name: Certificate and Key Storage | Path: /usr/bin/gnome-keyring-daemon --start --components=pkcs11",
    "Name: Secret Storage Service | Path: /usr/bin/gnome-keyring-daemon --start --components=secrets",
    "Name: SSH Key Agent | Path: /usr/bin/gnome-keyring-daemon --start --components=ssh",
    "Name: Liveinst Setup | Path: /usr/libexec/liveinst-setup.sh",
    "Name: Tracker File System Miner | Path: /usr/libexec/localsearch-3",
    "Name: gnome-disk-utility notification plugin | Path: /usr/libexec/gsd-disk-utility-notify",
    "Name: Spice vdagent | Path: /usr/bin/spice-vdagent",
    "Name: User folders update | Path: xdg-user-dirs-gtk-update",
    "Name: Geoclue Demo agent | Path: /usr/libexec/geoclue-2.0/demos/agent",
    "Name: Events and Tasks Reminders | Path: /usr/libexec/evolution-data-server/evolution-alarm-notify",
    "Name: VMware User Agent | Path: /usr/bin/vmware-user-suid-wrapper",
    "Name: Orca Screen Reader | Path: orca --replace",
    "Name: Snap user application autostart helper | Path: /usr/bin/snap userd --autostart",
    "Name: AT-SPI D-Bus Bus | Path: /usr/libexec/at-spi-bus-launcher --launch-immediately",
    "Name: Input Method starter | Path: imsettings-boot.sh",
    "Name: Problem Reporting | Path: abrt-applet --gapplication-service",
    "Name: SELinux Troubleshooter | Path: /usr/bin/seapplet",
    "Name: vboxclient | Path: /usr/bin/VBoxClient-all",
]


class TestStartupCatalogue(unittest.TestCase):
    def test_real_world_startup_list_is_fully_explained(self):
        for entry in REAL_WORLD_ENTRIES:
            with self.subTest(entry=entry):
                self.assertIsNotNone(explain(entry), msg=entry)

    def test_known_desktop_components(self):
        self.assertIn("keyring", explain("gnome-keyring-daemon").lower())
        self.assertIn("virtual machine", explain("Spice vdagent").lower())
        self.assertIn("virtualbox", explain("vboxclient").lower())
        self.assertIn("indexer", explain("localsearch-3").lower())
        self.assertIn("accessibility", explain("at-spi-bus-launcher").lower())

    def test_known_third_party_apps_are_marked_for_review(self):
        for name in ("OneDrive", "Discord", "Spotify", "Slack"):
            with self.subTest(name=name):
                summary = explain(name)
                self.assertIsNotNone(summary)
                self.assertIn("only", summary.lower())

    def test_unknown_entries_return_none(self):
        self.assertIsNone(explain("Totally Unknown Agent"))
        self.assertIsNone(explain("mystery-daemon --start"))

    def test_known_words_inside_larger_words_do_not_match(self):
        # Substring matching used to claim these as chat/media apps; a
        # security tool must stay silent rather than guess.
        for probe in ("upsteam", "steamship", "signaling", "mysignal",
                      "teamsync", "adobeanalysis", "steamdeck-helper"):
            with self.subTest(probe=probe):
                self.assertIsNone(explain(probe), msg=probe)

    def test_remote_access_tools_are_not_mislabelled_as_chat_apps(self):
        # TeamsViewer is remote-access software from a different vendor.
        # It must not receive the chat-app note, while real Teams entries
        # still do.
        teams_note = "Third-party"
        self.assertIsNone(explain(r"C:\Program Files\TeamsViewer\TeamsViewer.exe"))
        self.assertIn(teams_note, explain("Microsoft Teams"))
        self.assertIn(teams_note, explain("MSTeams.exe"))
        self.assertIn(teams_note, explain("ms-teams --autostart"))

    def test_common_compound_variants_still_match(self):
        # Boundary matching must not lose the common explicit binary names.
        probes = {
            "bluetoothd": "Bluetooth",
            "VBoxTray.exe": "VirtualBox",
            "iTunesHelper.exe": "Apple",
            "RtkAudUService64.exe": "Audio driver",
            "snapd.service": "Snap",
            "steam.exe": "Third-party",
        }
        for probe, fragment in probes.items():
            with self.subTest(probe=probe):
                summary = explain(probe)
                self.assertIsNotNone(summary, msg=probe)
                self.assertIn(fragment, summary, msg=probe)

    def test_empty_or_missing_input(self):
        self.assertIsNone(explain(""))
        self.assertIsNone(explain(None))
        self.assertIsNone(explain(0))

    def test_matching_is_case_insensitive_and_checks_commands(self):
        self.assertIsNotNone(explain("CERTIFICATE AND KEY STORAGE"))
        self.assertIsNotNone(explain("Custom Tool | /usr/bin/gnome-keyring-daemon"))


if __name__ == "__main__":
    unittest.main()
