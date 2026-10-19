"""Suite-wide isolation for the desktop application tests.

The application reads preferences through QSettings and stores scan history
under the platform data directory. Both are redirected to throwaway
directories here, before any test module is imported, so no test can read or
write the developer's real preferences file, history database, or cache.
"""

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="dfa-test-env-")

os.environ["XDG_DATA_HOME"] = os.path.join(_TMP, "data")
os.environ["XDG_CONFIG_HOME"] = os.path.join(_TMP, "config")
os.environ["XDG_CACHE_HOME"] = os.path.join(_TMP, "cache")

from PySide6.QtCore import QSettings  # noqa: E402  (after the env redirect)

_SETTINGS_DIR = os.path.join(_TMP, "settings")
os.makedirs(_SETTINGS_DIR, exist_ok=True)
QSettings.setDefaultFormat(QSettings.Format.IniFormat)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.UserScope, _SETTINGS_DIR)
QSettings.setPath(QSettings.Format.IniFormat, QSettings.Scope.SystemScope, _SETTINGS_DIR)
