"""Import the backend modules without leaving the backend directory on sys.path.

The backend has an ``app.py`` of its own, and the desktop application's package
is also called ``app``. If the backend directory stayed on ``sys.path`` for the
whole session, a later ``import app`` would resolve to ``backend/app.py`` (a
plain module) instead of the desktop package, and the desktop suite would fail
to collect. So the path entry only exists while these imports are running.
"""

import contextlib
import importlib.util
import os
import sys

BACKEND_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@contextlib.contextmanager
def backend_path():
    """Expose the backend directory on sys.path for the duration of a block."""

    inserted = BACKEND_DIR not in sys.path
    if inserted:
        sys.path.insert(0, BACKEND_DIR)
    try:
        yield
    finally:
        if inserted:
            with contextlib.suppress(ValueError):
                sys.path.remove(BACKEND_DIR)


def load_backend_app():
    """Import ``backend/app.py`` under its own module name."""

    name = "dfa_backend_app"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(
        name, os.path.join(BACKEND_DIR, "app.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    with backend_path():
        spec.loader.exec_module(module)
    return module
