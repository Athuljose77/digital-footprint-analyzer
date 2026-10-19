"""Backend test suite.

The backend directory must not be left on ``sys.path`` (its ``app.py`` would
shadow the desktop's ``app`` package), so the test modules import the backend
through ``backend_imports`` instead. This file exists to hold that rule and any
future shared fixtures.
"""
