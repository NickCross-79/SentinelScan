"""Test configuration: isolate the DB/data dir before the app is imported."""

import os
import tempfile

# Must be set before backend.app.config is imported anywhere.
_TMP = tempfile.mkdtemp(prefix="sentinelscan-test-")
os.environ.setdefault("SENTINEL_DATA_DIR", _TMP)
