"""Pin this service's root at sys.path[0]: `app` must resolve to python/intel/app even when
a sibling service (python/adjudicator has the same top-level `app` layout, 06 §1.1) is
installed in the shared workspace venv — suites are invoked per-service from repo root."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
