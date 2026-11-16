import sys
from pathlib import Path
from typing import Any

import pytest
from syrupy.extensions.json import JSONSnapshotExtension

# deployment/snapshot_account_ids.py (repository root) masks AWS account IDs in the plans
sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "deployment"))


@pytest.fixture
def snapshot_json(snapshot: Any) -> Any:
    return snapshot.use_extension(JSONSnapshotExtension)
