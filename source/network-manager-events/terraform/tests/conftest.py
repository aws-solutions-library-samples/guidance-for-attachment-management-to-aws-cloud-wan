from typing import Any

import pytest
from syrupy.extensions.json import JSONSnapshotExtension


@pytest.fixture
def snapshot_json(snapshot: Any) -> Any:
    return snapshot.use_extension(JSONSnapshotExtension)
