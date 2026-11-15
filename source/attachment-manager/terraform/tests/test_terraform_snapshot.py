import datetime
import sys
import time
from typing import Any

import pytest
from syrupy.filters import props
from terraform_snapshot_test import (
    assert_expectations,
    get_json_from_file,
    sort_lists_in_dictionary,
    synthetise_terraform_json,
)

# Get the timestamp
UNIX_TIME = int(time.mktime(datetime.datetime.today().timetuple()))
FILE_PATH = f"__snapshots__/_{UNIX_TIME}"
WORKING_DIRECTORY = "tests"


@pytest.mark.terraform
@pytest.mark.order(1)
def test_synthesizes_properly(snapshot_json: Any) -> None:
    # Generate the new manifest
    tf_manifest = synthetise_terraform_json(file_path=FILE_PATH, working_directory=WORKING_DIRECTORY)

    # Only focus on generated configuration
    assert tf_manifest["configuration"]["root_module"] == snapshot_json()

    # Assert defined expectations
    assert_expectations(
        snapshot=tf_manifest["configuration"]["root_module"],
        snapshot_type="synthesis",
        folder_path="expectations",
        working_directory=WORKING_DIRECTORY,
    )


@pytest.mark.terraform
@pytest.mark.order(2)
def test_planned_values(snapshot_json: Any) -> None:
    # Read generated manifest
    tf_manifest = get_json_from_file(file_path=f"{FILE_PATH}.json", working_directory=WORKING_DIRECTORY)

    # Sort the lists embedded in the dictionary by the terraform module address
    tf_manifest["planned_values"] = sort_lists_in_dictionary(dictionary=tf_manifest["planned_values"])

    # Only focus on planned values that need to be there
    assert tf_manifest["planned_values"] == snapshot_json(
        exclude=props("filename", "content", "timestamp", "enabled_analysis_types", "paths", "triggers_replace")
    )

    # Assert defined expectations
    assert_expectations(
        snapshot=tf_manifest["planned_values"],
        snapshot_type="planned_values",
        folder_path="expectations",
        working_directory=WORKING_DIRECTORY,
    )
