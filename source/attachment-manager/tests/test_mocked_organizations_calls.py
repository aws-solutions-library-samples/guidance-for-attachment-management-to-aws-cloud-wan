"""
Pre-built botocore Stubber response dicts for AWS Organizations API calls.

Each entry is a dict with ``call``, ``expected_params``, and ``response``
suitable for use with ``init_boto3_stubber``.  Fixtures cover
``list_tags_for_resource`` responses for test accounts: 222222222222 (has a
valid ``route-domain: nonprod`` tag) and 333333333333 (no tags).
"""

import os
from datetime import datetime

# Queued mocked calls for organizations
org_list_tags_for_resource_222222222222 = {
    "call": "list_tags_for_resource",
    "expected_params": {
        "ResourceId": "222222222222",
    },
    "response": {
        "Tags": [{"Key": "route-domain", "Value": "nonprod"}],
    },
}

org_list_tags_for_resource_333333333333 = {
    "call": "list_tags_for_resource",
    "expected_params": {
        "ResourceId": "333333333333",
    },
    "response": {
        "Tags": [],
    },
}
