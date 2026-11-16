"""
Pre-built botocore Stubber response dicts for AWS STS API calls.

Each entry is a dict with ``call``, ``expected_params``, and ``response``
suitable for use with ``init_boto3_stubber``.  Provides a single
``assume_role`` response that simulates assuming the org-reader role
(``arn:aws:iam::000000000000:role/org-reader``) used by the Lambda to read
AWS Organizations account tags.
"""

import os
from datetime import datetime

# Queued mocked calls for sts
sts_assume_role_org_reader = {
    "call": "assume_role",
    "expected_params": {
        "RoleArn": "arn:aws:iam::000000000000:role/org-reader",
        "RoleSessionName": "spoke_vpc",
    },
    "response": {
        "Credentials": {
            "AccessKeyId": "mocked_key_id_00",
            "SecretAccessKey": "mocked_key_secret",
            "SessionToken": "mocked_session_token",
            "Expiration": datetime(2015, 1, 1),
        },
        "AssumedRoleUser": {
            "AssumedRoleId": "org-reader/123456",
            "Arn": "arn:aws:sts::000000000000:assumed-role/org-reader/123456",
        },
    },
}
