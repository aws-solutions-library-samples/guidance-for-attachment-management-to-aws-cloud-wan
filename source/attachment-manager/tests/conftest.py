"""Shared test utilities for the aws_lambda test suite."""

from typing import Any, Dict

import boto3
from botocore.stub import Stubber


def init_boto3_stubber(service: str, mocked_calls: Dict[str, Any]) -> Any:
    """Create a boto3 client with pre-queued Stubber responses."""
    client = boto3.client(service)
    stubber = Stubber(client)
    for call in mocked_calls:
        stubber.add_response(
            call["call"],
            call["response"],
            call["expected_params"],
        )
    stubber.activate()
    return client
