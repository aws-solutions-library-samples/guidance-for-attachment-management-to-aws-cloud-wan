"""
IPv6 (dual-stack VPC) attachment tests.

The IP address plan (``vpc_segment_address_map``) only describes IPv4 ranges.
IPv6 prefixes propagated by a dual-stack VPC must therefore not be rejected by
the plan check, but they are still checked for conflicting routes in the full
return segment (global or regional inspection) and in the quarantine routes
segment. All AWS calls are served by botocore Stubbers.
"""

from typing import Any, Dict, List

import pytest
from lambda_handler import process_cloudwan_event, process_route_event
from local_utils import import_vpc_address_mapping_file, validate_prefix_in_segment
from conftest import init_boto3_stubber
from test_configuration_events import (
    core_network_arn,
    core_network_id,
    full_return_segment,
    global_network_id,
    quarantine_routes_segment,
    regional_full_return_segment_by_region,
)
from test_mocked_networkmanager_calls import (
    nm_delete_vpc_attachment_00000000000000002,
    nm_get_vpc_attachment_00000000000000002,
    nm_tag_vpc_attachment_00000000000000002,
)
from test_mocked_organizations_calls import org_list_tags_for_resource_222222222222
from test_mocked_sts_calls import sts_assume_role_org_reader

vpc_address_mapping = import_vpc_address_mapping_file("tests/vpc_segment_address_map.yml")

IPV6_PREFIX = "2001:db8:1234:5600::/56"
OTHER_ATTACHMENT_ID = "attachment-00000000000000099"

# Attachment account owner: 222222222222 (route-domain = nonprod), IPv6 prefix of a dual-stack VPC
route_ok_ipv6 = {
    "changeType": "new_route",
    "coreNetworkArn": core_network_arn,
    "coreNetworkId": core_network_id,
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": IPV6_PREFIX,
            "attachments": [{"attachmentId": "attachment-00000000000000002", "attachmentType": "vpc"}],
            "routeType": "route_propagated",
            "routeState": "active",
            "propagatedRouteFamily": "bgp",
            "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": core_network_arn,
}


# ─── Stubbed NetworkManager get_network_routes calls (IPv6 prefix) ───────────


def _nm_get_network_routes(segment: str, match: str, routes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Stub for a supernet (``match="SupernetOfMatches"``) or subnet query of *IPV6_PREFIX* in *segment*."""
    return {
        "call": "get_network_routes",
        "expected_params": {
            "GlobalNetworkId": global_network_id,
            "RouteTableIdentifier": {
                "CoreNetworkSegmentEdge": {
                    "CoreNetworkId": core_network_id,
                    "SegmentName": segment,
                    "EdgeLocation": "eu-west-1",
                }
            },
            match: [IPV6_PREFIX],
            "States": ["ACTIVE"],
            "Types": ["PROPAGATED"],
        },
        "response": {"NetworkRoutes": routes},
    }


overlapping_ipv6_route = {
    "DestinationCidrBlock": "2001:db8:1234::/48",
    "Destinations": [
        {
            "CoreNetworkAttachmentId": OTHER_ATTACHMENT_ID,
            "SegmentName": "nonprod",
            "EdgeLocation": "eu-west-1",
            "ResourceType": "vpc",
            "ResourceId": "vpc-00000000000000099",
        }
    ],
    "State": "ACTIVE",
    "Type": "PROPAGATED",
}


def _no_conflict_stubs(full_return: str) -> List[Dict[str, Any]]:
    return [
        _nm_get_network_routes(full_return, "SupernetOfMatches", []),
        _nm_get_network_routes(full_return, "SubnetOfMatches", []),
        _nm_get_network_routes(quarantine_routes_segment, "SupernetOfMatches", []),
        _nm_get_network_routes(quarantine_routes_segment, "SubnetOfMatches", []),
    ]


# ─── Address plan ────────────────────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_validate_prefix_in_segment_ipv6_not_checked_against_ipv4_plan() -> None:
    """IPv6 prefixes are not rejected by the (IPv4) address plan; IPv4 prefixes still are."""
    assert validate_prefix_in_segment(IPV6_PREFIX, "nonprod", "eu-west-1", vpc_address_mapping) is True
    assert validate_prefix_in_segment(IPV6_PREFIX, "nonprod", "us-east-1", vpc_address_mapping) is True
    assert validate_prefix_in_segment("10.254.137.0/24", "nonprod", "eu-west-1", vpc_address_mapping) is True
    assert validate_prefix_in_segment("10.1.0.0/24", "nonprod", "eu-west-1", vpc_address_mapping) is False


# ─── Admission ───────────────────────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_route_event_ipv6_dual_stack_vpc_is_tagged() -> None:
    """A dual-stack VPC propagating an IPv6 prefix passes the plan check, is checked for conflicts and tagged."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [nm_get_vpc_attachment_00000000000000002]
                + _no_conflict_stubs(full_return_segment)
                + [nm_tag_vpc_attachment_00000000000000002],
            ),
        },
        route=route_ok_ipv6["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_ipv6_regional_inspection_without_full_return() -> None:
    """IPv6 prefix with regional inspection segments only: the edge's inspection segment is queried."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [nm_get_vpc_attachment_00000000000000002]
                + _no_conflict_stubs(regional_full_return_segment_by_region["eu-west-1"])
                + [nm_tag_vpc_attachment_00000000000000002],
            ),
        },
        configuration_event=route_ok_ipv6,
        global_network_id=global_network_id,
        full_return_segment="",
        full_return_segment_by_region=regional_full_return_segment_by_region,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


# ─── Conflicts ───────────────────────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_route_event_ipv6_overlapping_route_is_deleted() -> None:
    """An IPv6 prefix inside another VPC's IPv6 range (supernet in the full return segment) is deleted."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    _nm_get_network_routes(full_return_segment, "SupernetOfMatches", [overlapping_ipv6_route]),
                    _nm_get_network_routes(full_return_segment, "SubnetOfMatches", []),
                    _nm_get_network_routes(quarantine_routes_segment, "SupernetOfMatches", []),
                    _nm_get_network_routes(quarantine_routes_segment, "SubnetOfMatches", []),
                    nm_delete_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok_ipv6["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "overlapping cidrs found in network for attachment-00000000000000002",
    }
