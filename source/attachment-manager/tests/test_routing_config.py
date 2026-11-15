# pytest --verbose
import json
import os

import pytest
from lambda_handler import (
    handler,
    process_cloudwan_event,
    process_route_event,
    resolve_full_return_segment,
)
from local_utils import _validate_address_map, import_vpc_address_mapping_file
from conftest import init_boto3_stubber
from test_configuration_events import (
    core_network_arn,
    full_return_segment,
    global_network_id,
    regional_full_return_segment,
    route_nok_event_ip,
    route_nok_event_tag,
    route_ok,
    route_ok_5,
    segment_default_route,
    segment_default_route_ipv6,
)
from test_mocked_networkmanager_calls import (
    nm_delete_vpc_attachment_00000000000000002,
    nm_delete_vpc_attachment_00000000000000003,
    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002_overlapping,
    nm_get_network_routes_route_ok_full_return_subnet_00000000000000005,
    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002_overlapping,
    nm_get_network_routes_route_ok_full_return_supernet_00000000000000005,
    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002_overlapping,
    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002_overlapping,
    nm_get_network_routes_route_ok_regional_full_return_subnet_00000000000000002,
    nm_get_network_routes_route_ok_regional_full_return_supernet_00000000000000002,
    nm_get_vpc_attachment_00000000000000002,
    nm_get_vpc_attachment_00000000000000002_updating,
    nm_get_vpc_attachment_00000000000000003,
    nm_get_vpc_attachment_00000000000000004_nfg,
    nm_get_vpc_attachment_00000000000000005,
    nm_tag_vpc_attachment_00000000000000002,
    nm_tag_vpc_attachment_00000000000000003_quarantine,
)
from test_mocked_organizations_calls import (
    org_list_tags_for_resource_222222222222,
    org_list_tags_for_resource_333333333333,
)
from test_mocked_sts_calls import sts_assume_role_org_reader

# Load a test vpc address map
vpc_address_mapping = import_vpc_address_mapping_file("tests/vpc_segment_address_map.yml")


# ─── Happy-path: valid attachments ────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok() -> None:
    """Account 222222222222 with valid 'nonprod' org tag and CIDR 10.254.137.0/24 is tagged to the nonprod segment."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok() -> None:
    """Account 222222222222 with valid 'nonprod' org tag and CIDR 10.254.137.0/24 is tagged to the nonprod segment."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


# ─── Conflict detection (overlapping routes) ──────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_nok_overlapping_failure() -> None:
    """Account 222222222222 with a CIDR overlapping routes in both the full-return and quarantine segments is deleted."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002_overlapping,
                    nm_delete_vpc_attachment_00000000000000002,
                    # nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_nok_overlapping_failure() -> None:
    """Account 222222222222 presents an overlapping CIDR — conflict detection triggers deletion."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002_overlapping,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002_overlapping,
                    nm_delete_vpc_attachment_00000000000000002,
                    # nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "overlapping cidrs found in network for attachment-00000000000000002",
    }


# ─── Account filtering (ignore / process-only lists) ─────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_process_account_positive() -> None:
    """When process_only_aws_accounts=['222222222222'], account 222222222222 is still processed and tagged."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=["222222222222"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_process_account_positive() -> None:
    """When process_only_aws_accounts=['222222222222'], the matching account proceeds to be tagged."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=["222222222222"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_process_account_negative() -> None:
    """When process_only_aws_accounts=['111111111111'], account 222222222222 is skipped without processing."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber(
                "sts",
                [
                    sts_assume_role_org_reader,
                ],
            ),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=["111111111111"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_process_account_negative() -> None:
    """When process_only_aws_accounts=['111111111111'], account 222222222222 returns early with no action."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber(
                "sts",
                [
                    sts_assume_role_org_reader,
                ],
            ),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=["111111111111"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "attachment account not part of accounts to process",
    }


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_ignore_account_positive() -> None:
    """When ignore_aws_accounts=['222222222222'], the attachment from that account is skipped entirely."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=["222222222222"],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_ignore_account_positive() -> None:
    """When ignore_aws_accounts=['222222222222'], the matching account returns early with no action."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=["222222222222"],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "attachment account is part of ignored accounts",
    }


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_ignore_account_negative() -> None:
    """When ignore_aws_accounts=['111111111111'], account 222222222222 is not ignored and is tagged normally."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=["111111111111"],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_ignore_account_negative() -> None:
    """When ignore_aws_accounts=['111111111111'], account 222222222222 is not ignored and is tagged normally."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=["111111111111"],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


# ─── Account tag failures ─────────────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_invalid_tag() -> None:
    """Account 333333333333 has no 'route-domain' org tag — the attachment is deleted."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_333333333333,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000003,
                    nm_delete_vpc_attachment_00000000000000003,
                ],
            ),
        },
        configuration_event=route_nok_event_tag,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_invalid_tag() -> None:
    """Account 333333333333 has no 'route-domain' org tag — returns 'deleted attachment (no tag)'."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_333333333333,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000003,
                    nm_delete_vpc_attachment_00000000000000003,
                ],
            ),
        },
        route=route_nok_event_tag["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "deleted attachment (no tag)",
    }


# ─── Invalid CIDR / address-range failures ────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_route_ok_invalid_ip() -> None:
    """Account 222222222222 propagates 172.168.1.0/24, outside the allowed address space — attachment is deleted."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_delete_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_nok_event_ip,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_invalid_ip() -> None:
    """Account 222222222222 propagates 172.168.1.0/24 outside allowed space — returns 'deleted attachment (wrong ip)'."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_delete_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_nok_event_ip["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "deleted attachment (wrong ip)",
    }


# ─── Default routes and NFG ───────────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_default_route() -> None:
    """NFG attachment propagating 0.0.0.0/0 is silently skipped — NFG routes cannot be blackholed."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000004_nfg,
                    nm_get_vpc_attachment_00000000000000004_nfg,
                ],
            ),
        },
        configuration_event=segment_default_route,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_default_route() -> None:
    """NFG attachment propagating 0.0.0.0/0 is skipped — action is empty string."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000004_nfg,
                    nm_get_vpc_attachment_00000000000000004_nfg,
                ],
            ),
        },
        route=segment_default_route["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "",
    }


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_new_default_route_ipv6() -> None:
    """NFG attachment propagating ::/0 (IPv6 default route) is silently skipped."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000004_nfg,
                    nm_get_vpc_attachment_00000000000000004_nfg,
                ],
            ),
        },
        configuration_event=segment_default_route_ipv6,
        global_network_id=global_network_id,
        full_return_segment=None,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_process_route_event_new_default_route_ipv6() -> None:
    """NFG attachment propagating ::/0 (IPv6 default route) is skipped — action is empty string."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_222222222222,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000004_nfg,
                    nm_get_vpc_attachment_00000000000000004_nfg,
                ],
            ),
        },
        route=segment_default_route_ipv6["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=None,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "",
    }


# ─── Already-enrolled attachments (quarantine check skip) ─────────────────────


@pytest.mark.aws_lambdas
def test_process_route_event_new_route_ok_segment_skip_quarantine() -> None:
    """Attachment already tagged to 'nonprod' skips the quarantine-segment conflict check; only the full-return segment is queried."""
    assert process_route_event(
        boto3_client_dict={
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000005,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000005,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000005,
                ],
            ),
        },
        route=route_ok_5["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "action": "",
        "unhandled_event": False,
        "retry_event": False,
    }


# ─── Quarantine path (perform_deletions=false) ──────────────────────────────


@pytest.mark.aws_lambdas
def test_process_route_event_quarantine_instead_of_delete() -> None:
    """When perform_deletions=False, an invalid attachment is tagged to quarantine instead of deleted."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber(
                "organizations",
                [
                    org_list_tags_for_resource_333333333333,
                ],
            ),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000003,
                    nm_tag_vpc_attachment_00000000000000003_quarantine,
                ],
            ),
        },
        route=route_nok_event_tag["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=False,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
        ignore_aws_accounts=[],
        process_only_aws_accounts=[],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "deleted attachment (no tag)",
    }


# ─── Handler integration tests ──────────────────────────────────────────────


def _make_sqs_event(cloudwan_event: dict) -> dict:  # type: ignore
    """Wrap a CloudWAN event dict in the SQS→SNS envelope expected by handler()."""
    return {
        "Records": [
            {
                "messageId": "test-message-id-001",
                "receiptHandle": "test-receipt-handle",
                "body": json.dumps({"Message": json.dumps(cloudwan_event)}),
            }
        ]
    }


@pytest.mark.aws_lambdas
def test_handler_happy_path(monkeypatch: pytest.MonkeyPatch) -> None:
    """handler() processes a valid SQS event end-to-end and returns no batch failures."""
    monkeypatch.setenv("MANAGED_GLOBAL_NETWORK_ID", global_network_id)
    monkeypatch.setenv("PERFORM_ATTACHMENT_DELETIONS", "true")
    monkeypatch.setenv("SEGMENT_ADDRESSING_FILE", "tests/vpc_segment_address_map.yml")
    monkeypatch.setenv("FULL_RETURN_TABLE", full_return_segment)
    monkeypatch.setenv("AWS_ACCOUNT_READ_ROLE_ARN", "arn:aws:iam::000000000000:role/org-reader")

    boto3_client_dict = {
        "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
        "organizations": init_boto3_stubber(
            "organizations",
            [org_list_tags_for_resource_222222222222],
        ),
        "networkmanager": init_boto3_stubber(
            "networkmanager",
            [
                nm_get_vpc_attachment_00000000000000002,
                nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                nm_tag_vpc_attachment_00000000000000002,
            ],
        ),
    }

    result = handler(_make_sqs_event(route_ok), context=None, boto3_client_dict=boto3_client_dict)
    assert result == {"batchItemFailures": []}


@pytest.mark.aws_lambdas
def test_handler_unhandled_event_returns_no_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """handler() silently skips events missing required CloudWAN fields — no batch failures."""
    monkeypatch.setenv("MANAGED_GLOBAL_NETWORK_ID", global_network_id)
    monkeypatch.setenv("PERFORM_ATTACHMENT_DELETIONS", "true")
    monkeypatch.setenv("SEGMENT_ADDRESSING_FILE", "")

    incomplete_event = {"someField": "value"}
    boto3_client_dict = {
        "sts": init_boto3_stubber("sts", []),
        "networkmanager": init_boto3_stubber("networkmanager", []),
    }

    result = handler(_make_sqs_event(incomplete_event), context=None, boto3_client_dict=boto3_client_dict)
    assert result == {"batchItemFailures": []}


@pytest.mark.aws_lambdas
def test_handler_missing_global_network_id_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """handler() raises ValueError when MANAGED_GLOBAL_NETWORK_ID is not set."""
    monkeypatch.delenv("MANAGED_GLOBAL_NETWORK_ID", raising=False)
    monkeypatch.setenv("PERFORM_ATTACHMENT_DELETIONS", "true")
    monkeypatch.setenv("SEGMENT_ADDRESSING_FILE", "")

    with pytest.raises(ValueError, match="MANAGED_GLOBAL_NETWORK_ID"):
        handler({"Records": []}, context=None, boto3_client_dict={})


@pytest.mark.aws_lambdas
def test_handler_perform_deletions_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    """handler() accepts 'True', 'TRUE', 'true' for PERFORM_ATTACHMENT_DELETIONS."""
    monkeypatch.setenv("MANAGED_GLOBAL_NETWORK_ID", global_network_id)
    monkeypatch.setenv("PERFORM_ATTACHMENT_DELETIONS", "True")
    monkeypatch.setenv("SEGMENT_ADDRESSING_FILE", "")

    boto3_client_dict = {
        "sts": init_boto3_stubber("sts", []),
        "networkmanager": init_boto3_stubber("networkmanager", []),
    }

    result = handler({"Records": []}, context=None, boto3_client_dict=boto3_client_dict)
    assert result == {"batchItemFailures": []}


@pytest.mark.aws_lambdas
def test_handler_retry_reports_batch_item_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    """An attachment that is not ready yet is handed back to SQS as a batch item failure (counts towards the DLQ)."""
    monkeypatch.setenv("MANAGED_GLOBAL_NETWORK_ID", global_network_id)
    monkeypatch.setenv("PERFORM_ATTACHMENT_DELETIONS", "true")
    monkeypatch.setenv("SEGMENT_ADDRESSING_FILE", "tests/vpc_segment_address_map.yml")
    monkeypatch.setenv("FULL_RETURN_TABLE", full_return_segment)

    boto3_client_dict = {
        "sts": init_boto3_stubber("sts", []),
        "networkmanager": init_boto3_stubber("networkmanager", [nm_get_vpc_attachment_00000000000000002_updating]),
    }

    result = handler(_make_sqs_event(route_ok), context=None, boto3_client_dict=boto3_client_dict)
    assert result == {"batchItemFailures": [{"itemIdentifier": "test-message-id-001"}]}


# ─── Admission without optional features ──────────────────────────────────────


@pytest.mark.aws_lambdas
def test_process_route_event_tag_without_address_map() -> None:
    """Without a VPC address map, a valid attachment is still checked for conflicts and tagged to its segment."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment=full_return_segment,
        perform_deletions=True,
        vpc_address_mapping=None,
        attachment_type=["vpc"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


@pytest.mark.aws_lambdas
def test_process_route_event_tag_without_full_return_segment() -> None:
    """Without a full return segment, conflict detection is skipped and a valid attachment is still tagged."""
    assert process_route_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        route=route_ok["routes"][0],
        global_network_id=global_network_id,
        core_network_arn=core_network_arn,
        full_return_segment="",
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
        attachment_type=["vpc"],
    ) == {
        "unhandled_event": False,
        "retry_event": False,
        "action": "tag attachment to nonprod",
    }


# ─── Region specific full return segment (loopback removal) ──────────────────


@pytest.mark.aws_lambdas
def test_process_cloudwan_event_full_return_segment_by_region() -> None:
    """The region specific full return segment (e.g. regional inspection segment) is queried for conflicts."""
    assert process_cloudwan_event(
        boto3_client_dict={
            "sts": init_boto3_stubber("sts", [sts_assume_role_org_reader]),
            "organizations": init_boto3_stubber("organizations", [org_list_tags_for_resource_222222222222]),
            "networkmanager": init_boto3_stubber(
                "networkmanager",
                [
                    nm_get_vpc_attachment_00000000000000002,
                    nm_get_network_routes_route_ok_regional_full_return_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_regional_full_return_subnet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002,
                    nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002,
                    nm_tag_vpc_attachment_00000000000000002,
                ],
            ),
        },
        configuration_event=route_ok,
        global_network_id=global_network_id,
        full_return_segment=full_return_segment,
        full_return_segment_by_region={"eu-west-1": regional_full_return_segment},
        perform_deletions=True,
        vpc_address_mapping=vpc_address_mapping,
    ) == {
        "unhandled_event": False,
        "retry_event": False,
    }


@pytest.mark.aws_lambdas
def test_resolve_full_return_segment() -> None:
    """Region specific entries take precedence; empty values fall back or disable conflict detection."""
    by_region = {"eu-west-1": "inspectioneuw1", "us-east-1": ""}
    assert resolve_full_return_segment("eu-west-1", "fullreturn", by_region) == "inspectioneuw1"
    assert resolve_full_return_segment("eu-west-2", "fullreturn", by_region) == "fullreturn"
    assert resolve_full_return_segment("us-east-1", "fullreturn", by_region) == "fullreturn"
    assert resolve_full_return_segment("eu-west-2", "", by_region) is None
    assert resolve_full_return_segment("eu-west-2", None, None) is None


# ─── YAML address map validation ────────────────────────────────────────────


@pytest.mark.aws_lambdas
def test_validate_address_map_valid() -> None:
    """Valid address map structure passes validation."""
    _validate_address_map({"nonprod": {"eu-west-1": ["10.254.0.0/16"]}})


@pytest.mark.aws_lambdas
def test_validate_address_map_not_a_dict() -> None:
    """Non-dict root raises ValueError."""
    with pytest.raises(ValueError, match="must be a dict"):
        _validate_address_map("not a dict")


@pytest.mark.aws_lambdas
def test_validate_address_map_region_not_dict() -> None:
    """Segment with a non-dict region value raises ValueError."""
    with pytest.raises(ValueError, match="must be a dict of regions"):
        _validate_address_map({"nonprod": "not-a-dict"})


@pytest.mark.aws_lambdas
def test_validate_address_map_cidrs_not_list() -> None:
    """Region with a non-list CIDR value raises ValueError."""
    with pytest.raises(ValueError, match="must be a list"):
        _validate_address_map({"nonprod": {"eu-west-1": "10.0.0.0/8"}})


@pytest.mark.aws_lambdas
def test_validate_address_map_invalid_cidr() -> None:
    """Invalid CIDR string raises ValueError."""
    with pytest.raises(ValueError, match="Invalid CIDR"):
        _validate_address_map({"nonprod": {"eu-west-1": ["not-a-cidr"]}})


@pytest.mark.aws_lambdas
def test_validate_address_map_invalid_segment_name() -> None:
    """Segment names must only contain letters and numbers."""
    with pytest.raises(ValueError, match="letters and numbers"):
        _validate_address_map({"non-prod": {"eu-west-1": ["10.254.0.0/16"]}})
