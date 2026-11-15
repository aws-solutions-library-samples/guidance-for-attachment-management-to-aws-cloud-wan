import json
import logging
import time
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger(__name__)


def cloudwan_discover_conflicting_vpc_routes(
    boto3_client_dict: Dict[str, Any],
    global_network_id: str,
    core_network_id: str,
    segment: str,
    edge_location: str,
    route_prefix: str,
    attachment_id: str,
    attachment_types: List[str],
) -> List[Any]:
    """Query CloudWAN for routes in *segment* that overlap with *route_prefix*.

    Issues two API calls: one for supernets (wider summaries that contain
    *route_prefix*) and one for subnets (narrower prefixes contained within
    *route_prefix*).  Only routes whose destination is a VPC attachment other
    than *attachment_id* are included.

    Returns a list of raw ``get_network_routes`` response dicts, each containing
    at least one conflicting VPC route.
    """
    boto_client = boto3_client_dict.get("networkmanager")
    conflict_routes: List[Any] = []

    # Get supernets / wider summaries that may contain the prefix
    try:
        t0 = time.monotonic()
        response = boto_client.get_network_routes(  # type: ignore
            GlobalNetworkId=global_network_id,
            RouteTableIdentifier={
                "CoreNetworkSegmentEdge": {
                    "CoreNetworkId": core_network_id,
                    "SegmentName": segment,
                    "EdgeLocation": edge_location,
                }
            },
            SupernetOfMatches=[route_prefix],
            States=["ACTIVE"],
            Types=["PROPAGATED"],
        )
        logger.info(
            json.dumps(
                {
                    "event": "api_call",
                    "service": "networkmanager",
                    "method": "get_network_routes",
                    "match_type": "supernet",
                    "segment": segment,
                    "prefix": route_prefix,
                    "duration_ms": round((time.monotonic() - t0) * 1000),
                }
            )
        )
    except ClientError as e:
        logger.error(
            json.dumps(
                {
                    "event": "api_error",
                    "service": "networkmanager",
                    "method": "get_network_routes",
                    "match_type": "supernet",
                    "segment": segment,
                    "prefix": route_prefix,
                    "error_code": e.response["Error"]["Code"],
                    "error_message": e.response["Error"]["Message"],
                }
            )
        )
        raise
    if len(response["NetworkRoutes"]):
        conflict_routes.append(response)

    # Get subnets / narrower summaries that may contain the prefix
    try:
        t0 = time.monotonic()
        response = boto_client.get_network_routes(  # type: ignore
            GlobalNetworkId=global_network_id,
            RouteTableIdentifier={
                "CoreNetworkSegmentEdge": {
                    "CoreNetworkId": core_network_id,
                    "SegmentName": segment,
                    "EdgeLocation": edge_location,
                }
            },
            SubnetOfMatches=[route_prefix],
            States=["ACTIVE"],
            Types=["PROPAGATED"],
        )
        logger.info(
            json.dumps(
                {
                    "event": "api_call",
                    "service": "networkmanager",
                    "method": "get_network_routes",
                    "match_type": "subnet",
                    "segment": segment,
                    "prefix": route_prefix,
                    "duration_ms": round((time.monotonic() - t0) * 1000),
                }
            )
        )
    except ClientError as e:
        logger.error(
            json.dumps(
                {
                    "event": "api_error",
                    "service": "networkmanager",
                    "method": "get_network_routes",
                    "match_type": "subnet",
                    "segment": segment,
                    "prefix": route_prefix,
                    "error_code": e.response["Error"]["Code"],
                    "error_message": e.response["Error"]["Message"],
                }
            )
        )
        raise
    if len(response["NetworkRoutes"]):
        conflict_routes.append(response)

    # Only return routes from VPC attachments other than the one being evaluated
    vpc_conflict_routes: List[Any] = []
    for route_api_response in conflict_routes:
        for route in route_api_response["NetworkRoutes"]:
            for destination in route["Destinations"]:
                if (
                    destination["ResourceType"] in attachment_types
                    and destination["CoreNetworkAttachmentId"] != attachment_id
                ):
                    vpc_conflict_routes.append(route_api_response)
                    break

    return vpc_conflict_routes


def get_account_tag_from_account_id(boto3_client_dict: Dict[str, Any], role_arn: str, account_id: str) -> List[Any]:
    """Return all AWS Organizations tags for *account_id*.

    Assumes *role_arn* via STS to obtain temporary credentials, then calls
    ``organizations:ListTagsForResource`` (with pagination) using those
    credentials.  An ``organizations`` client from *boto3_client_dict* is used
    when present (for test stubbing); otherwise a new client is created from
    the temporary session.
    """
    sts = boto3_client_dict.get("sts")
    try:
        t0 = time.monotonic()
        token = sts.assume_role(RoleArn=role_arn, RoleSessionName="spoke_vpc")  # type: ignore
        logger.info(
            json.dumps(
                {
                    "event": "api_call",
                    "service": "sts",
                    "method": "assume_role",
                    "role_arn": role_arn,
                    "account_id": account_id,
                    "duration_ms": round((time.monotonic() - t0) * 1000),
                }
            )
        )
    except ClientError as e:
        logger.error(
            json.dumps(
                {
                    "event": "api_error",
                    "service": "sts",
                    "method": "assume_role",
                    "role_arn": role_arn,
                    "account_id": account_id,
                    "error_code": e.response["Error"]["Code"],
                    "error_message": e.response["Error"]["Message"],
                }
            )
        )
        raise
    cred = token["Credentials"]
    temp_access_key = cred["AccessKeyId"]
    temp_secret_key = cred["SecretAccessKey"]
    session_token = cred["SessionToken"]
    session = boto3.session.Session(
        aws_access_key_id=temp_access_key, aws_secret_access_key=temp_secret_key, aws_session_token=session_token
    )

    # Query the organizations
    account_tags: List[Any] = []
    client = boto3_client_dict.get("organizations", session.client("organizations"))
    next_token = None
    while True:
        try:
            t0 = time.monotonic()
            if next_token is None:
                response = client.list_tags_for_resource(ResourceId=account_id)
            else:
                response = client.list_tags_for_resource(ResourceId=account_id, NextToken=next_token)
            logger.info(
                json.dumps(
                    {
                        "event": "api_call",
                        "service": "organizations",
                        "method": "list_tags_for_resource",
                        "account_id": account_id,
                        "duration_ms": round((time.monotonic() - t0) * 1000),
                    }
                )
            )
        except ClientError as e:
            logger.error(
                json.dumps(
                    {
                        "event": "api_error",
                        "service": "organizations",
                        "method": "list_tags_for_resource",
                        "account_id": account_id,
                        "error_code": e.response["Error"]["Code"],
                        "error_message": e.response["Error"]["Message"],
                    }
                )
            )
            raise

        # Get the tags
        if "Tags" in response:
            account_tags = account_tags + response["Tags"]

        # Loop control
        if "NextToken" in response:
            next_token = response["NextToken"]
        else:
            break

    return account_tags


def resolve_account_tag(
    boto3_client_dict: Dict[str, Any],
    account_id: str,
    reader_role_arn: str,
    segment_tag: Optional[str],
    account_route_domain_tag: str,
) -> Optional[str]:
    """Return the effective routing tag for *account_id*.

    When *segment_tag* is set it takes precedence — it was deliberately applied
    to the attachment, so the account-level org tag is not consulted.  When
    *segment_tag* is ``None`` the account's org tags are fetched and the value
    of the ``route-domain`` tag is returned (or ``None`` if the tag is absent).
    """
    if segment_tag is not None:
        # The attachment tag was deliberately set; it takes precedence over the account tag.
        return segment_tag

    account_tags = get_account_tag_from_account_id(
        boto3_client_dict=boto3_client_dict,
        role_arn=reader_role_arn,
        account_id=account_id,
    )
    for tag in account_tags:
        if tag["Key"] == account_route_domain_tag:
            return str(tag["Value"])
    return None


def find_conflicting_routes(
    boto3_client_dict: Dict[str, Any],
    global_network_id: str,
    core_network_id: str,
    full_return_segment: str,
    edge_region: str,
    route_prefix: str,
    attachment_id: str,
    segment_tag: Optional[str],
    account_tag: Optional[str],
    quarantine_routes_segment: str,
    attachment_types: List[str],
) -> List[Any]:
    """Return all conflicting VPC routes for *route_prefix* across relevant segments.

    Always queries the full return segment.  Also queries the quarantine
    routes segment unless *segment_tag* == *account_tag*: when the attachment
    is already enrolled to its final segment, re-checking the quarantine routes
    for its own prefixes is unnecessary.
    """
    conflict_routes: List[Any] = []

    conflict_routes += cloudwan_discover_conflicting_vpc_routes(
        boto3_client_dict=boto3_client_dict,
        global_network_id=global_network_id,
        core_network_id=core_network_id,
        segment=full_return_segment,
        edge_location=edge_region,
        route_prefix=route_prefix,
        attachment_id=attachment_id,
        attachment_types=attachment_types,
    )

    # Skip the quarantine segment when the attachment is already tagged to its final segment —
    # segment_tag == account_tag means it is already enrolled and its routes are expected there.
    if segment_tag != account_tag:
        conflict_routes += cloudwan_discover_conflicting_vpc_routes(
            boto3_client_dict=boto3_client_dict,
            global_network_id=global_network_id,
            core_network_id=core_network_id,
            segment=quarantine_routes_segment,
            edge_location=edge_region,
            route_prefix=route_prefix,
            attachment_id=attachment_id,
            attachment_types=attachment_types,
        )

    return conflict_routes


def apply_routing_decision(
    client: Any,
    delete_attachment: bool,
    perform_deletions: bool,
    attachment_id: str,
    attachment_arn: str,
    attachment_state: str,
    quarantine_segment: str,
    account_route_domain_tag: str,
    logger: logging.Logger,
) -> None:
    """Execute the final delete-or-quarantine action for a non-compliant attachment.

    When *delete_attachment* is ``False`` this is a no-op; the caller handles
    the tagging path for compliant attachments.  When ``True``:

    - *perform_deletions* ``True``  → hard-delete the attachment.
    - *perform_deletions* ``False`` → tag the attachment to the quarantine segment
      instead of deleting (soft quarantine mode).
    """
    if delete_attachment and perform_deletions:
        try:
            t0 = time.monotonic()
            client.delete_attachment(AttachmentId=attachment_id)
            logger.info(
                json.dumps(
                    {
                        "event": "api_call",
                        "service": "networkmanager",
                        "method": "delete_attachment",
                        "attachment_id": attachment_id,
                        "duration_ms": round((time.monotonic() - t0) * 1000),
                    }
                )
            )
        except ClientError as e:
            logger.error(
                json.dumps(
                    {
                        "event": "api_error",
                        "service": "networkmanager",
                        "method": "delete_attachment",
                        "attachment_id": attachment_id,
                        "error_code": e.response["Error"]["Code"],
                        "error_message": e.response["Error"]["Message"],
                    }
                )
            )
            raise
    elif delete_attachment and not perform_deletions:
        logger.info(
            json.dumps(
                {
                    "event": "TAG_ATTACHMENT",
                    "target": "QUARANTINE_SEGMENT",
                    "marker": f"[TAG_ATTACHMENT=QUARANTINE_SEGMENT {attachment_id}]",
                    "attachment_arn": attachment_arn,
                    "attachment_state": attachment_state,
                    "segment": quarantine_segment,
                }
            )
        )
        try:
            t0 = time.monotonic()
            client.tag_resource(
                ResourceArn=attachment_arn,
                Tags=[{"Key": account_route_domain_tag, "Value": quarantine_segment}],
            )
            logger.info(
                json.dumps(
                    {
                        "event": "api_call",
                        "service": "networkmanager",
                        "method": "tag_resource",
                        "attachment_arn": attachment_arn,
                        "tag_key": account_route_domain_tag,
                        "tag_value": quarantine_segment,
                        "duration_ms": round((time.monotonic() - t0) * 1000),
                    }
                )
            )
        except ClientError as e:
            logger.error(
                json.dumps(
                    {
                        "event": "api_error",
                        "service": "networkmanager",
                        "method": "tag_resource",
                        "attachment_arn": attachment_arn,
                        "error_code": e.response["Error"]["Code"],
                        "error_message": e.response["Error"]["Message"],
                    }
                )
            )
            raise
