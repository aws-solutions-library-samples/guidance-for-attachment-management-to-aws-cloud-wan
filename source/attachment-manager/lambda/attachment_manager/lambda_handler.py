"""
Cloud WAN Attachment Manager.

Processes curated AWS Network Manager events (delivered through SNS -> SQS) and
decides, for every VPC attachment propagating routes into the core network,
whether it is admitted to its segment, quarantined, or deleted.

Logging markers for operational troubleshooting:

# Attachment marked for disconnection due to absent AWS Organizations account tag
[DISCONNECT_ATTACHMENT=ABSENT_ACCOUNT_TAG {attachment_id}]

# Attachment marked for disconnection due to incompatible address range (not part of VPC Segment Map)
[DISCONNECT_ATTACHMENT=WRONG_ADDRESS_RANGE {attachment_id}]

# Attachment marked for disconnection due to conflicting routes already installed in the network
[DISCONNECT_ATTACHMENT=CONFLICTING_ROUTES {attachment_id}]

# Attachment marked for tagging to an user segment
[TAG_ATTACHMENT=USER_SEGMENT {attachment_id}]

# Attachment marked for tagging to the quarantine segment
[TAG_ATTACHMENT=QUARANTINE_SEGMENT {attachment_id}]

# Attachment marked for retry because network isn't ready
[RETRY_ATTACHMENT=NOT_READY {attachment_id}]

"""

import json
import logging
import os
from typing import Any, Dict, List, Optional

import boto3
from aws_utils import apply_routing_decision, find_conflicting_routes, resolve_account_tag
from botocore.exceptions import ClientError
from local_utils import import_vpc_address_mapping_file, validate_prefix_in_segment

# Define environmental variables
ENV_ACCOUNT_READ_ROLE_ARN = "AWS_ACCOUNT_READ_ROLE_ARN"
ENV_CORE_NETWORK_ARN = "MANAGED_CORE_NETWORK_ARN"
ENV_SEGMENT_ADDRESSING_FILE = "SEGMENT_ADDRESSING_FILE"
ENV_IGNORE_AWS_ACCOUNTS = "IGNORE_AWS_ACCOUNTS"
ENV_PROCESS_ONLY_AWS_ACCOUNTS = "PROCESS_ONLY_AWS_ACCOUNTS"
ENV_LOGGING_LEVEL = "LOGGING_LEVEL"
ENV_PERFORM_ATTACHMENT_DELETIONS = "PERFORM_ATTACHMENT_DELETIONS"
ENV_GLOBAL_NETWORK_ID = "MANAGED_GLOBAL_NETWORK_ID"
ENV_FULL_RETURN_TABLE = "FULL_RETURN_TABLE"
ENV_FULL_RETURN_TABLE_BY_REGION = "FULL_RETURN_TABLE_BY_REGION"
ENV_ACCOUNT_ROUTE_DOMAIN_TAG = "ACCOUNT_ROUTE_DOMAIN_TAG"
ENV_QUARANTINE_SEGMENT = "QUARANTINE_SEGMENT"
ENV_QUARANTINE_ROUTES_SEGMENT = "QUARANTINE_ROUTES_SEGMENT"

# Define global static variables
DEFAULT_ACCOUNT_ROUTE_DOMAIN_TAG = "route-domain"
DEFAULT_QUARANTINE_SEGMENT = "quarantine"
DEFAULT_QUARANTINE_ROUTES_SEGMENT = "quarantineroutes"

ATTACHMENT_TYPE_VPC = "vpc"
ATTACHMENT_RETRY_STATES = ["UPDATING", "PENDING_NETWORK_UPDATE", "PENDING_TAG_ACCEPTANCE"]

# Initiate logging
str_logging_level = os.environ.get(ENV_LOGGING_LEVEL, "WARN")
logging_level = logging.WARN
if str_logging_level == "INFO":
    logging_level = logging.INFO
if str_logging_level == "DEBUG":
    logging_level = logging.DEBUG
logger = logging.getLogger()
logger.setLevel(logging_level)
logging.basicConfig(
    format="%(levelname)s %(threadName)s [%(filename)s:%(lineno)d] %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    level=logging_level,
)
logger.debug("Lambda initialization completed")


def _route_domain_tag() -> str:
    return os.environ.get(ENV_ACCOUNT_ROUTE_DOMAIN_TAG, DEFAULT_ACCOUNT_ROUTE_DOMAIN_TAG)


def _quarantine_segment() -> str:
    return os.environ.get(ENV_QUARANTINE_SEGMENT, DEFAULT_QUARANTINE_SEGMENT)


def _quarantine_routes_segment() -> str:
    return os.environ.get(ENV_QUARANTINE_ROUTES_SEGMENT, DEFAULT_QUARANTINE_ROUTES_SEGMENT)


def resolve_full_return_segment(
    edge_region: str,
    full_return_segment: Optional[str],
    full_return_segment_by_region: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """Return the segment holding every known route for *edge_region*.

    A region-specific entry in *full_return_segment_by_region* takes precedence
    (e.g. a regional inspection segment such as ``inspectioneuw1`` when the
    last-hop loopback has been removed for that region). Otherwise the global
    *full_return_segment* is used. Returns ``None`` when neither is set, which
    disables conflicting-route detection for that region.
    """
    segment = (full_return_segment_by_region or {}).get(edge_region) or full_return_segment
    return segment or None


def process_route_event(
    boto3_client_dict: Dict[str, Any],
    global_network_id: str,
    core_network_arn: str,
    route: Dict[str, Any],
    perform_deletions: bool = True,
    vpc_address_mapping: Any = None,
    full_return_segment: Optional[str] = None,
    attachment_type: Optional[List[str]] = None,
    ignore_aws_accounts: Optional[List[str]] = None,
    process_only_aws_accounts: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Validate a single propagated route and take the appropriate action.

    Runs the following pipeline for each VPC attachment associated with *route*:

    1. Fetch the attachment details and apply account allow/deny filtering.
    2. Resolve the effective ``route-domain`` tag (attachment tag -> org account tag).
    3. Validate that the propagated CIDR belongs to the expected address space.
    4. Detect conflicting / overlapping routes already present in the network
       (only when a full return segment is known for the attachment region).
    5. Act: tag the attachment to its segment, quarantine it, or delete it.

    Returns a dict with keys:
    - ``unhandled_event`` (bool) - True if the attachment state was unrecognised.
    - ``retry_event`` (bool) - True if the attachment is not yet ready; the
      SQS message should be retried.
    - ``action`` (str) - human-readable description of the action taken.
    """
    attachment_type = attachment_type or []
    ignore_aws_accounts = ignore_aws_accounts or []
    process_only_aws_accounts = process_only_aws_accounts or []

    return_dict: Dict[str, Any] = {
        "unhandled_event": False,
        "retry_event": False,
        "action": "",
    }

    client = boto3_client_dict.get("networkmanager")
    core_network_id = core_network_arn.split("/")[-1]
    route_prefix = route["destinationCidrBlock"]
    full_return_segment = full_return_segment or None

    if "attachments" not in route:
        return return_dict

    for attachment in route["attachments"]:
        if len(attachment_type) > 0 and attachment.get("attachmentType") not in attachment_type:
            continue

        attachment_id = attachment["attachmentId"]
        response = client.get_vpc_attachment(AttachmentId=attachment_id)  # type: ignore
        attachment_object = response["VpcAttachment"]["Attachment"]

        spoke_account_id = attachment_object["ResourceArn"].split(":")[4]

        # Ignore learned routes from Network Function Group attachments (service insertion):
        # the routes they propagate are not owned by the attachment and can't be evaluated here.
        if attachment_object.get("NetworkFunctionGroupName", None):
            continue

        # Account filtering
        if spoke_account_id in ignore_aws_accounts:
            return_dict["action"] = "attachment account is part of ignored accounts"
            return return_dict

        if len(process_only_aws_accounts) > 0 and spoke_account_id not in process_only_aws_accounts:
            return_dict["action"] = "attachment account not part of accounts to process"
            return return_dict

        edge_region = attachment_object["EdgeLocation"]
        attachment_state = attachment_object["State"]
        attachment_arn = f"arn:aws:networkmanager::{spoke_account_id}:attachment/{attachment_id}"

        if attachment_state in ["AVAILABLE"]:
            # Resolve the attachment-level tag (None if not yet tagged)
            segment_tag = None
            for tag in attachment_object.get("Tags", []):
                if tag["Key"] == _route_domain_tag():
                    segment_tag = tag["Value"]
                    break

            # Use the attachment tag when present; fall back to the account-level org tag.
            reader_role_arn = os.environ.get(ENV_ACCOUNT_READ_ROLE_ARN)
            if not reader_role_arn:
                raise ValueError(f"Missing required environment variable: {ENV_ACCOUNT_READ_ROLE_ARN}")
            account_tag = resolve_account_tag(
                boto3_client_dict=boto3_client_dict,
                account_id=spoke_account_id,
                reader_role_arn=reader_role_arn,
                segment_tag=segment_tag,
                account_route_domain_tag=_route_domain_tag(),
            )

            delete_attachment = False

            if segment_tag is None and account_tag is None:
                # No route-domain tag found at attachment or account level - delete.
                logger.info(
                    json.dumps(
                        {
                            "event": "DISCONNECT_ATTACHMENT",
                            "reason": "ABSENT_ACCOUNT_TAG",
                            "marker": f"[DISCONNECT_ATTACHMENT=ABSENT_ACCOUNT_TAG {attachment_id}]",
                            "attachment_id": attachment_id,
                            "attachment_state": attachment_state,
                        }
                    )
                )
                delete_attachment = True
                return_dict["action"] = "deleted attachment (no tag)"

            else:
                # 1. The propagated CIDR must belong to the address space of the segment / region.
                if (
                    not validate_prefix_in_segment(route_prefix, account_tag, edge_region, vpc_address_mapping)
                    and segment_tag != _quarantine_segment()
                ):
                    logger.info(
                        json.dumps(
                            {
                                "event": "DISCONNECT_ATTACHMENT",
                                "reason": "WRONG_ADDRESS_RANGE",
                                "marker": f"[DISCONNECT_ATTACHMENT=WRONG_ADDRESS_RANGE {attachment_id}]",
                                "attachment_id": attachment_id,
                                "attachment_state": attachment_state,
                                "route_prefix": route_prefix,
                            }
                        )
                    )
                    delete_attachment = True
                    return_dict["action"] = "deleted attachment (wrong ip)"

                # 2. The propagated CIDR must not overlap with routes already known in the network.
                #    Segments without an entry in a non-empty address map are not subject to this check.
                if (
                    not delete_attachment
                    and full_return_segment is not None
                    and (not vpc_address_mapping or account_tag in vpc_address_mapping)
                ):
                    conflict_routes = find_conflicting_routes(
                        boto3_client_dict=boto3_client_dict,
                        global_network_id=global_network_id,
                        core_network_id=core_network_id,
                        full_return_segment=full_return_segment,
                        edge_region=edge_region,
                        route_prefix=route_prefix,
                        attachment_id=attachment_id,
                        segment_tag=segment_tag,
                        account_tag=account_tag,
                        quarantine_routes_segment=_quarantine_routes_segment(),
                        attachment_types=[ATTACHMENT_TYPE_VPC],
                    )
                    if conflict_routes:
                        delete_attachment = True
                        return_dict["action"] = f"overlapping cidrs found in network for {attachment_id}"
                        logger.info(
                            json.dumps(
                                {
                                    "event": "DISCONNECT_ATTACHMENT",
                                    "reason": "CONFLICTING_ROUTES",
                                    "marker": f"[DISCONNECT_ATTACHMENT=CONFLICTING_ROUTES {attachment_id}]",
                                    "attachment_id": attachment_id,
                                    "conflict_routes": conflict_routes,
                                },
                                default=str,
                            )
                        )

                # 3. Admit the attachment to its segment.
                if not delete_attachment and segment_tag != account_tag:
                    logger.info(
                        json.dumps(
                            {
                                "event": "TAG_ATTACHMENT",
                                "target": "USER_SEGMENT",
                                "marker": f"[TAG_ATTACHMENT=USER_SEGMENT {attachment_id}]",
                                "attachment_id": attachment_id,
                                "attachment_arn": attachment_arn,
                                "attachment_state": attachment_state,
                                "segment": account_tag,
                            }
                        )
                    )
                    client.tag_resource(  # type: ignore
                        ResourceArn=attachment_arn,
                        Tags=[{"Key": _route_domain_tag(), "Value": account_tag}],
                    )
                    return_dict["action"] = f"tag attachment to {account_tag}"

            apply_routing_decision(
                client=client,
                delete_attachment=delete_attachment,
                perform_deletions=perform_deletions,
                attachment_id=attachment_id,
                attachment_arn=attachment_arn,
                attachment_state=attachment_state,
                quarantine_segment=_quarantine_segment(),
                account_route_domain_tag=_route_domain_tag(),
                logger=logger,
            )

        elif attachment_state in ATTACHMENT_RETRY_STATES:
            return_dict["retry_event"] = True
            logger.info(
                json.dumps(
                    {
                        "event": "RETRY_ATTACHMENT",
                        "reason": "NOT_READY",
                        "marker": f"[RETRY_ATTACHMENT=NOT_READY {attachment_id}]",
                        "attachment_id": attachment_id,
                        "attachment_state": attachment_state,
                    }
                )
            )
            return_dict["action"] = "attachment not ready"
        else:
            return_dict["unhandled_event"] = True

    return return_dict


def process_cloudwan_event(
    boto3_client_dict: Dict[str, Any],
    configuration_event: Any,
    global_network_id: str,
    perform_deletions: bool = True,
    full_return_segment: Optional[str] = None,
    vpc_address_mapping: Any = None,
    ignore_aws_accounts: Optional[List[str]] = None,
    process_only_aws_accounts: Optional[List[str]] = None,
    full_return_segment_by_region: Optional[Dict[str, str]] = None,
) -> Any:
    """Filter Cloud WAN events and process each ``new_route`` event.

    Ignores events that are not ``new_route`` type (e.g. attachment-creation
    events) or that belong to a Network Function Group segment (service
    insertion routes are not owned by the attachments being evaluated). For
    each route in a qualifying event, delegates to ``process_route_event`` and
    aggregates the ``unhandled_event`` and ``retry_event`` flags across all routes.

    Returns a dict with keys ``unhandled_event`` and ``retry_event``.
    """
    return_dict = {
        "unhandled_event": False,
        "retry_event": False,
    }

    change_type = configuration_event["changeType"]
    edge_region = configuration_event["edgeRegion"]
    core_network_arn = configuration_event["coreNetworkArn"]

    # The segment holding every known route may be region specific
    # (e.g. regional inspection segments when the last-hop loopback is removed).
    region_full_return_segment = resolve_full_return_segment(
        edge_region=edge_region,
        full_return_segment=full_return_segment,
        full_return_segment_by_region=full_return_segment_by_region,
    )

    # Check if we have a route being learned ("routes" property exists in Message Payload)
    if change_type == "new_route" and "routes" in configuration_event and "segments" in configuration_event:
        # Routes installed in Network Function Group segments are not evaluated (service insertion)
        if "aws:NetworkFunctionGroup:" in json.dumps(configuration_event["segments"], default=str):
            return return_dict

        # Iterate the received routes (VPC Attachments only)
        for route in configuration_event["routes"]:
            r = process_route_event(
                boto3_client_dict=boto3_client_dict,
                global_network_id=global_network_id,
                core_network_arn=core_network_arn,
                route=route,
                perform_deletions=perform_deletions,
                vpc_address_mapping=vpc_address_mapping,
                full_return_segment=region_full_return_segment,
                attachment_type=[ATTACHMENT_TYPE_VPC],
                ignore_aws_accounts=ignore_aws_accounts,
                process_only_aws_accounts=process_only_aws_accounts,
            )

            # perform an or mask to check if we have to retry or unhandled event
            return_dict["unhandled_event"] = return_dict["unhandled_event"] or r["unhandled_event"]
            return_dict["retry_event"] = return_dict["retry_event"] or r["retry_event"]

    else:
        # unhandled event
        return_dict["unhandled_event"] = True

    return return_dict


def handler(event_sqs: Any, context: Any, boto3_client_dict: Any = None) -> Dict[str, Any]:
    """Process an SQS batch of Cloud WAN events.

    Iterates over each SQS record, parses the SNS-wrapped Cloud WAN event, and
    delegates to ``process_cloudwan_event``. Unrecognised event shapes are
    logged and skipped.

    Messages that need a retry (attachment not yet ready) or that failed with an
    unexpected error are reported back as ``batchItemFailures``. SQS makes them
    visible again once the queue visibility timeout expires, counting each
    delivery towards the queue redrive policy (dead-letter queue).

    An optional *boto3_client_dict* parameter supports dependency injection
    of pre-stubbed clients in tests.
    """
    batch_item_failures: List[Dict[str, str]] = []

    try:
        logger.debug(json.dumps({"event": "new_sqs_batch", "payload": event_sqs}, default=str))

        # Dependency injection of boto3 clients (to support mocks in tests)
        if boto3_client_dict is None:
            boto3_client_dict = {aws_api: boto3.client(aws_api) for aws_api in ["networkmanager", "sts"]}

        # Get variables
        global_network_id = os.environ.get(ENV_GLOBAL_NETWORK_ID)
        if not global_network_id:
            raise ValueError(f"Missing required environment variable: {ENV_GLOBAL_NETWORK_ID}")
        full_return_segment = os.environ.get(ENV_FULL_RETURN_TABLE, "")
        full_return_segment_by_region = json.loads(os.environ.get(ENV_FULL_RETURN_TABLE_BY_REGION, "") or "{}")
        perform_deletions = os.environ.get(ENV_PERFORM_ATTACHMENT_DELETIONS, "true").lower().strip() == "true"

        # Read the yml file containing the VPC / Address Mapping
        path_file = os.environ.get(ENV_SEGMENT_ADDRESSING_FILE, "")
        vpc_address_mapping = None
        if path_file != "":
            vpc_address_mapping = import_vpc_address_mapping_file(path_file)
            logger.debug(
                json.dumps({"event": "vpc_address_mapping_loaded", "mapping": vpc_address_mapping}, default=str)
            )

        # Check if we have accounts to process
        ignore_aws_accounts = json.loads(os.environ.get(ENV_IGNORE_AWS_ACCOUNTS, "") or "[]")
        process_only_aws_accounts = json.loads(os.environ.get(ENV_PROCESS_ONLY_AWS_ACCOUNTS, "") or "[]")

        # Now we process the request
        for message in event_sqs["Records"]:
            sqs_message_id = message.get("messageId", "unknown")
            logger.debug(json.dumps({"event": "processing_sqs_message", "sqs_message_id": sqs_message_id}))

            try:
                body = json.loads(message["body"])
                unhandled_event = False
                retry_event = False

                # Let's check what kind of event we have
                if "Message" in body:
                    configuration_event = json.loads(body["Message"])

                    # Get our inputs!
                    if (
                        "changeType" in configuration_event
                        and "edgeRegion" in configuration_event
                        and "coreNetworkArn" in configuration_event
                        and "apiChangeType" in configuration_event
                    ):
                        # Cloud WAN event
                        event_result = process_cloudwan_event(
                            boto3_client_dict=boto3_client_dict,
                            configuration_event=configuration_event,
                            global_network_id=global_network_id,
                            full_return_segment=full_return_segment,
                            perform_deletions=perform_deletions,
                            vpc_address_mapping=vpc_address_mapping,
                            ignore_aws_accounts=ignore_aws_accounts,
                            process_only_aws_accounts=process_only_aws_accounts,
                            full_return_segment_by_region=full_return_segment_by_region,
                        )
                        unhandled_event = event_result["unhandled_event"]
                        retry_event = event_result["retry_event"]

                    else:
                        # unhandled event
                        unhandled_event = True

                # unhandled event
                if unhandled_event:
                    logger.debug(
                        json.dumps(
                            {"event": "unhandled_event", "sqs_message_id": sqs_message_id, "body": body}, default=str
                        )
                    )

                # Hand the message back to SQS: it becomes visible again after the visibility timeout
                if retry_event:
                    batch_item_failures.append({"itemIdentifier": sqs_message_id})
                    logger.info(json.dumps({"event": "retry_requested", "sqs_message_id": sqs_message_id}))

            except Exception as msg_err:
                logger.error(
                    json.dumps(
                        {"event": "message_processing_error", "sqs_message_id": sqs_message_id, "error": str(msg_err)}
                    )
                )
                batch_item_failures.append({"itemIdentifier": sqs_message_id})

    except ClientError as e:
        logger.error(
            json.dumps(
                {
                    "event": "aws_api_error",
                    "error_code": e.response["Error"]["Code"],
                    "error_message": e.response["Error"]["Message"],
                    "service": e.response.get("ResponseMetadata", {}).get("ServiceName", "unknown"),
                }
            )
        )
        raise
    except Exception as e:
        logger.exception(json.dumps({"event": "unhandled_exception", "error": str(e)}))
        raise

    return {"batchItemFailures": batch_item_failures}
