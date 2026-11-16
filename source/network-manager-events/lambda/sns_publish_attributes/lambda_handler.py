"""
Network Manager Events publisher.

Receives raw AWS Network Manager events from Amazon EventBridge, curates them
into a compact message and publishes it to an SNS topic with message
attributes, so that subscribers (e.g. the Cloud WAN Attachment Manager) can use
SNS filter policies instead of deserialising every event.
"""

import json
import logging
import os
import traceback
from typing import Any, Dict, Optional

import boto3

# Environment variables
ENV_SNS_TOPIC_ARN = "SNS_TOPIC_ARN"
ENV_LOG_MESSAGES = "LOG_MESSAGES"
ENV_LOGGING_LEVEL = "LOGGING_LEVEL"


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


def _process_event(event: Any) -> Optional[Dict[str, Any]]:
    """Curate a Network Manager event.

    Returns ``None`` when the event is not of interest, otherwise a dict with
    the message body (``msg_send``) and the SNS message attributes (``msg_attr``).
    """
    detail = event.get("detail", {})

    # Check if it's a legit change message for a Cloud WAN core network
    change_type = detail.get("changeType", None)
    core_arn = detail.get("coreNetworkArn", None)
    edge_location = detail.get("edgeLocation", None)
    if change_type is None or core_arn is None or edge_location is None:
        return None

    # Extract attributes - Core Network
    core_id = str(core_arn.split(":core-network/")[-1])

    message_to_send: Dict[str, Any] = {
        "coreNetworkArn": core_arn,
        "coreNetworkId": core_id,
        "apiChangeType": change_type,
        "edgeRegion": edge_location,
        "routes": [],
        "segments": [],
        "coreUplinkArn": core_arn,
    }

    message_attributes: Dict[str, Any] = {
        "coreNetworkArn": {"DataType": "String", "StringValue": core_arn},
        "changeType": {"DataType": "String", "StringValue": change_type},
        "attachmentRegion": {"DataType": "String", "StringValue": edge_location},
        "coreUplinkArn": {"DataType": "String", "StringValue": core_arn},
    }

    # Extract attributes - Attachment if exists
    core_attachment_arn = detail.get("attachmentArn", None)
    if core_attachment_arn:
        core_attachment_id = str(core_attachment_arn.split(":attachment/")[-1])
        message_to_send["attachmentArn"] = core_attachment_arn
        message_to_send["attachmentId"] = core_attachment_id
        message_attributes["attachmentArn"] = {"DataType": "String", "StringValue": core_attachment_arn}

    # Ignore attachment & friends deletion
    if "_ATTACHMENT_DELETED" in change_type or "_PEERING_DELETED" in change_type or "_CONNECTION_DELETED" in change_type:
        return None

    # Manage attachment & friends creation
    if "_ATTACHMENT_CREATED" in change_type or "_PEERING_CREATED" in change_type or "_CONNECTION_CREATED" in change_type:
        message_to_send["changeType"] = "set"
        return {"msg_send": message_to_send, "msg_attr": message_attributes}

    # Check if we are learning new routes
    if "SEGMENT_ROUTE_INSTALLED" in change_type:
        message_to_send["changeType"] = "new_route"

        # Only forward routes propagated by (typed) attachments
        for route in detail.get("routes", []):
            if any("attachmentType" in attachment for attachment in route.get("attachments", [])):
                message_to_send["routes"].append(route)
        message_to_send["segments"] = detail.get("segments", [])

        # If we don't have interesting routes to send, we drop them
        if len(message_to_send["routes"]) == 0 or len(message_to_send["segments"]) == 0:
            return None

        return {"msg_send": message_to_send, "msg_attr": message_attributes}

    return None


def handler(event: Any, context: Any) -> None:
    try:
        # Get OS variables
        sns_topic_arn = os.environ[ENV_SNS_TOPIC_ARN]
        log_messages = os.environ.get(ENV_LOG_MESSAGES, "false").lower() in ["true", "1"]

        # Log
        if log_messages:
            logger.info(json.dumps(event, default=str))

        # Prepare message to send
        msg_event = _process_event(event=event)
        if msg_event is None:
            return

        message_to_send = msg_event.get("msg_send", None)
        message_attributes = msg_event.get("msg_attr", None)
        if message_to_send is None or message_attributes is None:
            return

        # Send message
        client = boto3.client("sns")
        client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps(message_to_send),
            MessageAttributes=message_attributes,
        )

    except Exception as e:
        logger.error(e)
        traceback.print_tb(e.__traceback__)
        raise e
