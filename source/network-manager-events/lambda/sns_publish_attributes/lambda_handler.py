import os
import logging
import json
import time
import traceback
import boto3
from botocore.exceptions import ClientError


# Variable containing the path of the routing configuration file
ENV_SNS_TOPIC_ARN = "SNS_TOPIC_ARN"

# Initiate logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logging.basicConfig(
    format='%(levelname)s %(threadName)s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO
)
# logger.info("Lambda initialization completed")


def handler(event, context):
    try:
        
        sns_topic_arn = os.environ[ENV_SNS_TOPIC_ARN]
        # logger.info(json.dumps(event))

        # Prepare message to send
        message_to_send = None
        message_attributes = None
        message_deduplication_id = event["id"]
        if "changeType" not in event["detail"].keys():
            return
        
        change_type = event["detail"]["changeType"]
        
        # TGW related change
        if "transitGatewayAttachmentArn" in event["detail"].keys() and "transitGatewayArn" in event["detail"].keys():

            tgw_attachment_arn = event["detail"]["transitGatewayAttachmentArn"]
            tgw_attachment_id = str(tgw_attachment_arn.split("transit-gateway-attachment/")[-1])
            tgw_arn = event["detail"]["transitGatewayArn"]
            tgw_id = str(tgw_arn.split("transit-gateway/")[-1])
            

            if "-ATTACHMENT-CREATED" in change_type or "-PEERING-CREATED" in change_type or "-CONNECTION-CREATED" in change_type:
                change_type_to_advertise = "set"
            elif "-ATTACHMENT-DELETED" in change_type or "-PEERING-DELETED" in change_type or "-CONNECTION-DELETED" in change_type:
                change_type_to_advertise = "remove"
                return
            else:
                return

            message_to_send = {
                "transitGatewayAttachmentArn": tgw_attachment_arn,
                "transitGatewayAttachmentId": tgw_attachment_id,
                "transitGatewayArn": tgw_arn,
                "transitGatewayId": tgw_id,
                "apiChangeType": event["detail"]["changeType"],
                "changeType": change_type_to_advertise
            }

            message_attributes = {
                'transitGatewayArn': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["transitGatewayArn"]
                },
                'transitGatewayAttachmentArn': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["transitGatewayAttachmentArn"]
                },
                'changeType': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["changeType"]
                },
                'coreUplinkArn' : {
                    'DataType': 'String',
                    'StringValue': event["detail"]["transitGatewayArn"]
                }
            }
        
        # CloudWAN related change (Attachment Created)
        elif "coreNetworkArn" in event["detail"].keys() and "attachmentArn" in event["detail"].keys() and "edgeLocation" in event["detail"].keys():
            
            core_attachment_arn = event["detail"]["attachmentArn"]
            core_attachment_id = str(core_attachment_arn.split(":attachment/")[-1])
            core_arn = event["detail"]["coreNetworkArn"]
            core_id = str(core_arn.split(":core-network/")[-1])

            message_to_send = {
                "attachmentArn": core_attachment_arn,
                "attachmentId": core_attachment_id,
                "coreNetworkArn": core_arn,
                "coreNetworkId": core_id,
                "apiChangeType": event["detail"]["changeType"],
                "edgeRegion": event["detail"]["edgeLocation"],
                "coreUplinkArn": core_arn
            }

            if "_ATTACHMENT_CREATED" in change_type or "_PEERING_CREATED" in change_type or "_CONNECTION_CREATED" in change_type:
                change_type_to_advertise = "set"
                message_to_send["changeType"] = change_type_to_advertise
                
            elif "_ATTACHMENT_DELETED" in change_type or "_PEERING_DELETED" in change_type or "_CONNECTION_DELETED" in change_type:
                change_type_to_advertise = "remove"
                message_to_send["changeType"] = change_type_to_advertise
                return # Ignore deletions

            else:
                return
            
            message_attributes = {
                'coreNetworkArn': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["coreNetworkArn"]
                },
                'attachmentArn': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["attachmentArn"]
                },
                'changeType': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["changeType"]
                },
                'attachmentRegion': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["edgeLocation"]
                },
                'coreUplinkArn' : {
                    'DataType': 'String',
                    'StringValue': event["detail"]["coreNetworkArn"]
                }
            }

        
        # CloudWAN related change (Attachment Created)
        elif "coreNetworkArn" in event["detail"].keys() and "edgeLocation" in event["detail"].keys():

            core_arn = event["detail"]["coreNetworkArn"]
            core_id = str(core_arn.split(":core-network/")[-1])
            
            message_to_send = {
                "coreNetworkArn": core_arn,
                "coreNetworkId": core_id,
                "edgeRegion": event["detail"]["edgeLocation"],
                "apiChangeType": event["detail"]["changeType"],
                "routes": [],
                "segments": [],
                "coreUplinkArn": core_arn
            }

            if "SEGMENT_ROUTE_INSTALLED" in change_type:
                change_type_to_advertise = "new_route"
                message_to_send["changeType"] = change_type_to_advertise
                if "routes" in event["detail"].keys():
                    for route in event["detail"]["routes"]:
                        if len(route["attachments"]) > 0:
                            for attachment in route["attachments"]:
                                if "attachmentType" in attachment.keys():
                                    if attachment["attachmentType"] == "vpc":
                                        message_to_send["routes"].append(route)
                                        break
                
                if "segments" in event["detail"].keys():
                    message_to_send["segments"] = event["detail"]["segments"]

                
                # If we don't have interesting routes to send, we drop them
                if len(message_to_send["routes"]) == 0 or len(message_to_send["segments"]) == 0:
                    return

            else:
                return

            message_attributes = {
                'coreNetworkArn': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["coreNetworkArn"]
                },
                'changeType': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["changeType"]
                },
                'attachmentRegion': {
                    'DataType': 'String',
                    'StringValue': event["detail"]["edgeLocation"]
                },
                'coreUplinkArn' : {
                    'DataType': 'String',
                    'StringValue': event["detail"]["coreNetworkArn"]
                }
            }
        
        
        # Nothing to manage
        else:
            return

        # Send message
        if message_to_send != None and message_attributes != None:
            client = boto3.client("sns")
            response = client.publish(
                TopicArn=sns_topic_arn,
                Message=json.dumps(message_to_send),
                MessageAttributes=message_attributes
            )
    
    except Exception as e:
        logger.error(e)
        traceback.print_tb(e.__traceback__)
        raise e

    return
