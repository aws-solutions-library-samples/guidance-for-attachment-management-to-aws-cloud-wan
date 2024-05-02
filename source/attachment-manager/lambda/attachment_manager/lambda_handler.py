import os
import logging
import json
import yaml
import traceback
import ipaddress
import time
import boto3
from botocore.exceptions import ClientError


# Define environmental variables
ENV_ACCOUNT_READ_ROLE_ARN   = "AWS_ACCOUNT_READ_ROLE_ARN"
ENV_SQS_URL                 = "SQS_URL"
ENV_CORE_NETWORK_ARN        = "MANAGED_CORE_NETWORK_ARN"
ENV_GLOBAL_NETWORK_ID       = "MANAGED_GLOBAL_NETWORK_ID"
ENV_SEGMENT_ADDRESSING_FILE = "SEGMENT_ADDRESSING_FILE"
ENV_FULL_RETURN_TABLE       = "FULL_RETURN_TABLE"
ENV_IGNORE_AWS_ACCOUNTS     = "IGNORE_AWS_ACCOUNTS"
ENV_PROCESS_ONLY_AWS_ACCOUNTS       = "PROCESS_ONLY_AWS_ACCOUNTS"
ENV_PERFORM_ATTACHMENT_DELETIONS    = "PERFORM_ATTACHMENT_DELETIONS"
ENV_SNS_TOPIC_ARN           = "SNS_TOPIC_ARN"
ENV_SNS_TOPIC_REGION        = "SNS_TOPIC_REGION"

# Define global static variables
ACCOUNT_ROUTE_DOMAIN_TAG    = "route-domain"
QUARANTINE_SEGMENT          = "quarantine"
QUARANTINE_ROUTES_SEGMENT   = "quarantineroutes"


# Initiate logging
logger = logging.getLogger()
logger.setLevel(logging.INFO) # logging.DEBUG
logging.basicConfig(
    format='%(levelname)s %(threadName)s [%(filename)s:%(lineno)d] %(message)s',
    datefmt='%Y-%m-%d:%H:%M:%S',
    level=logging.INFO
)
logger.info("Lambda initialization completed")



def publish_sns_topic(sns_topic_arn, sns_topic_region, msg):
    try:
        client = boto3.client("sns", region_name = sns_topic_region)
        response = client.publish(
            TopicArn=sns_topic_arn,
            Message=json.dumps({ "msg": msg })
        )
    except Exception as e:
        logger.error(e)


# Discovers existing conflicting routes within a cloudwan segment
def cloudwan_discover_conflicting_vpc_routes(boto_client, global_network_id: str, core_network_id: str, segment: str, edge_location: str, route_prefix: str, attachment_id: str):
    conflict_routes = []

    # Get supernets / wider summaries that may contain the prefixe
    response = boto_client.get_network_routes(
        GlobalNetworkId=global_network_id,
        RouteTableIdentifier={
            'CoreNetworkSegmentEdge': {
                'CoreNetworkId': core_network_id,
                'SegmentName': segment,
                'EdgeLocation': edge_location
            }
        },
        SupernetOfMatches=[ route_prefix ],
        States=[ 'ACTIVE' ],
        Types=[ 'PROPAGATED' ]
    )
    conflict_routes = conflict_routes + list(response["NetworkRoutes"])

    # Get subneets / narrower summaries that may contain the prefixe
    response = boto_client.get_network_routes(
        GlobalNetworkId=global_network_id,
        RouteTableIdentifier={
            'CoreNetworkSegmentEdge': {
                'CoreNetworkId': core_network_id,
                'SegmentName': segment,
                'EdgeLocation': edge_location
            }
        },
        SubnetOfMatches=[ route_prefix ],
        States=[ 'ACTIVE' ],
        Types=[ 'PROPAGATED' ]
    )
    conflict_routes = conflict_routes + list(response["NetworkRoutes"])

    # Only check vpc routes
    vpc_conflict_routes = []
    for route in conflict_routes:
        route_vpc = False
        for destination in route["Destinations"]:
            if destination["ResourceType"] == "vpc" and destination["CoreNetworkAttachmentId"] != attachment_id:
                vpc_conflict_routes.append(route)
                break

    return vpc_conflict_routes



def import_vpc_address_mapping_file(path_file: str) -> dict:
    routing_config = dict()
    
    with open(path_file, "r") as file:
        routing_config = yaml.safe_load(file)

    # TODO: Validate the input we are reading from the file
    
    return routing_config



def get_account_tag_from_account_id(role_arn: str, account_id: str) -> list:
    # Assume role
    sts = boto3.client('sts')
    token = sts.assume_role(RoleArn=role_arn, RoleSessionName='spoke_vpc')
    cred = token['Credentials']
    temp_access_key = cred['AccessKeyId']
    temp_secret_key = cred['SecretAccessKey']
    session_token = cred['SessionToken']
    session = boto3.session.Session(
        aws_access_key_id=temp_access_key,
        aws_secret_access_key=temp_secret_key,
        aws_session_token=session_token
    )

    # Query the organizations
    account_tags = []
    client = session.client("organizations")
    next_token = None
    while True:
        if next_token is None:
            response = client.list_tags_for_resource(
                ResourceId=account_id
            )
        else:
            response = client.list_tags_for_resource(
                ResourceId=account_id,
                NextToken=next_token
            )
        
        # Get the tags
        if "Tags" in response.keys():
            account_tags = account_tags + response["Tags"]

        # Loop control
        if "NextToken" in response.keys():
            next_token = response["NextToken"]
        else:
            break

    return account_tags


def process_cloudwan_event(configuration_event: dict, vpc_address_mapping: dict = None):
    client = boto3.client("networkmanager")
    unhandled_event = False
    retry_event = False

    change_type = configuration_event["changeType"]
    edge_region = configuration_event["edgeRegion"]
    core_network_arn = configuration_event["coreNetworkArn"]
    core_network_id = core_network_arn.split("/")[-1]
    api_change_type = configuration_event["apiChangeType"]
    global_network_id = os.environ[ENV_GLOBAL_NETWORK_ID]
    full_return_segment = os.environ[ENV_FULL_RETURN_TABLE]
    
    # SNS Monitoring
    sns_topic_arn = ""
    sns_topic_region = ""
    if ENV_SNS_TOPIC_ARN in os.environ.keys():
        sns_topic_arn = os.environ[ENV_SNS_TOPIC_ARN]
    if ENV_SNS_TOPIC_REGION in os.environ.keys():
        sns_topic_region = os.environ[ENV_SNS_TOPIC_REGION]

    # Accounts to ignore or process (for testing purposes)
    ignore_aws_accounts = []
    if ENV_IGNORE_AWS_ACCOUNTS in os.environ.keys():
        ignore_aws_accounts = json.loads(os.environ[ENV_IGNORE_AWS_ACCOUNTS])
    process_only_aws_accounts = []
    if ENV_PROCESS_ONLY_AWS_ACCOUNTS in os.environ.keys():
        process_only_aws_accounts = json.loads(os.environ[ENV_PROCESS_ONLY_AWS_ACCOUNTS])
    
    if os.environ[ENV_PERFORM_ATTACHMENT_DELETIONS] == "true":
        bool_perform_deletions = True
    else:
        bool_perform_deletions = False
    
    
    # Check if it's a VPC attachment being created ("newRoutes" property doesn't exist in Message Payload)
    if change_type == "set" and "attachmentArn" in configuration_event.keys():
        unhandled_event = False
        pass
        
    # Check if we have a route being learned ("newRoutes" property exists in Message Payload)
    elif change_type == "new_route" and "routes" in configuration_event.keys() and "segments" in configuration_event.keys():
        new_routes = configuration_event["routes"]
        segments = configuration_event["segments"]

        # Iterate the received routes
        for route in configuration_event["routes"]:
            route_prefix = route["destinationCidrBlock"]
            ipaddr_route_prefix = ipaddress.IPv4Network(route_prefix)
            ipaddr_route_prefix_first = ipaddr_route_prefix.network_address
            ipaddr_route_prefix_last = ipaddr_route_prefix.broadcast_address
            
            if "attachments" in route.keys() and route["routeType"] == "route_propagated" and route["routeState"] == "active":
                for attachment in route["attachments"]:
                    
                    # Only process routes coming from VPC Attachments
                    if attachment["attachmentType"] == "vpc":
                        
                        
                        # Describe attachment
                        attachment_id = attachment["attachmentId"]
                        response = client.get_vpc_attachment(AttachmentId=attachment_id)
                        attachment_object = response["VpcAttachment"]["Attachment"]
                        
                        edge_region = attachment_object["EdgeLocation"]
                        current_segment = attachment_object["SegmentName"]
                        attachment_state = attachment_object["State"]
                        spoke_account_id = attachment_object["ResourceArn"].split(":")[4]
                        attachment_arn = f"arn:aws:networkmanager::{spoke_account_id}:attachment/{attachment_id}"
                        
                        
                        # Check if we have filtered accounts

                        # 1. If the spoke account is part of the ignored accounts, return
                        if spoke_account_id in ignore_aws_accounts:
                            return False, False # unhandled_event, retry_event
                        
                        # 2. If the spoke account is not part of the list and we have specified accounts to be processed, return
                        if spoke_account_id not in process_only_aws_accounts and len(process_only_aws_accounts) > 0:
                            return False, False # unhandled_event, retry_event
                        
                        # 3. Else, we need to process because:
                        #    - Account is not part of the ignored accounts, or
                        #    - Account is part of the process accounts, or
                        #    - Process Accounts are empty (i.e. match any)
                        segment_tag = None
                        account_tag = None

                        if "Tags" in attachment_object.keys():
                            for tag in attachment_object["Tags"]:
                                if tag["Key"] == ACCOUNT_ROUTE_DOMAIN_TAG:
                                    segment_tag = tag["Value"]
                                    break
                        
                        # If we don't have a tag or if tag is quarantine, let's find out about the account level tag
                        if segment_tag == None: # or segment_tag == QUARANTINE_SEGMENT:
                            account_tags = get_account_tag_from_account_id(os.environ[ENV_ACCOUNT_READ_ROLE_ARN], spoke_account_id)
                            for tag in account_tags:
                                if tag["Key"] == ACCOUNT_ROUTE_DOMAIN_TAG:
                                    account_tag = tag["Value"]
                                    break
                        
                        elif account_tag == segment_tag:
                            # There's nothing to do, we can safely return
                            pass
                        
                        else:
                            # The segment has been deliberately set, so this takes precendence over the account_tag.
                            # We still need to verify the addressing compliance
                            account_tag = segment_tag
                            unhandled_event = False
                            retry_event = False
                            # return unhandled_event, retry_event
                            

                        # If the attachment is in the correct status
                        if attachment_state in ["AVAILABLE"]:
                            # At this point we know of:
                            #  - New prefix being propagated:   route_prefix
                            #  - Spoke VPC Current segment:     current_segment
                            #  - Spoke VPC Attachment Tag:      segment_tag
                            #  - Spoke VPC Account Tag:         account_tag
                            
                            
                            # Let's run our enrolment logic
                            delete_attachment = False

                            if segment_tag == None and account_tag == None: # (segment_tag == None or segment_tag == QUARANTINE_SEGMENT) and account_tag == None:
                                # 1. If there is no account tag for a 'cloudwan untagged' spoke vpc, let's delete the attachment
                                logger.info(f"Deleting attachment {attachment_id} (state: {attachment_state}) because there is no account tag for a 'cloudwan untagged' spoke vpc")
                                delete_attachment = True

                            else:

                                # 2. First check if the route is coherent with the mapping for the account_tag
                                prefix_belongs_in_summary = False
                                if vpc_address_mapping != None:
                                    if account_tag in vpc_address_mapping.keys():
                                        if edge_region in vpc_address_mapping[account_tag].keys():
                                            segment_allowed_prefixes = vpc_address_mapping[account_tag][edge_region]
                                            for segment_allowed_prefix in segment_allowed_prefixes:
                                                ipaddr_segment_allowed_prefix = ipaddress.IPv4Network(segment_allowed_prefix)
                                                if ipaddr_route_prefix_first in ipaddr_segment_allowed_prefix and ipaddr_route_prefix_last in ipaddr_segment_allowed_prefix:
                                                    prefix_belongs_in_summary = True
                                                    break
                                    else:
                                        # If no route-domain is defined, we allow
                                        prefix_belongs_in_summary = True
                                else:
                                    # If no vpc-map is defined, we allow
                                    prefix_belongs_in_summary = True                                  


                                if prefix_belongs_in_summary == False and vpc_address_mapping != None and segment_tag != QUARANTINE_SEGMENT:
                                    # 2.1. If the address doesn't belong to the IPAM address space, delete the attachment
                                    msg = f"Deleting attachment {attachment_id} (state: {attachment_state}) because the propagated prefix '{route_prefix}' doesn't belong to the current IPAM space"
                                    logger.info(msg)
                                    if sns_topic_arn != "" and sns_topic_region != "" : publish_sns_topic(sns_topic_arn, sns_topic_region, msg)
                                        
                                    delete_attachment = True


                                # 3. If the segment of the attachment is 'quarantine' (i.e. 1st time enrolment), check if the propagated routes already exist or overlap with existing VPC routes. We only need to do this the first time the VPC is attached because VPCs can be created with manually input CIDRs (e.g. non-routable, or guess of routable), but aditional CIDRs need to come from IPAM (SCP enforced).
                                # QUARANTINE_SEGMENT          = "quarantine"
                                # QUARANTINE_ROUTES_SEGMENT   = "quarantineroutes"
                                if delete_attachment == False and (segment_tag == QUARANTINE_SEGMENT or segment_tag == None):
                                    conflict_routes = []

                                    conflict_routes = conflict_routes + cloudwan_discover_conflicting_vpc_routes(client, global_network_id, core_network_id, full_return_segment, edge_region, route_prefix, attachment_id)

                                    conflict_routes = conflict_routes + cloudwan_discover_conflicting_vpc_routes(client, global_network_id, core_network_id, QUARANTINE_ROUTES_SEGMENT, edge_region, route_prefix, attachment_id)

                                    logger.info("Conflicting Routes: "+json.dumps(conflict_routes))

                                    if len(conflict_routes) > 0 :
                                        # We have conflicting routes, delete!
                                        delete_attachment = True


                                # If the address belongs to the IPAM address space, but the tags are different, let's tag them properly
                                if delete_attachment == False and segment_tag != account_tag:
                                    msg = f"Tagging attachment '{attachment_arn}' (state: {attachment_state}) for segment '{account_tag}'"
                                    logger.info(msg)
                                    if sns_topic_arn != "" and sns_topic_region != "" : publish_sns_topic(sns_topic_arn, sns_topic_region, msg)
                                    response = client.tag_resource(ResourceArn=attachment_arn,Tags=[{'Key': ACCOUNT_ROUTE_DOMAIN_TAG,'Value': account_tag}])


                            # Let's process the flags we have...
                            if delete_attachment == True and bool_perform_deletions == True:
                                # May need to wait for the attachment to stabilise
                                response = client.delete_attachment(AttachmentId=attachment_id)

                            elif delete_attachment == True and bool_perform_deletions == False:
                                # Lambda to set tag to 'quarantine'
                                msg = f"Tagging attachment '{attachment_arn}' (state: {attachment_state}) for segment '{QUARANTINE_SEGMENT}'"
                                logger.info(msg)
                                if sns_topic_arn != "" and sns_topic_region != "" : publish_sns_topic(sns_topic_arn, sns_topic_region, msg)
                                response = client.tag_resource(ResourceArn=attachment_arn,Tags=[{'Key': ACCOUNT_ROUTE_DOMAIN_TAG,'Value': QUARANTINE_SEGMENT}])
                                
                        
                        elif attachment_state in ["UPDATING", "PENDING_NETWORK_UPDATE", "PENDING_TAG_ACCEPTANCE"]:
                            retry_event = True
                            logger.info(f"Attachment {attachment_id} (state: {attachment_state}) not ready. Marking it for retry.")
                        
                        else:
                            unhandled_event = True

    else:
        # unhandled event
        unhandled_event = True

    return unhandled_event, retry_event



def process_tgw_event(configuration_event: dict, vpc_address_mapping: dict = None):
    client = boto3.client("ec2")
    unhandled_event = False
    retry_event = False

    api_change_type = configuration_event["apiChangeType"]
    change_type = configuration_event["changeType"]
    tgw_attachment_id = configuration_event["transitGatewayAttachmentId"]
    tgw_id = configuration_event["transitGatewayId"]
    tgw_attachment_description = configuration_event["transitGatewayAttachmentDescription"] if "transitGatewayAttachmentDescription" in configuration_event.keys() else None
    
    logger.info(api_change_type, change_type, tgw_attachment_id, tgw_id)
    

    return unhandled_event, retry_event



def handler(event_sqs, context):
    try:
        logger.info("(+) New event: "+json.dumps(event_sqs))
        
        # Read the yml file containing the VPC / Address Mapping
        path_file = os.environ[ENV_SEGMENT_ADDRESSING_FILE]
        vpc_address_mapping = None
        if path_file != "":
            vpc_address_mapping = import_vpc_address_mapping_file(path_file)
            logger.info("VPC Address Mapping: "+json.dumps(vpc_address_mapping))


        # Now we process the request
        for message in event_sqs["Records"]:
            body = json.loads(message["body"])
            sqs_message_id = message["messageId"]
            sqs_receipt_handle = message["receiptHandle"]
            unhandled_event = False
            retry_event = False
            
            # Let's check what kind of event we have
            if "Message" in body.keys():
                configuration_event = json.loads(body["Message"])

                
                # Get our inputs!
                if "changeType" in configuration_event.keys() and "edgeRegion" in configuration_event.keys() and "coreNetworkArn" in configuration_event.keys() and "apiChangeType" in configuration_event.keys():
                    # CloudWAN event
                    unhandled_event, retry_event = process_cloudwan_event(configuration_event, vpc_address_mapping)

                elif "changeType" in configuration_event.keys() and "transitGatewayArn" in configuration_event.keys() and "apiChangeType" in configuration_event.keys():
                    # CloudWAN event
                    unhandled_event, retry_event = process_tgw_event(configuration_event, vpc_address_mapping)

                else:
                    # unhandled event
                    unhandled_event = True
            
            # unhandled event
            if unhandled_event == True:
                logger.info("(+) Unhandled event: "+json.dumps(event_sqs))
    
    except Exception as e:
        #traceback.print_exc()
        #logger.error("(+) Unhandled event: "+json.dumps(event_sqs))
        logger.error(e)
        traceback.print_tb(e.__traceback__)
        raise e


    # If we have a retry, let's raise the exception to avoid evicting from queue
    # https://docs.aws.amazon.com/en_gb/lambda/latest/dg/with-sqs.html
    if retry_event == True:
        msg = "(+) Retrying event: "+json.dumps(event_sqs)
        logger.info(msg)
        time.sleep(120) # Sleep 2 mins before raising the exception (this may only apply when creating a new attachment)
        raise Exception(msg)

    else:
        pass
        # Uncomment this if debugging / running from developer machine
        # try:
        #     # Remove the message from the queue
        #     sqs_client = boto3.client("sqs")
        #     response = sqs_client.delete_message(
        #         QueueUrl=os.environ[ENV_SQS_URL],
        #         ReceiptHandle=sqs_receipt_handle
        #     )
        # except Exception as ex:
        #     logger.error(ex)
        #     traceback.print_tb(ex.__traceback__)
    
    
    return


'''
# Variables to test
export AWS_ACCOUNT_READ_ROLE_ARN="arn:aws:iam::116953415465:role/org_account_reader_name_dev"
export FULL_RETURN_TABLE="fullreturn"
export IGNORE_AWS_ACCOUNTS="[]"
export MANAGED_CORE_NETWORK_ARN="arn:aws:networkmanager::169017635628:core-network/core-network-0d99e3bd1eb6430d4"
export MANAGED_GLOBAL_NETWORK_ID="global-network-0b36f5c1316553091"
export MANAGED_TGW_ARN=""
export PERFORM_ATTACHMENT_DELETIONS="true"
export PROCESS_ONLY_AWS_ACCOUNTS="[]"
export SEGMENT_ADDRESSING_FILE="vpc_segment_address_map.yml"
export SNS_TOPIC_ARN="arn:aws:sns:us-west-2:169017635628:network_manager_events_sns"
'''

TEST_NEW_ATTACHMENT_EVENT ={}

TEST_NEW_ROUTE_EVENT = {
    "Records": [
        {
            "messageId": "4a5b7771-dfad-42c0-9271-3bcd5bec4882",
            "receiptHandle": "AQEBdkRm5Q1fixcOeBRxC8sTiVQwikL97QJx/gOUFPFDnZZnAb+ewuOs+668UspKakt19ZFS8va6YfL6qwsMQvVsCDmyuvD9wfV7Kki1ezMGyiGdiQBqQXGzXS/5GT/ptXADySdj16bdz7a1DW1McijGstC3aa/ryygHE8B6V8JXIqUW1vGmOsiiOVzxeWyBy67/N0q4hSlGo3BtQmrxMnV0RnxpLLxlen2ay0Cde0TPPcodCWc6RmOF96Z1Y1i2zF36Ppf7i7Pm+DCLalXlLvrd0j/8e9TaO3e+5gbPE2vbSEAHh7I3nBSbvP+S4N/ipOxYRqWdUodU2+ueH5VlzOoppmFKaqzxniv1/Fk9sraWl+KOVa8Af7kzXlnJhetSKL+LQHwSIGsn1a9tTDNpPY+F2OGrS1Y3tMgZ3DVlAIrFUXU=",
            "body": "{\n  \"Type\" : \"Notification\",\n  \"MessageId\" : \"f8cb1761-4d8a-547e-b620-492e93135637\",\n  \"TopicArn\" : \"arn:aws:sns:us-west-2:169017635628:network_manager_events_sns\",\n  \"Message\" : \"{\\\"coreNetworkArn\\\": \\\"arn:aws:networkmanager::169017635628:core-network/core-network-0d99e3bd1eb6430d4\\\", \\\"coreNetworkId\\\": \\\"core-network-0d99e3bd1eb6430d4\\\", \\\"edgeRegion\\\": \\\"us-east-1\\\", \\\"apiChangeType\\\": \\\"SEGMENT_ROUTE_INSTALLED\\\", \\\"routes\\\": [{\\\"destinationCidrBlock\\\": \\\"10.203.160.0/24\\\", \\\"attachments\\\": [{\\\"attachmentId\\\": \\\"attachment-0182be230c336cb81\\\", \\\"resourceId\\\": \\\"vpc-0402b57a608d71e4f\\\", \\\"attachmentType\\\": \\\"vpc\\\"}], \\\"routeType\\\": \\\"route_propagated\\\", \\\"routeState\\\": \\\"active\\\"}], \\\"segments\\\": [\\\"quarantineroutes\\\"], \\\"coreUplinkArn\\\": \\\"arn:aws:networkmanager::169017635628:core-network/core-network-0d99e3bd1eb6430d4\\\", \\\"changeType\\\": \\\"new_route\\\"}\",\n  \"Timestamp\" : \"2024-02-21T11:19:53.570Z\",\n  \"SignatureVersion\" : \"1\",\n  \"Signature\" : \"Q497M7m2VWS4OVaZiGXwcy0HJ21UtyiPT/y0gVY7Eg9hIrIY/PZw+HqicCGhxjEYxyVhVH45Xbs51xGwgT+YJlYF4HGlBUMaLtEai6UaSQXZfniJN10hayyZXFfpjsu0xGG558r9epxfd+gMwRV9NlJ6JQLo0/JlkgzdTw5/GYIvMd6Akfn0xNIRFiaIgkTzQzAyIIGBMxiv4NoHG+8eortyqolnaEzNpI1L+0C9oCs8VzDM9QqNCsNOMkoENvJmJgAeIPGL3Tzfy+LLJN6toYRGr/xHWr2/CuPCkw3Dm/E7YjRgyq6iaWPcd5G65oDxnzNqFMPb0Thw80IdwX0DWw==\",\n  \"SigningCertURL\" : \"https://sns.us-west-2.amazonaws.com/SimpleNotificationService-60eadc530605d63b8e62a523676ef735.pem\",\n  \"UnsubscribeURL\" : \"https://sns.us-west-2.amazonaws.com/?Action=Unsubscribe&SubscriptionArn=arn:aws:sns:us-west-2:169017635628:network_manager_events_sns:452d9824-df62-4cbe-8d82-bf6ab4ab74d3\",\n  \"MessageAttributes\" : {\n    \"attachmentRegion\" : {\"Type\":\"String\",\"Value\":\"us-east-1\"},\n    \"coreUplinkArn\" : {\"Type\":\"String\",\"Value\":\"arn:aws:networkmanager::169017635628:core-network/core-network-0d99e3bd1eb6430d4\"},\n    \"coreNetworkArn\" : {\"Type\":\"String\",\"Value\":\"arn:aws:networkmanager::169017635628:core-network/core-network-0d99e3bd1eb6430d4\"},\n    \"changeType\" : {\"Type\":\"String\",\"Value\":\"SEGMENT_ROUTE_INSTALLED\"}\n  }\n}",
            "attributes": {
                "ApproximateReceiveCount": "1",
                "AWSTraceHeader": "Root=1-65d5dc59-0ff861215e025f3b20aea149;Parent=4d5e0f7c173ba796;Sampled=0;Lineage=adaf0d36:0",
                "SentTimestamp": "1708514393639",
                "SenderId": "AIDAIYLAVTDLUXBIEIX46",
                "ApproximateFirstReceiveTimestamp": "1708514393647"
            },
            "messageAttributes": {},
            "md5OfBody": "9d270bc3d5483c43d3ba07fd128a2cf3",
            "eventSource": "aws:sqs",
            "eventSourceARN": "arn:aws:sqs:us-east-1:169017635628:core-network-attachment-manager-primary",
            "awsRegion": "us-east-1"
        }
    ]
}

if __name__ == '__main__':

    event_sqs = TEST_NEW_ROUTE_EVENT
    context = {}
    handler(event_sqs, context)
