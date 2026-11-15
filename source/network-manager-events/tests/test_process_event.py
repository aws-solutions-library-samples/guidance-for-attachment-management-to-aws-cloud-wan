# pytest --verbose
import pytest
from lambda_handler import _process_event

# Test 1 - Empty event
test_event_1 = {"detail": {}}
test_msg_return_1 = None

# Test 2 - Attachment Created
test_event_2 = {
    "detail": {
        "attachmentArn": "arn:aws:networkmanager::111111111111:attachment/attachment-0f54e1e8d847f7d42",
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "VPC_ATTACHMENT_CREATED",
        "edgeLocation": "eu-west-1",
    }
}
test_msg_send_2 = {
    "changeType": "set",
    "attachmentArn": test_event_2["detail"]["attachmentArn"],
    "attachmentId": test_event_2["detail"]["attachmentArn"].split("/")[-1],
    "coreNetworkArn": test_event_2["detail"]["coreNetworkArn"],
    "coreNetworkId": test_event_2["detail"]["coreNetworkArn"].split("/")[-1],
    "apiChangeType": test_event_2["detail"]["changeType"],
    "edgeRegion": test_event_2["detail"]["edgeLocation"],
    "routes": [],
    "segments": [],
    "coreUplinkArn": test_event_2["detail"]["coreNetworkArn"],
}
test_msg_attr_2 = {
    "coreNetworkArn": {
        "DataType": "String",
        "StringValue": test_event_2["detail"]["coreNetworkArn"],
    },
    "attachmentArn": {
        "DataType": "String",
        "StringValue": test_event_2["detail"]["attachmentArn"],
    },
    "changeType": {
        "DataType": "String",
        "StringValue": test_event_2["detail"]["changeType"],
    },
    "attachmentRegion": {"DataType": "String", "StringValue": test_event_2["detail"]["edgeLocation"]},
    "coreUplinkArn": {
        "DataType": "String",
        "StringValue": test_event_2["detail"]["coreNetworkArn"],
    },
}
test_msg_return_2 = {"msg_send": test_msg_send_2, "msg_attr": test_msg_attr_2}

# Test 3 - Attachment Deleted
test_event_3 = {
    "detail": {
        "attachmentArn": "arn:aws:networkmanager::111111111111:attachment/attachment-0f54e1e8d847f7d42",
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "VPC_ATTACHMENT_DELETED",
        "edgeLocation": "eu-west-1",
    }
}
test_msg_return_3 = None

# Test 4 - Segment Routes Added - same region
test_event_4 = {
    "detail": {
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "SEGMENT_ROUTE_INSTALLED",
        "edgeLocation": "eu-west-1",
        "segments": ["nonprod"],
        "routes": [
            {
                "destinationCidrBlock": "10.254.137.0/24",
                "attachments": [
                    {
                        "attachmentId": "attachment-1234567890abcdef0",
                        "attachmentType": "vpc",
                    }
                ],
                "routeType": "route_propagated",
                "routeState": "active",
                "propagatedRouteFamily": "bgp",
                "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
            }
        ],
    }
}
test_msg_send_4 = {
    "changeType": "new_route",
    "coreNetworkArn": test_event_4["detail"]["coreNetworkArn"],
    "coreNetworkId": test_event_4["detail"]["coreNetworkArn"].split("/")[-1],
    "apiChangeType": test_event_4["detail"]["changeType"],
    "edgeRegion": test_event_4["detail"]["edgeLocation"],
    "routes": test_event_4["detail"]["routes"],
    "segments": test_event_4["detail"]["segments"],
    "coreUplinkArn": test_event_4["detail"]["coreNetworkArn"],
}
test_msg_attr_4 = {
    "coreNetworkArn": {
        "DataType": "String",
        "StringValue": test_event_4["detail"]["coreNetworkArn"],
    },
    "changeType": {
        "DataType": "String",
        "StringValue": test_event_4["detail"]["changeType"],
    },
    "attachmentRegion": {"DataType": "String", "StringValue": test_event_4["detail"]["edgeLocation"]},
    "coreUplinkArn": {
        "DataType": "String",
        "StringValue": test_event_4["detail"]["coreNetworkArn"],
    },
}
test_msg_return_4 = {"msg_send": test_msg_send_4, "msg_attr": test_msg_attr_4}

# Test 5 - Segment Routes without routes
test_event_5 = {
    "detail": {
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "SEGMENT_ROUTE_INSTALLED",
        "edgeLocation": "eu-west-1",
        "segments": ["nonprod"],
        "edgeLocation": "eu-west-1",
        "routes": [],
    }
}
test_msg_return_5 = None

# Test 6 - Segment Routes Removed
test_event_6 = {
    "detail": {
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "SEGMENT_ROUTE_UNINSTALLED",
        "edgeLocation": "eu-west-1",
        "segments": ["nonprod"],
        "routes": [
            {
                "destinationCidrBlock": "10.254.137.0/24",
                "attachments": [
                    {
                        "attachmentId": "attachment-1234567890abcdef0",
                        "attachmentType": "vpc",
                    }
                ],
                "routeType": "route_propagated",
                "routeState": "active",
                "propagatedRouteFamily": "bgp",
            }
        ],
    }
}
test_msg_return_6 = None

# Test 7 - Network Manager event without a core network (e.g. global network / TGW events)
test_event_7 = {
    "detail": {
        "changeType": "VPC-ATTACHMENT-CREATED",
        "transitGatewayArn": "arn:aws:ec2:eu-west-1:111111111111:transit-gateway/tgw-0123456789abcdef0",
        "region": "eu-west-1",
    }
}
test_msg_return_7 = None

# Test 8 - Segment route with several attachments is forwarded once
test_event_8 = {
    "detail": {
        "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
        "changeType": "SEGMENT_ROUTE_INSTALLED",
        "edgeLocation": "eu-west-1",
        "segments": ["nonprod"],
        "routes": [
            {
                "destinationCidrBlock": "10.254.0.0/16",
                "attachments": [
                    {"attachmentId": "attachment-1234567890abcdef0", "attachmentType": "vpc"},
                    {"attachmentId": "attachment-1234567890abcdef1", "attachmentType": "vpc"},
                ],
                "routeType": "route_propagated",
                "routeState": "active",
            }
        ],
    }
}


@pytest.mark.aws_lambdas
def test_process_event() -> None:
    assert _process_event(test_event_1) == test_msg_return_1
    assert _process_event(test_event_2) == test_msg_return_2
    assert _process_event(test_event_3) == test_msg_return_3
    assert _process_event(test_event_4) == test_msg_return_4
    assert _process_event(test_event_5) == test_msg_return_5
    assert _process_event(test_event_6) == test_msg_return_6



@pytest.mark.aws_lambdas
def test_process_event_without_core_network() -> None:
    assert _process_event(test_event_7) == test_msg_return_7


@pytest.mark.aws_lambdas
def test_process_event_route_forwarded_once() -> None:
    result = _process_event(test_event_8)
    assert result is not None
    assert result["msg_send"]["routes"] == test_event_8["detail"]["routes"]
