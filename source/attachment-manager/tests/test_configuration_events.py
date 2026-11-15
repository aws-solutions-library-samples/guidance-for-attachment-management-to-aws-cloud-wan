"""
SQS/CloudWAN event payloads used as test fixtures.

Contains the raw event dicts that represent different CloudWAN notification
types (attachment creation, new routes, invalid-IP routes, default routes, etc.)
along with the shared identifiers (core_network_arn, global_network_id, etc.)
referenced throughout the test suite.
"""

core_network_arn = "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000"
core_network_id = core_network_arn.split("/")[-1]
global_network_id = "global-network-123456789"
full_return_segment = "fullreturn"
regional_full_return_segment = "inspectioneuw1"
quarantine_routes_segment = "quarantineroutes"

# Attachment account owner: 222222222222
attachment_created_event = {
    "changeType": "set",
    "attachmentArn": "arn:aws:networkmanager::222222222222:attachment/attachment-00000000000000002",
    "attachmentId": "attachment-00000000000000001",
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "VPC_ATTACHMENT_CREATED",
    "edgeRegion": "eu-west-1",
    "routes": [],
    "segments": [],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
}

# Attachment account owner: 222222222222
route_ok = {
    "changeType": "new_route",
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "10.254.137.0/24",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000002",
                    "attachmentType": "vpc",
                }
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "propagatedRouteFamily": "bgp",
            "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
}

# Attachment account owner: 222222222222
route_nok_event_ip = {
    "changeType": "new_route",
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "172.168.1.0/24",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000002",
                    "attachmentType": "vpc",
                }
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "propagatedRouteFamily": "bgp",
            "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
}

# Attachment account owner: 333333333333
route_nok_event_tag = {
    "changeType": "new_route",
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "10.254.137.0/24",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000003",
                    "attachmentType": "vpc",
                }
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "propagatedRouteFamily": "bgp",
            "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
}

invalid_event = {
    "Hello": "world",
}


segment_default_route = {
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "0.0.0.0/0",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000004",
                    "resourceId": "vpc-00000000000000004",
                    "attachmentType": "vpc",
                },
                {
                    "attachmentId": "attachment-00000000000000004",
                    "resourceId": "vpc-00000000000000004",
                    "attachmentType": "vpc",
                },
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "bgpAttributes": {"med": "100", "asPath": ["AS_SEQ: [65450]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "changeType": "new_route",
}


segment_default_route_ipv6 = {
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "0:0:0:0:0:0:0:0/0",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000004",
                    "resourceId": "vpc-00000000000000004",
                    "attachmentType": "vpc",
                },
                {
                    "attachmentId": "attachment-00000000000000004",
                    "resourceId": "vpc-00000000000000004",
                    "attachmentType": "vpc",
                },
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "bgpAttributes": {"med": "100", "asPath": ["AS_SEQ: [65450]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "changeType": "new_route",
}


# Attachment account owner: 555555555555
route_ok_5 = {
    "changeType": "new_route",
    "coreNetworkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
    "coreNetworkId": "core-network-11bf1111f7e92b000",
    "apiChangeType": "SEGMENT_ROUTE_INSTALLED",
    "edgeRegion": "eu-west-1",
    "routes": [
        {
            "destinationCidrBlock": "10.254.250.0/24",
            "attachments": [
                {
                    "attachmentId": "attachment-00000000000000005",
                    "attachmentType": "vpc",
                }
            ],
            "routeType": "route_propagated",
            "routeState": "active",
            "propagatedRouteFamily": "bgp",
            "bgpAttributes": {"med": "0", "asPath": ["AS_SEQ: [65001]"]},
        }
    ],
    "segments": ["nonprod"],
    "coreUplinkArn": "arn:aws:networkmanager::111111111111:core-network/core-network-11bf1111f7e92b000",
}
