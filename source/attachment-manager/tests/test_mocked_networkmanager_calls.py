"""
Pre-built botocore Stubber response dicts for NetworkManager API calls.

Each entry is a dict with ``call`` (method name), ``expected_params`` (the
params the Stubber validates against), and ``response`` (the mocked return
value).  Fixtures cover get_vpc_attachment, get_network_routes (supernet and
subnet variants, with and without overlapping routes), tag_resource,
and delete_attachment.

Import individual fixtures into test modules and pass them to
``init_boto3_stubber`` to build a pre-queued NetworkManager client.
"""

from datetime import datetime

from test_configuration_events import (
    core_network_arn,
    core_network_id,
    full_return_segment,
    global_network_id,
    quarantine_routes_segment,
    regional_full_return_segment,
    route_ok,
    route_ok_5,
)

nm_get_vpc_attachment_00000000000000002 = {
    "call": "get_vpc_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000002",
    },
    "response": {
        "VpcAttachment": {
            "Attachment": {
                "CoreNetworkId": core_network_id,
                "CoreNetworkArn": core_network_arn,
                "AttachmentId": "attachment-00000000000000002",
                "OwnerAccountId": "222222222222",
                "AttachmentType": "VPC",
                "EdgeLocation": "eu-west-1",
                "EdgeLocations": ["eu-west-1"],
                "ResourceArn": "arn:aws:networkmanager::222222222222:attachment/attachment-00000000000000002",
                "SegmentName": "quarantine",
                "State": "AVAILABLE",
                "Tags": [],
                "CreatedAt": datetime(2015, 1, 1),
                "UpdatedAt": datetime(2015, 1, 1),
                "LastModificationErrors": [],
            },
            "SubnetArns": [],
        }
    },
}

nm_get_vpc_attachment_00000000000000003 = {
    "call": "get_vpc_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000003",
    },
    "response": {
        "VpcAttachment": {
            "Attachment": {
                "CoreNetworkId": core_network_id,
                "CoreNetworkArn": core_network_arn,
                "AttachmentId": "attachment-00000000000000003",
                "OwnerAccountId": "333333333333",
                "AttachmentType": "VPC",
                "EdgeLocation": "eu-west-1",
                "EdgeLocations": ["eu-west-1"],
                "ResourceArn": "arn:aws:networkmanager::333333333333:attachment/attachment-00000000000000003",
                "SegmentName": "quarantine",
                "State": "AVAILABLE",
                "Tags": [],
                "CreatedAt": datetime(2015, 1, 1),
                "UpdatedAt": datetime(2015, 1, 1),
                "LastModificationErrors": [],
            },
            "SubnetArns": [],
        }
    },
}

nm_tag_vpc_attachment_00000000000000002 = {
    "call": "tag_resource",
    "expected_params": {
        "ResourceArn": "arn:aws:networkmanager::222222222222:attachment/attachment-00000000000000002",
        "Tags": [{"Key": "route-domain", "Value": "nonprod"}],
    },
    "response": {},
}

nm_delete_vpc_attachment_00000000000000002 = {
    "call": "delete_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000002",
    },
    "response": {},
}

nm_tag_vpc_attachment_00000000000000003_quarantine = {
    "call": "tag_resource",
    "expected_params": {
        "ResourceArn": "arn:aws:networkmanager::333333333333:attachment/attachment-00000000000000003",
        "Tags": [{"Key": "route-domain", "Value": "quarantine"}],
    },
    "response": {},
}

nm_delete_vpc_attachment_00000000000000003 = {
    "call": "delete_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000003",
    },
    "response": {},
}

nm_get_vpc_attachment_00000000000000004_nfg = {
    "call": "get_vpc_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000004",
    },
    "response": {
        "VpcAttachment": {
            "Attachment": {
                "CoreNetworkId": core_network_id,
                "CoreNetworkArn": core_network_arn,
                "AttachmentId": "attachment-00000000000000004",
                "OwnerAccountId": "333333333333",
                "AttachmentType": "VPC",
                "EdgeLocation": "eu-west-1",
                "EdgeLocations": ["eu-west-1"],
                "ResourceArn": "arn:aws:networkmanager::333333333333:attachment/attachment-00000000000000004",
                "NetworkFunctionGroupName": "egress",
                "State": "AVAILABLE",
                "Tags": [
                    {"Key": "route-domain", "Value": "egress"},
                ],
                "CreatedAt": datetime(2015, 1, 1),
                "UpdatedAt": datetime(2015, 1, 1),
                "LastModificationErrors": [],
            },
            "SubnetArns": [
                "arn:aws:ec2:eu-west-1:333333333333:subnet/subnet-0123456789",
                "arn:aws:ec2:eu-west-1:333333333333:subnet/subnet-1234556689a",
            ],
            "Options": {"Ipv6Support": False, "ApplianceModeSupport": True},
        }
    },
}

nm_get_network_routes_route_ok_full_return_supernet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_full_return_subnet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": quarantine_routes_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": quarantine_routes_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_full_return_supernet_00000000000000002_overlapping = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {
        "NetworkRoutes": [
            {
                "DestinationCidrBlock": "string",
                "Destinations": [
                    {
                        "CoreNetworkAttachmentId": "attachment-00000000000000099",
                        "SegmentName": "string",
                        "EdgeLocation": "string",
                        "ResourceType": "vpc",
                        "ResourceId": "string",
                    },
                ],
                "State": "ACTIVE",
                "Type": "PROPAGATED",
            },
        ]
    },
}

nm_get_network_routes_route_ok_full_return_subnet_00000000000000002_overlapping = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {
        "NetworkRoutes": [
            {
                "DestinationCidrBlock": "string",
                "Destinations": [
                    {
                        "CoreNetworkAttachmentId": "attachment-00000000000000099",
                        "SegmentName": "string",
                        "EdgeLocation": "string",
                        "ResourceType": "vpc",
                        "ResourceId": "string",
                    },
                ],
                "State": "ACTIVE",
                "Type": "PROPAGATED",
            },
        ]
    },
}

nm_get_network_routes_route_ok_quarantineroutes_supernet_00000000000000002_overlapping = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": quarantine_routes_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {
        "NetworkRoutes": [
            {
                "DestinationCidrBlock": "string",
                "Destinations": [
                    {
                        "CoreNetworkAttachmentId": "attachment-00000000000000099",
                        "SegmentName": "string",
                        "EdgeLocation": "string",
                        "ResourceType": "vpc",
                        "ResourceId": "string",
                    },
                ],
                "State": "ACTIVE",
                "Type": "PROPAGATED",
            },
        ]
    },
}

nm_get_network_routes_route_ok_quarantineroutes_subnet_00000000000000002_overlapping = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": quarantine_routes_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {
        "NetworkRoutes": [
            {
                "DestinationCidrBlock": "string",
                "Destinations": [
                    {
                        "CoreNetworkAttachmentId": "attachment-00000000000000099",
                        "SegmentName": "string",
                        "EdgeLocation": "string",
                        "ResourceType": "vpc",
                        "ResourceId": "string",
                    },
                ],
                "State": "ACTIVE",
                "Type": "PROPAGATED",
            },
        ]
    },
}

nm_get_vpc_attachment_00000000000000005 = {
    "call": "get_vpc_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000005",
    },
    "response": {
        "VpcAttachment": {
            "Attachment": {
                "CoreNetworkId": core_network_id,
                "CoreNetworkArn": core_network_arn,
                "AttachmentId": "attachment-00000000000000005",
                "OwnerAccountId": "555555555555",
                "AttachmentType": "VPC",
                "EdgeLocation": "eu-west-1",
                "EdgeLocations": ["eu-west-1"],
                "ResourceArn": "arn:aws:networkmanager::555555555555:attachment/attachment-00000000000000005",
                "SegmentName": "nonprod",
                "State": "AVAILABLE",
                "Tags": [{"Key": "route-domain", "Value": "nonprod"}],
                "CreatedAt": datetime(2015, 1, 1),
                "UpdatedAt": datetime(2015, 1, 1),
                "LastModificationErrors": [],
            },
            "SubnetArns": [],
        }
    },
}

nm_get_network_routes_route_ok_full_return_supernet_00000000000000005 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok_5["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_full_return_subnet_00000000000000005 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok_5["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}


nm_get_vpc_attachment_00000000000000002_updating = {
    "call": "get_vpc_attachment",
    "expected_params": {
        "AttachmentId": "attachment-00000000000000002",
    },
    "response": {
        "VpcAttachment": {
            "Attachment": {
                "CoreNetworkId": core_network_id,
                "CoreNetworkArn": core_network_arn,
                "AttachmentId": "attachment-00000000000000002",
                "OwnerAccountId": "222222222222",
                "AttachmentType": "VPC",
                "EdgeLocation": "eu-west-1",
                "EdgeLocations": ["eu-west-1"],
                "ResourceArn": "arn:aws:networkmanager::222222222222:attachment/attachment-00000000000000002",
                "SegmentName": "quarantine",
                "State": "UPDATING",
                "Tags": [],
                "CreatedAt": datetime(2015, 1, 1),
                "UpdatedAt": datetime(2015, 1, 1),
                "LastModificationErrors": [],
            },
            "SubnetArns": [],
        }
    },
}

nm_get_network_routes_route_ok_regional_full_return_supernet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": regional_full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SupernetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}

nm_get_network_routes_route_ok_regional_full_return_subnet_00000000000000002 = {
    "call": "get_network_routes",
    "expected_params": {
        "GlobalNetworkId": global_network_id,
        "RouteTableIdentifier": {
            "CoreNetworkSegmentEdge": {
                "CoreNetworkId": core_network_id,
                "SegmentName": regional_full_return_segment,
                "EdgeLocation": "eu-west-1",
            }
        },
        "SubnetOfMatches": [route_ok["routes"][0]["destinationCidrBlock"]],
        "States": ["ACTIVE"],
        "Types": ["PROPAGATED"],
    },
    "response": {"NetworkRoutes": []},
}
