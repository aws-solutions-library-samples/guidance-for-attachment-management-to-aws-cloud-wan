import ipaddress
import json
import logging
import re
from typing import Any, Optional

import yaml

# Cloud WAN segment names only contain letters and numbers
SEGMENT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9]+$")

logger = logging.getLogger(__name__)


def _validate_address_map(config: Any) -> None:
    """Validate that *config* matches the ``{segment: {region: [cidr_list]}}`` structure."""
    if not isinstance(config, dict):
        raise ValueError(f"Address map must be a dict, got {type(config).__name__}")
    for segment, regions in config.items():
        if not isinstance(segment, str):
            raise ValueError(f"Segment key must be a string, got {type(segment).__name__}: {segment}")
        if not SEGMENT_NAME_PATTERN.match(segment):
            raise ValueError(f"Segment name '{segment}' must only contain letters and numbers")
        if not isinstance(regions, dict):
            raise ValueError(f"Segment '{segment}' value must be a dict of regions, got {type(regions).__name__}")
        for region, cidrs in regions.items():
            if not isinstance(region, str):
                raise ValueError(f"Region key in segment '{segment}' must be a string, got {type(region).__name__}")
            if not isinstance(cidrs, list):
                raise ValueError(f"CIDRs for {segment}/{region} must be a list, got {type(cidrs).__name__}")
            for cidr in cidrs:
                try:
                    ipaddress.IPv4Network(cidr, strict=False)
                except (ValueError, TypeError) as e:
                    raise ValueError(f"Invalid CIDR '{cidr}' in {segment}/{region}: {e}")


def import_vpc_address_mapping_file(path_file: str) -> Any:
    """Load the YAML VPC-to-segment address mapping from *path_file*.

    Returns the parsed mapping dict.  Returns ``None`` indirectly when the
    caller passes an empty string (i.e. ``SEGMENT_ADDRESSING_FILE`` env var is
    unset) — the caller is responsible for the empty-string guard.
    """
    routing_config = dict()

    with open(path_file, "r") as file:
        routing_config = yaml.safe_load(file)

    _validate_address_map(routing_config)

    return routing_config


def validate_prefix_in_segment(
    route_prefix: str,
    account_tag: Optional[str],
    edge_region: str,
    vpc_address_mapping: Any,
) -> bool:
    """Return ``True`` if *route_prefix* belongs to the expected address space.

    Checks whether the CIDR falls within any allowed prefix for
    *account_tag* / *edge_region* in *vpc_address_mapping*.  Returns ``True``
    (allow) when no address mapping is configured, when *account_tag* has no
    entry in the map (unknown segment — treated as unrestricted), or when
    *route_prefix* is IPv6 (the address plan only covers IPv4).
    """
    if vpc_address_mapping is None:
        return True
    if account_tag not in vpc_address_mapping:
        # No address constraints defined for this segment — allow.
        return True

    ipaddr_prefix = ipaddress.ip_network(route_prefix, strict=False)
    if ipaddr_prefix.version != 4:
        # The address plan only describes IPv4 ranges: IPv6 prefixes (dual-stack VPCs) are not
        # validated here. They are still subject to the conflicting-route check.
        logger.info(
            json.dumps({"event": "SKIP_ADDRESS_PLAN_CHECK", "reason": "IPV6_PREFIX", "route_prefix": route_prefix})
        )
        return True

    if edge_region in vpc_address_mapping[account_tag]:
        for allowed_prefix in vpc_address_mapping[account_tag][edge_region]:
            ipaddr_allowed = ipaddress.IPv4Network(allowed_prefix)
            if ipaddr_prefix.network_address in ipaddr_allowed and ipaddr_prefix.broadcast_address in ipaddr_allowed:
                return True

    return False
