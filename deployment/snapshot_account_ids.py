#!/usr/bin/env python3
"""Mask AWS account IDs in Terraform plan snapshots.

`tofu plan` resolves ``data.aws_caller_identity`` with the credentials in use,
so plan snapshots would contain the account ID of whoever generated them. This
public repository must never contain real account IDs.

* Imported by the snapshot tests (``mask_account_ids``): the plan is masked
  before it is compared with, or written to, the snapshot files.
* Run by pre-commit (``--check``): fails when a snapshot still contains an
  account ID that is not a mock.
* Run by hand without ``--check``: masks the given files in place.

Mock account IDs (``000000000000``, ``111111111111``, … and ``123456789012``)
are kept; any other 12-digit number is replaced by ``111111111111``.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any, List

ACCOUNT_ID_PATTERN = re.compile(r"(?<![0-9])[0-9]{12}(?![0-9])")
MASK = "111111111111"
MOCK_ACCOUNT_IDS = {str(digit) * 12 for digit in range(10)} | {"123456789012"}


def _mask_string(value: str) -> str:
    return ACCOUNT_ID_PATTERN.sub(lambda m: m.group(0) if m.group(0) in MOCK_ACCOUNT_IDS else MASK, value)


def mask_account_ids(value: Any) -> Any:
    """Return a copy of a JSON value with every non-mock account ID masked."""
    if isinstance(value, dict):
        return {mask_account_ids(k): mask_account_ids(v) for k, v in value.items()}
    if isinstance(value, list):
        return [mask_account_ids(v) for v in value]
    if isinstance(value, str):
        return _mask_string(value)
    return value


def find_account_ids(text: str) -> List[str]:
    """Return the non-mock account IDs found in *text*."""
    return sorted({m for m in ACCOUNT_ID_PATTERN.findall(text) if m not in MOCK_ACCOUNT_IDS})


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="only report files with unmasked account IDs")
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args(argv)

    status = 0
    for path in args.files:
        text = path.read_text(encoding="utf-8")
        found = find_account_ids(text)
        if not found:
            continue
        if args.check:
            print(f"{path}: unmasked AWS account IDs found: {', '.join(found)}")
            status = 1
        else:
            masked = mask_account_ids(json.loads(text))
            path.write_text(json.dumps(masked, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            print(f"{path}: masked {len(found)} account ID(s)")
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
