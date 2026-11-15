# ─────────────────────────────────────────────────────────────────────────────
# Data sources — AWS account context
# ─────────────────────────────────────────────────────────────────────────────

# Resolve the current AWS account ID.
# Used to scope IAM policy principals so that publish/subscribe access is
# restricted to identities within this account only.
data "aws_caller_identity" "current" {}

# Resolve the current AWS region.
# Exposed via the region_name output for consumption by calling modules.
# Uses the .region attribute (provider v6+; .name was deprecated in v6).
data "aws_region" "current" { region = var.region }
