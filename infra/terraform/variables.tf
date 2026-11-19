variable "region" {
  description = "Region for the lab. us-east-1 is recommended: CloudTrail records IAM (global) events there."
  type        = string
  default     = "us-east-1"
}

variable "name_prefix" {
  description = "Prefix for every lab resource name."
  type        = string
  default     = "cloudsoc-lab"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,19}$", var.name_prefix))
    error_message = "Use 3-20 lowercase letters, digits, or hyphens, starting with a letter."
  }
}

variable "log_retention_days" {
  description = "Days before lab CloudTrail logs are deleted from S3 (keeps storage cost near zero)."
  type        = number
  default     = 7

  validation {
    condition     = var.log_retention_days >= 1 && var.log_retention_days <= 90
    error_message = "Keep lab logs between 1 and 90 days."
  }
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition

  trail_name   = "${var.name_prefix}-trail"
  trail_bucket = "${var.name_prefix}-trail-${local.account_id}-${var.region}"
  # Built from parts instead of read from the trail resource: the bucket
  # policy must name the trail before the trail can be created.
  trail_arn = "arn:${local.partition}:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"

  # The role CloudSOC reads with, and the role the failed-call scenario uses.
  # Both trust only principals in this account (who also need sts:AssumeRole).
  account_root = "arn:${local.partition}:iam::${local.account_id}:root"
}
