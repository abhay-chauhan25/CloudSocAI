# The read-only role CloudSOC uses: CloudTrail logs from the lab bucket, and
# the configuration calls the posture collector makes. Nothing here can
# write, delete, or change anything.

data "aws_iam_policy_document" "trust_account" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
  }
}

resource "aws_iam_role" "reader" {
  name                 = "${var.name_prefix}-reader"
  description          = "CloudSOC read-only access to lab CloudTrail logs and posture configuration"
  assume_role_policy   = data.aws_iam_policy_document.trust_account.json
  max_session_duration = 3600
}

data "aws_iam_policy_document" "log_reader" {
  statement {
    sid       = "ListTrailLogs"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.trail_logs.arn]

    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["AWSLogs/${local.account_id}/CloudTrail/*"]
    }
  }

  statement {
    sid       = "ReadTrailLogs"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/CloudTrail/*"]
  }
}

resource "aws_iam_role_policy" "log_reader" {
  name   = "cloudtrail-log-reader"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.log_reader.json
}

# These actions do not support resource-level restrictions, hence "*".
data "aws_iam_policy_document" "posture_reader" {
  statement {
    sid = "ReadPostureConfiguration"
    actions = [
      "iam:GetAccountSummary",
      "iam:GenerateCredentialReport", # builds the report; changes nothing
      "iam:GetCredentialReport",
      "s3:ListAllMyBuckets",
      "s3:GetAccountPublicAccessBlock",
      "s3:GetBucketPublicAccessBlock",
      "s3:GetBucketPolicyStatus",
      "ec2:DescribeSecurityGroups",
      "cloudtrail:DescribeTrails",
      "cloudtrail:GetTrailStatus",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "posture_reader" {
  name   = "posture-reader"
  role   = aws_iam_role.reader.id
  policy = data.aws_iam_policy_document.posture_reader.json
}
