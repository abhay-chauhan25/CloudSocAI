# Logging foundation: a multi-region CloudTrail trail delivering to a
# private, encrypted S3 bucket that only CloudTrail can write to.

resource "aws_s3_bucket" "trail_logs" {
  bucket = local.trail_bucket

  # Lab only: lets `terraform destroy` delete the bucket even though it holds
  # logs. A production log bucket would do the opposite (versioning, object
  # lock, and a deny on deletes) because attackers delete logs.
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

# ACLs disabled: the bucket owner owns every object, and access is decided by
# policies alone.
resource "aws_s3_bucket_ownership_controls" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

# SSE-S3 rather than a customer-managed KMS key: free, and enough for a lab.
# A KMS key adds access control over decryption but costs $1/month plus
# requests, and the reader role would need kms:Decrypt.
resource "aws_s3_bucket_server_side_encryption_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id

  rule {
    id     = "expire-lab-logs"
    status = "Enabled"

    filter {}

    expiration {
      days = var.log_retention_days
    }
  }
}

data "aws_iam_policy_document" "trail_logs" {
  # CloudTrail checks the bucket ACL before delivering, then writes objects.
  # aws:SourceArn limits both to this trail, so another account's trail
  # cannot use the bucket (the "confused deputy" problem).
  statement {
    sid       = "AWSCloudTrailAclCheck"
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.trail_logs.arn]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid       = "AWSCloudTrailWrite"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.trail_logs.arn}/AWSLogs/${local.account_id}/*"]

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.trail_logs.arn, "${aws_s3_bucket.trail_logs.arn}/*"]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "trail_logs" {
  bucket = aws_s3_bucket.trail_logs.id
  policy = data.aws_iam_policy_document.trail_logs.json

  # S3 rejects policy and public-access-block changes made at the same time,
  # so apply them one after the other.
  depends_on = [aws_s3_bucket_public_access_block.trail_logs]
}

resource "aws_cloudtrail" "lab" {
  name           = local.trail_name
  s3_bucket_name = aws_s3_bucket.trail_logs.id

  # Management events (all read and write API calls) from every region,
  # including global services such as IAM. Data events (S3 object reads,
  # Lambda invocations) are off: they are high-volume and billed.
  is_multi_region_trail         = true
  include_global_service_events = true

  # Hourly signed digest files make tampering with delivered logs detectable.
  enable_log_file_validation = true

  depends_on = [aws_s3_bucket_policy.trail_logs]
}
