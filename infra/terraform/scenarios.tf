# Targets for the detection and posture scenarios. Each is deliberately
# insecure in a way CloudSOC should notice, and harmless in this lab:
# nothing runs behind the open security group, the unblocked bucket has no
# public policy, and the denied role has no permissions at all.

# A role with no policies: every call made with it is denied. The
# failed-call scenario assumes it and makes a burst of calls.
resource "aws_iam_role" "denied" {
  name                 = "${var.name_prefix}-denied"
  description          = "No permissions; used to generate AccessDenied events for CloudSOC"
  assume_role_policy   = data.aws_iam_policy_document.trust_account.json
  max_session_duration = 3600
}

# A VPC with no internet gateway and no instances: the open security group
# below is a configuration finding, not a real exposure.
resource "aws_vpc" "lab" {
  cidr_block = "10.42.0.0/16"

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

resource "aws_security_group" "open_ssh" {
  name        = "${var.name_prefix}-open-ssh"
  description = "Deliberately insecure: SSH from anywhere (CloudSOC posture check target)"
  vpc_id      = aws_vpc.lab.id
}

resource "aws_vpc_security_group_ingress_rule" "ssh_from_anywhere" {
  security_group_id = aws_security_group.open_ssh.id
  description       = "SSH from the whole internet"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
  cidr_ipv4         = "0.0.0.0/0"
}

# A bucket with Block Public Access switched off and no policy: nothing in it
# is public, but nothing stops it becoming public. CloudSOC flags it only if
# the account-level Block Public Access is also off, because the account
# setting overrides the bucket's.
resource "aws_s3_bucket" "unblocked" {
  bucket        = "${var.name_prefix}-unblocked-${local.account_id}-${var.region}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "unblocked" {
  bucket = aws_s3_bucket.unblocked.id

  block_public_acls       = false
  ignore_public_acls      = false
  block_public_policy     = false
  restrict_public_buckets = false
}
