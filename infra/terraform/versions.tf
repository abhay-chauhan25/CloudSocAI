# Pinned versions: the CLI within 1.17, the AWS provider exactly. The
# provider's checksums are recorded in .terraform.lock.hcl (committed), so
# every `terraform init` installs the same, verified build.
terraform {
  required_version = "~> 1.17.1"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.72.0"
    }
  }

  # State stays local (gitignored): this lab has one operator and is torn
  # down the same day. A team would keep state in S3 with locking instead.
}

provider "aws" {
  region = var.region

  # Every resource is tagged, so lab resources are easy to find, and the
  # scenario runner can refuse to touch anything that is not part of the lab.
  default_tags {
    tags = {
      Project   = "cloudsoc-lab"
      ManagedBy = "terraform"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
