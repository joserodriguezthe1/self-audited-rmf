terraform {
  required_version = ">= 1.10"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0, < 7.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # State lives in the evidence bucket (Object Lock, KMS, versioned), so every
  # state version is itself retained change evidence (CM-3). Values come from
  # backend.hcl, which scripts/discover.py writes. Native S3 locking, no DynamoDB.
  backend "s3" {}
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project  = "self-audited-rmf"
      Boundary = "sas"
    }
  }
}
