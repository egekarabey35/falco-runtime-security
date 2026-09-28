terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  backend "s3" {
    bucket         = "fintech-tf-state-prod"
    key            = "compliance/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "terraform-locks"
    encrypt        = true
  }
}
provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "prod_data" {
  bucket = "my-fintech-prod-data"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "prod_data_encryption" {
  bucket = aws_s3_bucket.prod_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = "arn:aws:kms:us-east-1:123456789012:key/alias/my-key"
    }
  }
}

# CRITICAL FIX: Block Public Access for Financial Data Bucket
resource "aws_s3_bucket_public_access_block" "prod_data_public_access_block" {
  bucket                  = aws_s3_bucket.prod_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
