terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# Gerçek AWS S3 Bucket'ı ve PCI-DSS 3.4 (KMS) Uyumluluğu
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
