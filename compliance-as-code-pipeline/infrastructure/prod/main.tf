terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  # GERÇEK ALTYAPI: AWS S3 State Backend
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
