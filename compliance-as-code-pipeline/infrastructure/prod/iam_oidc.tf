# 1. Trust Policy: Sadece bu repo ve sadece 'main' branch bu rolü alabilir.
data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      # CRITICAL: Spoofing ve yetki asimi onlemi. 
      # Baska repo veya branch bu rolu kullanamaz!
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:egekarabey35/compliance-as-code-pipeline:ref:refs/heads/main"]
    }
  }
}

resource "aws_iam_role" "github_actions_compliance_role" {
  name               = "GitHubActionsComplianceRole"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json
}

# 2. Permission Scope (Least Privilege): Sadece Plan yetkisi
data "aws_iam_policy_document" "compliance_read_only" {
  # AWS uzerindeki kaynaklari sadece okuyabilir (Apply/Write YASAK)
  statement {
    actions   = ["s3:Get*", "s3:List*", "ec2:Describe*"]
    resources = ["*"]
  }
  
  # Terraform State okuma yetkisi
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      "arn:aws:s3:::fintech-tf-state-prod", 
      "arn:aws:s3:::fintech-tf-state-prod/*"
    ]
  }
  
  # Terraform Lock yetkisi (Plan calisirken lock atmak icin DynamoDB Put/Delete sarttir)
  statement {
    actions   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
    resources = ["arn:aws:dynamodb:us-east-1:123456789012:table/terraform-locks"]
  }
}

resource "aws_iam_role_policy" "compliance_read_only_policy" {
  name   = "ComplianceReadOnlyPolicy"
  role   = aws_iam_role.github_actions_compliance_role.id
  policy = data.aws_iam_policy_document.compliance_read_only.json
}
