data "aws_caller_identity" "current" {}

data "terraform_remote_state" "platform" {
  backend = "s3"
  config = {
    bucket  = "omium-tfstate-169805602430"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    profile = "omium-mgmt"
  }
}

data "aws_eks_cluster" "prod" {
  name = var.eks_cluster_name
}

data "aws_iam_openid_connect_provider" "eks" {
  url = data.aws_eks_cluster.prod.identity[0].oidc[0].issuer
}

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

data "aws_secretsmanager_secret" "token_signing_key" {
  name = "omium/prod/mark1-token-signing-key"
}

locals {
  account_id = data.aws_caller_identity.current.account_id
  oidc_url   = replace(data.aws_eks_cluster.prod.identity[0].oidc[0].issuer, "https://", "")

  bucket_names = {
    ingest   = "omium-mark1-ingest-prod-${local.account_id}"
    corpus   = "omium-mark1-corpus-prod-${local.account_id}"
    evidence = "omium-mark1-evidence-prod-${local.account_id}"
    witness  = "omium-mark1-witness-prod-${local.account_id}"
  }
  bucket_arns = { for k, v in local.bucket_names : k => "arn:aws:s3:::${v}" }

  personal_alias = "alias/mark1-personal"
  tenant_prefix  = "alias/mark1-tenant-"
}
