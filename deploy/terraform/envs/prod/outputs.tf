output "bucket_names" {
  description = "Mark 1 S3 bucket names by purpose (values: S3_INGEST_BUCKET, WITNESS_BUCKET, INTEL_CORPUS_ROOT_URI)."
  value       = local.bucket_names
}

output "bucket_arns" {
  description = "Mark 1 S3 bucket ARNs by purpose."
  value       = { for k, v in local.bucket_names : k => "arn:aws:s3:::${v}" }
}

output "kms_personal_key_arn" {
  description = "Pooled personal-tenant KMS key ARN (ADR-0011)."
  value       = aws_kms_key.personal.arn
}

output "kms_personal_alias" {
  description = "Pooled personal-tenant KMS alias (controld KMS_PERSONAL_ALIAS)."
  value       = aws_kms_alias.personal.name
}

output "irsa_role_arns" {
  description = "IRSA role ARNs by service; annotate eks.amazonaws.com/role-arn on the ServiceAccount."
  value       = { for k, m in module.irsa : k => m.role_arn }
}

output "irsa_service_accounts" {
  description = "namespace/serviceaccount each IRSA role trusts."
  value       = { for k, m in module.irsa : k => m.service_account }
}

output "ecr_repository_urls" {
  description = "ECR repository URLs by service."
  value       = { for k, r in aws_ecr_repository.mark1 : k => r.repository_url }
}

output "gha_release_role_arn" {
  description = "GitHub OIDC release role; set as Mark-I repo variable AWS_RELEASE_ROLE_ARN (AWS_REGION=us-east-1)."
  value       = aws_iam_role.gha_release.arn
}

output "secret_arns" {
  description = "Secrets Manager ARNs by logical name (ExternalSecrets reference omium/prod/<name>)."
  value = merge(
    { for k, s in aws_secretsmanager_secret.mark1 : k => s.arn },
    { "mark1-token-signing-key" = data.aws_secretsmanager_secret.token_signing_key.arn },
  )
}

output "platform" {
  description = "Read-only values from the platform prod state used by the Helm values and the migrate Job."
  value = {
    vpc_id                     = data.terraform_remote_state.platform.outputs.vpc_id
    private_subnets            = data.terraform_remote_state.platform.outputs.private_subnets
    rds_endpoint               = data.terraform_remote_state.platform.outputs.rds_endpoint
    rds_master_user_secret_arn = data.terraform_remote_state.platform.outputs.rds_master_user_secret_arn
    eks_cluster_name           = data.aws_eks_cluster.prod.name
    eks_oidc_provider_arn      = data.aws_iam_openid_connect_provider.eks.arn
    github_oidc_provider_arn   = data.aws_iam_openid_connect_provider.github.arn
  }
}
