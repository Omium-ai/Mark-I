locals {
  kms_via_s3 = {
    sid      = "PooledKeyViaS3"
    actions  = ["kms:Encrypt", "kms:Decrypt", "kms:GenerateDataKey*", "kms:DescribeKey"]
    resource = aws_kms_key.personal.arn
  }
}

data "aws_iam_policy_document" "controld" {
  statement {
    sid       = "IngestLandingWrite"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectTagging"]
    resources = ["${local.bucket_arns.ingest}/t/*"]
  }
  statement {
    sid       = "IngestLandingRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arns.ingest}/t/*"]
  }
  statement {
    sid       = "IngestBucketProbe"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketPolicy"]
    resources = [local.bucket_arns.ingest]
  }
  statement {
    sid       = "QuarantineSweep"
    effect    = "Allow"
    actions   = ["s3:DeleteObject"]
    resources = ["${local.bucket_arns.ingest}/t/*/quarantine/*"]
  }
  statement {
    sid       = "WitnessAppend"
    effect    = "Allow"
    actions   = ["s3:PutObject", "s3:PutObjectRetention"]
    resources = ["${local.bucket_arns.witness}/witness/heads/*"]
  }
  statement {
    sid       = local.kms_via_s3.sid
    effect    = "Allow"
    actions   = local.kms_via_s3.actions
    resources = [local.kms_via_s3.resource]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "intel" {
  statement {
    sid       = "CorpusReadWrite"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:PutObject", "s3:AbortMultipartUpload"]
    resources = ["${local.bucket_arns.corpus}/t/*"]
  }
  statement {
    sid       = "CorpusList"
    effect    = "Allow"
    actions   = ["s3:ListBucket", "s3:GetBucketLocation"]
    resources = [local.bucket_arns.corpus]
  }
  statement {
    sid       = "ReplayRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arns.ingest}/t/*"]
  }
  statement {
    sid       = "ReplayList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arns.ingest]
  }
  statement {
    sid       = local.kms_via_s3.sid
    effect    = "Allow"
    actions   = local.kms_via_s3.actions
    resources = [local.kms_via_s3.resource]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

data "aws_iam_policy_document" "adjudicator" {
  statement {
    sid       = "EvidenceRead"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${local.bucket_arns.evidence}/t/*"]
  }
  statement {
    sid       = "EvidenceList"
    effect    = "Allow"
    actions   = ["s3:ListBucket"]
    resources = [local.bucket_arns.evidence]
  }
  statement {
    sid       = local.kms_via_s3.sid
    effect    = "Allow"
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = [local.kms_via_s3.resource]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${var.region}.amazonaws.com"]
    }
  }
}

locals {
  irsa = {
    controld = {
      service_account = "controld"
      description     = "IRSA: controld -> ingest landing/quarantine sweep, witness heads, pooled KMS via S3"
      policy_json     = data.aws_iam_policy_document.controld.json
    }
    intel = {
      service_account = "intel"
      description     = "IRSA: mark1-intel -> corpus read/write, replay read on the ingest log, pooled KMS via S3"
      policy_json     = data.aws_iam_policy_document.intel.json
    }
    adjudicator = {
      service_account = "adjudicator"
      description     = "IRSA: adjudicator -> evidence read-only, pooled KMS decrypt via S3"
      policy_json     = data.aws_iam_policy_document.adjudicator.json
    }
  }
}

module "irsa" {
  source   = "../../modules/mark1-irsa"
  for_each = local.irsa

  role_name         = "omium-prod-mark1-${each.key}-irsa"
  description       = each.value.description
  oidc_provider_arn = data.aws_iam_openid_connect_provider.eks.arn
  oidc_url          = local.oidc_url
  namespace         = var.namespace
  service_account   = each.value.service_account
  policy_json       = each.value.policy_json
}
