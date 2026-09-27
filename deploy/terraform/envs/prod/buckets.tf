locals {
  ingest_kms_statements = [
    {
      Sid       = "DenyTenantPrefixWithoutMark1TenantKey"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${local.bucket_arns.ingest}/t/*"
      Condition = {
        StringNotLike = {
          "s3:x-amz-server-side-encryption-aws-kms-key-id" = [
            aws_kms_key.personal.arn,
            "*${local.tenant_prefix}*",
            "*${local.personal_alias}",
          ]
        }
      }
    },
    {
      Sid         = "DenyPooledPersonalKeyOutsideTenantPrefix"
      Effect      = "Deny"
      Principal   = "*"
      Action      = "s3:PutObject"
      NotResource = "${local.bucket_arns.ingest}/t/*"
      Condition = {
        StringLike = {
          "s3:x-amz-server-side-encryption-aws-kms-key-id" = [
            aws_kms_key.personal.arn,
            "*${local.personal_alias}",
          ]
        }
      }
    },
  ]
}

module "ingest" {
  source = "../../modules/mark1-bucket"

  name              = local.bucket_names.ingest
  purpose           = "M1P ingest landing and replay log plus quarantine - the ack gate for every device batch"
  kms_key_arn       = aws_kms_key.personal.arn
  object_lock       = { mode = "GOVERNANCE", days = 35 }
  policy_statements = local.ingest_kms_statements
}

module "corpus" {
  source = "../../modules/mark1-bucket"

  name        = local.bucket_names.corpus
  purpose     = "Parquet mirrors and KTO JSONL manifest export pairs per tenant"
  kms_key_arn = aws_kms_key.personal.arn
}

module "evidence" {
  source = "../../modules/mark1-bucket"

  name        = local.bucket_names.evidence
  purpose     = "Opt-in E1 E2 evidence blobs per tenant - 90 day hard ceiling"
  kms_key_arn = aws_kms_key.personal.arn
}

module "witness" {
  source = "../../modules/mark1-bucket"

  name        = local.bucket_names.witness
  purpose     = "Hourly receipt-chain heads per tenant - COMPLIANCE-locked never deleted"
  kms_key_arn = aws_kms_key.personal.arn
  object_lock = { mode = "COMPLIANCE", years = 2 }
}

resource "aws_s3_bucket_lifecycle_configuration" "ingest" {
  bucket = module.ingest.id

  rule {
    id     = "replay-log-tiering"
    status = "Enabled"
    filter {}
    transition {
      days          = 90
      storage_class = "GLACIER_IR"
    }
    expiration {
      days = 760
    }
    noncurrent_version_expiration {
      noncurrent_days = 40
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "quarantine-backstop"
    status = "Enabled"
    filter {
      tag {
        key   = "class"
        value = "quarantine"
      }
    }
    expiration {
      days = 32
    }
  }

  rule {
    id     = "contribution-ttl"
    status = "Enabled"
    filter {
      tag {
        key   = "class"
        value = "contribution"
      }
    }
    expiration {
      days = 365
    }
  }

  rule {
    id     = "evidence-ttl"
    status = "Enabled"
    filter {
      tag {
        key   = "class"
        value = "evidence"
      }
    }
    expiration {
      days = 32
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "corpus" {
  bucket = module.corpus.id

  rule {
    id     = "corpus-default-ttl"
    status = "Enabled"
    filter {}
    expiration {
      days = 400
    }
    noncurrent_version_expiration {
      noncurrent_days = 30
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "evidence" {
  bucket = module.evidence.id

  rule {
    id     = "evidence-hard-ceiling"
    status = "Enabled"
    filter {}
    expiration {
      days = 90
    }
    noncurrent_version_expiration {
      noncurrent_days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "witness" {
  bucket = module.witness.id

  rule {
    id     = "abort-stale-multipart"
    status = "Enabled"
    filter {}
    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}
