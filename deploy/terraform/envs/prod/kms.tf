data "aws_iam_policy_document" "personal_key" {
  statement {
    sid       = "EnableIAMPolicies"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${local.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "personal" {
  description             = "Mark 1 pooled SSE-KMS key for kind='personal' tenants (ADR-0011); org tenants get per-tenant keys at enrollment"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.personal_key.json

  tags = {
    Name    = "mark1-personal"
    Service = "mark1-tenant-key"
    Purpose = "Pooled data key for personal tenants in the four Mark 1 buckets"
  }
}

resource "aws_kms_alias" "personal" {
  name          = local.personal_alias
  target_key_id = aws_kms_key.personal.key_id
}
