data "aws_iam_policy_document" "assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [var.oidc_provider_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_url}:sub"
      values   = ["system:serviceaccount:${var.namespace}:${var.service_account}"]
    }
    condition {
      test     = "StringEquals"
      variable = "${var.oidc_url}:aud"
      values   = ["sts.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "this" {
  name               = var.role_name
  description        = var.description
  assume_role_policy = data.aws_iam_policy_document.assume.json

  tags = {
    Service        = "mark1"
    ServiceAccount = "${var.namespace}/${var.service_account}"
  }
}

resource "aws_iam_role_policy" "this" {
  name   = "mark1-least-privilege"
  role   = aws_iam_role.this.id
  policy = var.policy_json
}
