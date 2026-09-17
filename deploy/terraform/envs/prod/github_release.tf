data "aws_iam_policy_document" "gha_release_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [data.aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = var.github_release_subjects
    }
  }
}

resource "aws_iam_role" "gha_release" {
  name               = "omium-mark1-gha-release"
  description        = "GitHub Actions (Omium-ai/Mark-I) release role: push omium/mark1-* images to ECR via OIDC"
  assume_role_policy = data.aws_iam_policy_document.gha_release_assume.json

  tags = {
    Service = "ci"
    Purpose = "Mark-I ci.yml and release.yml image push - set as repo variable AWS_RELEASE_ROLE_ARN"
  }
}

data "aws_iam_policy_document" "gha_release" {
  statement {
    sid       = "EcrAuth"
    effect    = "Allow"
    actions   = ["ecr:GetAuthorizationToken"]
    resources = ["*"]
  }
  statement {
    sid    = "EcrPushPullMark1"
    effect = "Allow"
    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:ListImages",
      "ecr:InitiateLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:CompleteLayerUpload",
      "ecr:PutImage",
    ]
    resources = [for r in aws_ecr_repository.mark1 : r.arn]
  }
}

resource "aws_iam_role_policy" "gha_release" {
  name   = "ecr-push-mark1"
  role   = aws_iam_role.gha_release.id
  policy = data.aws_iam_policy_document.gha_release.json
}
