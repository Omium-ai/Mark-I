output "role_arn" {
  value = aws_iam_role.this.arn
}

output "service_account" {
  value = "${var.namespace}/${var.service_account}"
}
