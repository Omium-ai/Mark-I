variable "role_name" {
  description = "IAM role name (omium-prod-mark1-<service>-irsa)."
  type        = string
}

variable "description" {
  description = "Role description."
  type        = string
}

variable "oidc_provider_arn" {
  description = "EKS cluster OIDC provider ARN."
  type        = string
}

variable "oidc_url" {
  description = "EKS OIDC issuer without the https:// scheme."
  type        = string
}

variable "namespace" {
  description = "Kubernetes namespace of the ServiceAccount."
  type        = string
  default     = "omium-mark1"
}

variable "service_account" {
  description = "Kubernetes ServiceAccount name bound to the role."
  type        = string
}

variable "policy_json" {
  description = "Inline least-privilege policy document (JSON)."
  type        = string
}
