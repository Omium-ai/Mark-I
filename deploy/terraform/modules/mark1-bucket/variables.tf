variable "name" {
  description = "Full bucket name (omium-mark1-<purpose>-<env>-<account>)."
  type        = string
}

variable "purpose" {
  description = "One-line purpose for the bucket tag."
  type        = string
}

variable "kms_key_arn" {
  description = "KMS key ARN for default SSE-KMS (S3 Bucket Keys on)."
  type        = string
}

variable "object_lock" {
  description = "Default object-lock retention; null = no object lock. Creation-time only: a bucket created without it cannot be retrofitted."
  type = object({
    mode  = string
    days  = optional(number)
    years = optional(number)
  })
  default = null
}

variable "policy_statements" {
  description = "Extra bucket-policy statements appended after DenyInsecureTransport."
  type        = any
  default     = []
}

variable "tags" {
  description = "Extra tags."
  type        = map(string)
  default     = {}
}
