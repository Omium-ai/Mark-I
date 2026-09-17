variable "region" {
  description = "AWS region; the platform estate is single-region."
  type        = string
  default     = "us-east-1"
}

variable "owner" {
  description = "Owning team tag."
  type        = string
  default     = "mark1"
}

variable "eks_cluster_name" {
  description = "Existing EKS cluster the omium-mark1 namespace runs in."
  type        = string
  default     = "omium-prod"
}

variable "namespace" {
  description = "Kubernetes namespace for every Mark 1 workload."
  type        = string
  default     = "omium-mark1"
}

variable "github_release_subjects" {
  description = "GitHub OIDC sub claims allowed to assume the release role: main pushes (ci.yml image build) and edge/v* tags (release.yml). Add ref patterns per workflow; never a bare *."
  type        = list(string)
  default = [
    "repo:Omium-ai/Mark-I:ref:refs/heads/main",
    "repo:Omium-ai/Mark-I:ref:refs/tags/edge/v*",
  ]
}

variable "ecr_max_image_count" {
  description = "Images kept per Mark 1 ECR repository; older ones expire."
  type        = number
  default     = 20
}

variable "clickhouse_host" {
  description = "In-cluster ClickHouse service DNS seeded into the mark1-clickhouse secret (native port 9000)."
  type        = string
  default     = "clickhouse.omium-mark1.svc.cluster.local"
}
