provider "aws" {
  region  = var.region
  profile = "omium-prod"

  default_tags {
    tags = {
      Project     = "omium"
      Component   = "mark1"
      Environment = "prod"
      ManagedBy   = "terraform"
      Repo        = "omium-mark1/deploy/terraform"
      Owner       = var.owner
    }
  }
}
