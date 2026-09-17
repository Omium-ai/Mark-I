resource "aws_ecr_repository" "mark1" {
  for_each = toset(["controld", "intel", "adjudicator", "migrate"])

  name                 = "omium/mark1-${each.value}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = false

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Service = "ecr"
    Purpose = "Container image repository for mark1-${each.value} - tags are sha7 only"
  }
}

resource "aws_ecr_lifecycle_policy" "mark1" {
  for_each   = aws_ecr_repository.mark1
  repository = each.value.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Expire untagged images"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 14
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Keep the ${var.ecr_max_image_count} most recent images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = var.ecr_max_image_count
        }
        action = { type = "expire" }
      },
    ]
  })
}
