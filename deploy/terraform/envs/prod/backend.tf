terraform {
  backend "s3" {
    bucket         = "omium-tfstate-169805602430"
    key            = "mark1/prod/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "omium-tf-locks"
    kms_key_id     = "arn:aws:kms:us-east-1:169805602430:key/a18f7b9a-a5fd-43bc-9279-a651c7134fc9"
    encrypt        = true
    profile        = "omium-mgmt"
  }
}
