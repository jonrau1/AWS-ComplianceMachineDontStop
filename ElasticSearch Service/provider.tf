provider "aws" {
  region     = "us-east-1"
}

## Include your Remote State Here

##terraform {
##    backend "s3" {
##      encrypt = true
##      bucket = "my_s3_bucket_name"
##      dynamodb_table = "my_dynamo_table_name"
##      key = "path/path/terraform.tfstate"
##      region = "us-east-1"
##  }
##}