terraform {
  required_version = ">= 1.5.0"
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "exchange_bucket" {
  type    = string
  default = "ix-exchange-audit-trail"
}

output "exchange_region" {
  value = var.aws_region
}

output "exchange_bucket" {
  value = var.exchange_bucket
}
