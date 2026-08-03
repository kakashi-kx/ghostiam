variable "region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for ghost user alerts"
  type        = string
  sensitive   = true
}

variable "lambda_zip_path" {
  description = "Path to the Lambda deployment zip file"
  type        = string
  default     = "../build/ghostiam-detector.zip"
}