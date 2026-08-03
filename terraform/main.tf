terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# IAM role for the detection Lambda
resource "aws_iam_role" "ghostiam_lambda_role" {
  name = "ghostiam-detector-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
  tags = { GhostIam = "true" }
}

# IAM policy: allow Lambda to write CloudWatch logs
resource "aws_iam_role_policy" "ghostiam_lambda_logs" {
  name = "ghostiam-lambda-logs"
  role = aws_iam_role.ghostiam_lambda_role.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "arn:aws:logs:*:*:*"
    }]
  })
}

# Lambda function
resource "aws_lambda_function" "ghostiam_detector" {
  filename         = var.lambda_zip_path
  function_name    = "ghostiam-detector"
  role             = aws_iam_role.ghostiam_lambda_role.arn
  handler          = "main"
  runtime          = "provided.al2023"
  source_code_hash = filebase64sha256(var.lambda_zip_path)
  timeout          = 10
  memory_size      = 128

  environment {
    variables = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  tags = { GhostIam = "true" }
}

# EventBridge rule: capture any CloudTrail event
resource "aws_cloudwatch_event_rule" "ghostiam_cloudtrail" {
  name        = "ghostiam-capture-ghost-activity"
  description = "Captures CloudTrail events where a ghost IAM user performs any API call"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        sessionContext = {
          sessionIssuer = {
            userName = [{ "prefix" : "ghost-" }]
          }
        }
      }
    }
  })

  tags = { GhostIam = "true" }
}

# Lambda permission: allow EventBridge to invoke
resource "aws_lambda_permission" "ghostiam_eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ghostiam_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.ghostiam_cloudtrail.arn
}

# EventBridge target: the Lambda
resource "aws_cloudwatch_event_target" "ghostiam_lambda_target" {
  rule      = aws_cloudwatch_event_rule.ghostiam_cloudtrail.name
  target_id = "ghostiam-detector"
  arn       = aws_lambda_function.ghostiam_detector.arn
}