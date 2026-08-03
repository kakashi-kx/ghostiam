output "lambda_function_name" {
  description = "Name of the GhostIam detector Lambda function"
  value       = aws_lambda_function.ghostiam_detector.function_name
}

output "lambda_function_arn" {
  description = "ARN of the GhostIam detector Lambda function"
  value       = aws_lambda_function.ghostiam_detector.arn
}

output "eventbridge_rule_name" {
  description = "Name of the EventBridge rule capturing ghost activity"
  value       = aws_cloudwatch_event_rule.ghostiam_cloudtrail.name
}

output "detector_role_arn" {
  description = "IAM role ARN for the detector Lambda"
  value       = aws_iam_role.ghostiam_lambda_role.arn
}