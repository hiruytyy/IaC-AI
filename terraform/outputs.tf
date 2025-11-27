output "lambda_function_name" {
  value = aws_lambda_function.sg_auditor.function_name
}

output "sns_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
