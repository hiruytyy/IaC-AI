variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "alert_email" {
  description = "Email address for security alerts"
  type        = string
}

variable "sns_topic_name" {
  description = "SNS topic name for alerts"
  type        = string
  default     = "sg-auditor-alerts"
}

variable "lambda_function_name" {
  description = "Lambda function name"
  type        = string
  default     = "security-group-auditor"
}

variable "bedrock_model_id" {
  description = "Bedrock model ID for AI analysis"
  type        = string
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
}
