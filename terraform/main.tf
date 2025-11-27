# Configure AWS provider with region from variables
provider "aws" {
  region = var.aws_region
}

# IAM role that Lambda function will assume
# Allows Lambda service to execute the function
resource "aws_iam_role" "sg_auditor_role" {
  name = "sg-auditor-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
    }]
  })
}

# IAM policy attached to Lambda role
# Grants permissions to scan AWS resources and invoke Bedrock
resource "aws_iam_role_policy" "sg_auditor_policy" {
  role = aws_iam_role.sg_auditor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        # EC2 permissions to read security groups and instances
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        # RDS and ELB permissions to find attached resources
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        # Bedrock permission for AI analysis
        "bedrock:InvokeModel",
        # CloudWatch Logs permissions for Lambda logging
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        # SNS permission to send email alerts
        "sns:Publish"
      ]
      Resource = "*"
    }]
  })
}

# Package Lambda function code into a zip file
# Terraform will automatically zip the Python file for deployment
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/sg_auditor.py"
  output_path = "${path.module}/../lambda/sg_auditor.zip"
}

# Lambda function that performs security group auditing
# Runs daily via EventBridge and sends findings to SNS
resource "aws_lambda_function" "sg_auditor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = var.lambda_function_name
  role            = aws_iam_role.sg_auditor_role.arn
  handler         = "sg_auditor.lambda_handler"  # Python function entry point
  runtime         = "python3.11"
  timeout         = 300      # 5 minutes - enough time to scan large accounts
  memory_size     = 512      # 512MB - sufficient for API calls and Bedrock
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      # Pass SNS topic ARN to Lambda for sending alerts
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      BEDROCK_MODEL_ID = var.bedrock_model_id
    }
  }
}

# SNS topic for sending security alert emails
resource "aws_sns_topic" "alerts" {
  name = var.sns_topic_name
}

# Email subscription to SNS topic
# User will receive confirmation email after deployment
resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# EventBridge rule to trigger Lambda daily at 9 AM UTC
# Cron format: minute hour day month day-of-week year
resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "sg-auditor-daily-scan"
  description         = "Trigger security group audit daily"
  schedule_expression = "cron(0 9 * * ? *)"  # 9 AM UTC every day
}

# Connect EventBridge rule to Lambda function
# This makes Lambda the target of the scheduled event
resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "sg-auditor-lambda"
  arn       = aws_lambda_function.sg_auditor.arn
}

# Grant EventBridge permission to invoke Lambda
# Without this, EventBridge cannot trigger the function
resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
