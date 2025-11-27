provider "aws" {
  region = var.aws_region
}

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

resource "aws_iam_role_policy" "sg_auditor_policy" {
  role = aws_iam_role.sg_auditor_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeInstances",
        "ec2:DescribeNetworkInterfaces",
        "rds:DescribeDBInstances",
        "elasticloadbalancing:DescribeLoadBalancers",
        "bedrock:InvokeModel",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "sns:Publish"
      ]
      Resource = "*"
    }]
  })
}

data "archive_file" "lambda_zip" {
  type        = "zip"
  source_file = "${path.module}/../lambda/sg_auditor.py"
  output_path = "${path.module}/../lambda/sg_auditor.zip"
}

resource "aws_lambda_function" "sg_auditor" {
  filename         = data.archive_file.lambda_zip.output_path
  function_name    = "security-group-auditor"
  role            = aws_iam_role.sg_auditor_role.arn
  handler         = "sg_auditor.lambda_handler"
  runtime         = "python3.11"
  timeout         = 300
  memory_size     = 512
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = "sg-auditor-alerts"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "daily_scan" {
  name                = "sg-auditor-daily-scan"
  description         = "Trigger security group audit daily"
  schedule_expression = "cron(0 9 * * ? *)"
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.daily_scan.name
  target_id = "sg-auditor-lambda"
  arn       = aws_lambda_function.sg_auditor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sg_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.daily_scan.arn
}
