# Security Group Auditor

AI-powered AWS security group auditor using Amazon Bedrock.

## Features
- Scans all security groups for risky configurations
- Identifies open ports to 0.0.0.0/0
- Maps resources using each security group
- AI-generated threat analysis and remediation steps
- Daily automated scans via EventBridge
- Email alerts for critical findings

## Setup

1. **Deploy infrastructure:**
```bash
cd terraform
terraform init
terraform apply -var="alert_email=your@email.com"
```

2. **Confirm SNS subscription** in your email

3. **Manual test:**
```bash
aws lambda invoke --function-name security-group-auditor output.json
cat output.json
```

## What it checks
- SSH (22), RDP (3389), MySQL (3306), PostgreSQL (5432)
- MongoDB (27017), Redis (6379), Elasticsearch (9200)
- MS SQL (1433), Memcached (11211)
- Any port open to 0.0.0.0/0

## Output
- JSON report with findings
- AI analysis via Bedrock Claude
- Email alerts for critical issues
- Terraform remediation code
