"""
Security Group Auditor Lambda Function

Scans all AWS security groups for risky configurations:
- Identifies ports open to 0.0.0.0/0 (internet)
- Finds resources attached to risky security groups
- Uses Amazon Bedrock AI to analyze threats and suggest fixes
- Sends email alerts via SNS for critical findings
"""

import json
import boto3
import os

# Initialize AWS service clients
ec2 = boto3.client('ec2')           # For scanning security groups and instances
bedrock = boto3.client('bedrock-runtime')  # For AI analysis
sns = boto3.client('sns')           # For sending email alerts

# Dictionary of high-risk ports that should never be open to internet
# Key: port number, Value: service name
RISKY_PORTS = {
    22: 'SSH',              # Remote shell access
    3389: 'RDP',            # Windows remote desktop
    3306: 'MySQL',          # MySQL database
    5432: 'PostgreSQL',     # PostgreSQL database
    1433: 'MS SQL',         # Microsoft SQL Server
    27017: 'MongoDB',       # MongoDB database
    6379: 'Redis',          # Redis cache
    9200: 'Elasticsearch',  # Elasticsearch
    11211: 'Memcached'      # Memcached
}

def lambda_handler(event, context):
    """
    Main Lambda handler function
    
    Process:
    1. Scan all security groups in the account
    2. Identify rules with risky port exposure to internet
    3. Find resources using those security groups
    4. Get AI analysis from Bedrock for each finding
    5. Send email alert if issues found
    
    Returns:
        dict: Response with status code and findings in JSON format
    """
    findings = []
    
    # Get all security groups in the current region
    sgs = ec2.describe_security_groups()['SecurityGroups']
    
    # Loop through each security group
    for sg in sgs:
        risky_rules = []
        
        # Check ingress (inbound) rules
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            
            # Check if rule allows traffic from internet (0.0.0.0/0)
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    # Flag if it's a risky port or all ports (-1)
                    if from_port in RISKY_PORTS or from_port == -1:
                        risky_rules.append({
                            'port': from_port,
                            'protocol': rule.get('IpProtocol', 'all'),
                            'source': '0.0.0.0/0'
                        })
        
        # If risky rules found, gather more details
        if risky_rules:
            # Find what resources are using this security group
            resources = get_attached_resources(sg['GroupId'])
            
            # Get AI-powered analysis from Bedrock
            ai_analysis = analyze_with_bedrock(sg, risky_rules, resources)
            
            # Add to findings list
            findings.append({
                'security_group_id': sg['GroupId'],
                'name': sg.get('GroupName'),
                'vpc_id': sg.get('VpcId'),
                'risky_rules': risky_rules,
                'attached_resources': resources,
                'ai_analysis': ai_analysis
            })
    
    # Send email alert if any issues found
    if findings:
        send_alert(findings)
    
    return {'statusCode': 200, 'body': json.dumps(findings)}

def get_attached_resources(sg_id):
    """
    Find all EC2 instances using a specific security group
    
    Args:
        sg_id (str): Security group ID to search for
        
    Returns:
        list: List of resources with type, ID, and state
    """
    resources = []
    
    # Query EC2 instances filtered by security group
    instances = ec2.describe_instances(
        Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}]
    )
    
    # Extract instance details from nested response structure
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            resources.append({
                'type': 'EC2',
                'id': instance['InstanceId'],
                'state': instance['State']['Name']  # running, stopped, etc.
            })
    
    return resources

def analyze_with_bedrock(sg, risky_rules, resources):
    """
    Use Amazon Bedrock AI to analyze security findings
    
    Sends security group details to Claude AI model for:
    - Threat assessment
    - Business impact analysis
    - Remediation recommendations
    - Terraform code generation
    
    Args:
        sg (dict): Security group details
        risky_rules (list): List of risky ingress rules
        resources (list): Resources using this security group
        
    Returns:
        str: AI-generated analysis and recommendations
    """
    try:
        # Construct prompt with security finding details - minimal format
        ports_list = ', '.join([f"port {r['port']}" for r in risky_rules])
        prompt = f"""Review AWS security group {sg['GroupId']} in VPC {sg.get('VpcId')}.

Configuration: {ports_list} accessible from internet (0.0.0.0/0)
Attached resources: {len(resources)}

Provide:
1. Risk (2 sentences)
2. Impact (2 sentences)
3. Fix steps (3-5 points)
4. Terraform example
5. Standards affected"""

        # Call Bedrock with model from environment variable
        model_id = os.environ.get('BEDROCK_MODEL_ID', 'amazon.nova-pro-v1:0')
        
        # Use appropriate API format based on model
        if 'anthropic' in model_id:
            body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}]
            }
        else:  # Amazon Nova models
            body = {
                "system": [{"text": "You are a senior network security engineer with expertise in AWS cloud security and compliance. Follow industry best practices and provide actionable recommendations."}],
                "messages": [{"role": "user", "content": [{"text": prompt}]}],
                "inferenceConfig": {"max_new_tokens": 1000}
            }
        
        # Log the payload for debugging
        print(f"Bedrock Model: {model_id}")
        print(f"Payload: {json.dumps(body, indent=2)}")
        
        response = bedrock.invoke_model(
            modelId=model_id,
            body=json.dumps(body)
        )
        
        # Parse response based on model
        result = json.loads(response['body'].read())
        if 'anthropic' in model_id:
            return result['content'][0]['text']
        else:  # Amazon Nova
            return result['output']['message']['content'][0]['text']
            
    except Exception as e:
        # Return basic analysis if Bedrock is unavailable
        error_msg = str(e)
        basic_analysis = f"""⚠️ AI Analysis unavailable: {error_msg}

MANUAL REVIEW REQUIRED:
- Ports exposed: {', '.join([f"{RISKY_PORTS.get(r['port'], 'Port ' + str(r['port']))}" for r in risky_rules])}
- Source: Internet (0.0.0.0/0)
- Risk: High - Exposed to brute-force attacks and unauthorized access

RECOMMENDED ACTIONS:
1. Restrict access to specific IP ranges only
2. Use VPN or bastion host for remote access
3. Enable MFA and strong authentication
4. Monitor access logs for suspicious activity
5. Consider using AWS Systems Manager Session Manager instead of direct SSH/RDP

COMPLIANCE: May violate CIS AWS Foundations, NIST, PCI DSS, HIPAA, GDPR"""
        return basic_analysis

def send_alert(findings):
    """
    Send email alert via SNS with summary of findings
    
    Creates a formatted message with top 5 findings and
    publishes to SNS topic (configured in environment variable)
    
    Args:
        findings (list): List of security group findings
    """
    # Build email message with summary
    message = f"🚨 SECURITY ALERT: {len(findings)} Vulnerable Security Group(s) Detected\n"
    message += "=" * 70 + "\n\n"
    
    # Include details for first 5 findings (avoid email size limits)
    for i, f in enumerate(findings[:5], 1):
        message += f"[{i}] Security Group: {f['name']} ({f['security_group_id']})\n"
        message += f"    VPC: {f['vpc_id']}\n"
        message += f"    Attached Resources: {len(f['attached_resources'])} resource(s)\n"
        
        # List risky rules with details
        message += f"    Risky Rules ({len(f['risky_rules'])}):\n"
        for rule in f['risky_rules']:
            port_name = RISKY_PORTS.get(rule['port'], f"Port {rule['port']}")
            message += f"      - {port_name} ({rule['protocol']}/{rule['port']}) open to {rule['source']}\n"
        
        # Add AI summary (first 3 lines)
        ai_lines = f['ai_analysis'].split('\n')[:3]
        message += f"\n    AI Analysis:\n"
        for line in ai_lines:
            if line.strip():
                message += f"      {line.strip()}\n"
        
        message += "\n" + "-" * 70 + "\n\n"
    
    if len(findings) > 5:
        message += f"... and {len(findings) - 5} more issue(s)\n\n"
    
    message += "⚠️  ACTION REQUIRED: Review and remediate these security groups immediately.\n"
    message += "Run Lambda function for full details and Terraform remediation code.\n"
    
    # Publish to SNS topic
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],  # From Terraform environment variable
        Subject=f'🚨 URGENT: {len(findings)} Security Group Issue(s) Detected',
        Message=message
    )
