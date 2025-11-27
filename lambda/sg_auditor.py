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
    Use Amazon Bedrock AI with 3 separate API calls for remediation options
    """
    try:
        ports_list = ', '.join([f"{RISKY_PORTS.get(r['port'], 'port ' + str(r['port']))}" for r in risky_rules])
        model_id = os.environ.get('BEDROCK_MODEL_ID', 'amazon.nova-lite-v1:0')
        
        # Call 1: AWS Console Steps with confidence
        console_prompt = f"""Security Group {sg['GroupId']} has {ports_list} from 0.0.0.0/0

Provide AWS Console fix steps and rate your confidence:
1. Step-by-step console instructions
2. Exact menu paths and clicks
3. At the end, provide: "Confidence Score: X/100" where X is how confident you are in this solution"""

        console_body = {"messages": [{"role": "user", "content": [{"text": console_prompt}]}], "inferenceConfig": {"max_new_tokens": 800}}
        console_response = bedrock.invoke_model(modelId=model_id, body=json.dumps(console_body))
        console_steps = json.loads(console_response['body'].read())['output']['message']['content'][0]['text']
        
        # Call 2: AWS CLI Commands with confidence
        cli_prompt = f"""Security Group {sg['GroupId']} has {ports_list} from 0.0.0.0/0

Provide AWS CLI commands and rate your confidence:
1. Exact commands to revoke risky rules
2. Commands to add restricted rules
3. At the end, provide: "Confidence Score: X/100" where X is how confident you are in this solution"""

        cli_body = {"messages": [{"role": "user", "content": [{"text": cli_prompt}]}], "inferenceConfig": {"max_new_tokens": 800}}
        cli_response = bedrock.invoke_model(modelId=model_id, body=json.dumps(cli_body))
        cli_steps = json.loads(cli_response['body'].read())['output']['message']['content'][0]['text']
        
        # Call 3: Amazon Q Developer with confidence
        q_prompt = f"""Security Group {sg['GroupId']} has {ports_list} from 0.0.0.0/0

Provide Amazon Q Developer guidance and rate your confidence:
1. How to use Q Developer to fix this
2. What prompts to give Q Developer
3. At the end, provide: "Confidence Score: X/100" where X is how confident you are in this solution"""

        q_body = {"messages": [{"role": "user", "content": [{"text": q_prompt}]}], "inferenceConfig": {"max_new_tokens": 800}}
        q_response = bedrock.invoke_model(modelId=model_id, body=json.dumps(q_body))
        q_steps = json.loads(q_response['body'].read())['output']['message']['content'][0]['text']
        
        # Calculate overall severity
        severity = "CRITICAL" if len(resources) > 0 else "HIGH"
        
        return f"""
╔══════════════════════════════════════════════════════════════════════╗
║ SEVERITY: {severity}                                                  
║ Security Group: {sg['GroupId']} ({sg.get('GroupName')})
║ Issue: {ports_list} exposed to internet (0.0.0.0/0)
║ Attached Resources: {len(resources)}
║ Compliance: Violates CIS AWS Foundations, NIST SP 800-53, PCI DSS
╚══════════════════════════════════════════════════════════════════════╝


╔══════════════════════════════════════════════════════════════════════╗
║ FIX OPTION 1: AWS CONSOLE                                            ║
╚══════════════════════════════════════════════════════════════════════╝

{console_steps}


╔══════════════════════════════════════════════════════════════════════╗
║ FIX OPTION 2: AWS CLI                                                ║
╚══════════════════════════════════════════════════════════════════════╝

{cli_steps}


╔══════════════════════════════════════════════════════════════════════╗
║ FIX OPTION 3: AMAZON Q DEVELOPER                                     ║
╚══════════════════════════════════════════════════════════════════════╝

{q_steps}
"""
            
    except Exception as e:
        return f"⚠️ AI Analysis unavailable: {str(e)}"

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
        
        # Add complete AI analysis
        ai_lines = f['ai_analysis'].split('\n')
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
