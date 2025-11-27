import json
import boto3
import os

ec2 = boto3.client('ec2')
bedrock = boto3.client('bedrock-runtime')
sns = boto3.client('sns')

RISKY_PORTS = {
    22: 'SSH', 3389: 'RDP', 3306: 'MySQL', 5432: 'PostgreSQL',
    1433: 'MS SQL', 27017: 'MongoDB', 6379: 'Redis', 
    9200: 'Elasticsearch', 11211: 'Memcached'
}

def lambda_handler(event, context):
    findings = []
    
    sgs = ec2.describe_security_groups()['SecurityGroups']
    
    for sg in sgs:
        risky_rules = []
        
        for rule in sg.get('IpPermissions', []):
            from_port = rule.get('FromPort', 0)
            to_port = rule.get('ToPort', 65535)
            
            for ip_range in rule.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    if from_port in RISKY_PORTS or from_port == -1:
                        risky_rules.append({
                            'port': from_port,
                            'protocol': rule.get('IpProtocol', 'all'),
                            'source': '0.0.0.0/0'
                        })
        
        if risky_rules:
            resources = get_attached_resources(sg['GroupId'])
            ai_analysis = analyze_with_bedrock(sg, risky_rules, resources)
            
            findings.append({
                'security_group_id': sg['GroupId'],
                'name': sg.get('GroupName'),
                'vpc_id': sg.get('VpcId'),
                'risky_rules': risky_rules,
                'attached_resources': resources,
                'ai_analysis': ai_analysis
            })
    
    if findings:
        send_alert(findings)
    
    return {'statusCode': 200, 'body': json.dumps(findings)}

def get_attached_resources(sg_id):
    resources = []
    instances = ec2.describe_instances(Filters=[{'Name': 'instance.group-id', 'Values': [sg_id]}])
    
    for reservation in instances['Reservations']:
        for instance in reservation['Instances']:
            resources.append({
                'type': 'EC2',
                'id': instance['InstanceId'],
                'state': instance['State']['Name']
            })
    
    return resources

def analyze_with_bedrock(sg, risky_rules, resources):
    prompt = f"""Analyze this security group finding:

Security Group: {sg['GroupId']} ({sg.get('GroupName')})
VPC: {sg.get('VpcId')}
Risky Rules: {json.dumps(risky_rules)}
Attached Resources: {json.dumps(resources)}

Provide:
1. Threat explanation (2 sentences)
2. Business impact (2 sentences)
3. Remediation steps (3-5 bullet points)
4. Terraform code to fix
5. Compliance violations

Keep response concise and actionable."""

    response = bedrock.invoke_model(
        modelId='anthropic.claude-3-sonnet-20240229-v1:0',
        body=json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": 1000,
            "messages": [{"role": "user", "content": prompt}]
        })
    )
    
    result = json.loads(response['body'].read())
    return result['content'][0]['text']

def send_alert(findings):
    message = f"🚨 Security Group Audit - {len(findings)} Issues Found\n\n"
    
    for f in findings[:5]:
        message += f"• {f['security_group_id']} ({f['name']})\n"
        message += f"  Rules: {len(f['risky_rules'])} risky\n"
        message += f"  Resources: {len(f['attached_resources'])}\n\n"
    
    sns.publish(
        TopicArn=os.environ['SNS_TOPIC_ARN'],
        Subject='Security Group Audit Alert',
        Message=message
    )
