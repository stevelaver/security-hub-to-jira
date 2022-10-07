import boto3
import json
import os
import getopt
import sys
from datetime import datetime, timedelta

def create_filter(aws_account_ids, severity_labels):
	aws_accounts = list(map(lambda x:  {'Value': x,'Comparison': 'EQUALS'}, aws_account_ids))
	severities = list(map(lambda x:  {'Value': x,'Comparison': 'EQUALS'}, severity_labels))
	return {
        'AwsAccountId': aws_accounts,
        'SeverityLabel': severities,
        'WorkflowStatus': [
            {'Value': 'NEW', 'Comparison': 'EQUALS'},
            {'Value': 'NOTIFIED', 'Comparison': 'EQUALS'}
        ],
        'RecordState': [
            {'Value': 'ACTIVE', 'Comparison': 'EQUALS'}
        ]
	}

def resource_descriptor(r):
	result =  f"Type: {r['Type']}, Id: {r['Id']}"
	name = resource_name(r)
	if name is not None:
		result = result + f", Name: {name}"
	return result
	
def resource_name(r):
	return r.get("Tags",{"Name":None}).get("Name", None)
	
def is_finding_old(finding, days):
	return datetime.now()-datetime.fromisoformat(finding['LastObservedAt'][0:-1])>timedelta(days=days)
	
def is_resource_ec2(resource):
	return resource['Type']=='AwsEc2Instance'
	
instance_running_cache = {}
	
def is_ec2_running(aws_account, resource):
	arn = resource['Id']
	if arn in instance_running_cache:
		return instance_running_cache[arn]
	id = arn.split(":")[-1].split("/")[-1]
	if not is_resource_ec2(resource):
		raise Exception(f"{id} is not an EC2 instance")
	# get AWS client for the given account
	session = boto3.Session(profile_name=aws_account, region_name='us-east-1')
	ec2_client = session.client('ec2')
	# get state of EC2
	response = ec2_client.describe_instance_status(InstanceIds=[id], IncludeAllInstances=True)
	if response['InstanceStatuses'][0]['InstanceId']!=id:
		raise Exception("Unexpected instance")
	is_running = response['InstanceStatuses'][0]['InstanceState']['Name']=='running'
	instance_running_cache[arn]=is_running
	return is_running
		
# retrieve SecurityHub findings, grouping together findings having the same
# AwsAccountId and Title and grouping the associated "resources" into a single list
def suppress_findings(aws_account_ids, severity_labels, dry_run):
	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html
	session = boto3.Session(profile_name='security-account', region_name='us-east-1')
	client = session.client('securityhub')
	filters = create_filter(aws_account_ids, severity_labels)
	findings = {}
	response = None
	next_token = None
	finding_ids_to_suppress=[]
	while response is None or next_token is not None:
		if next_token is None:
			response = client.get_findings(Filters=filters)
		else:
			response = client.get_findings(Filters=filters, NextToken=next_token)
		for f in response['Findings']:
			account = f['AwsAccountId']
			print(f"Account: {account} Finding: {f['Id']}")
				
			## if the resource is a stopped EC2 and the finding is > 2 weeks old, then suppress it
			for resource in f['Resources']:
				if is_resource_ec2(resource) and not is_ec2_running(account, resource) and is_finding_old(f, 14):
					print(f"\tSuppress {f['Id']} for {resource_name(resource)}")
					finding_ids_to_suppress.append({'Id': f['Id'], 'ProductArn': f['ProductArn']})

		if 'NextToken' in response:
			next_token = response['NextToken']
		else:
			next_token = None
			
	if not dry_run:
		batch_start = 0
		while batch_start<len(finding_ids_to_suppress):
			client.batch_update_findings(
				FindingIdentifiers=finding_ids_to_suppress[batch_start:batch_start+100],
				 Workflow={'Status':'SUPPRESSED'})
			batch_start = batch_start + 100

		
ARG_HELP =  'python3 suppress-findings-for-stopped-instances.py --account 325565585839[,383874245509,...] --severity CRITICAL[,HIGH,...] --dryrun'

def main():
	dry_run=False
	try:
		opts, args = getopt.getopt(sys.argv[1:],"a:s:d",["account=", "severity=", "dryrun"])
	except getopt.GetoptError:
		print(ARG_HELP)
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print(ARG_HELP)
			sys.exit()
		elif opt in ("-a", "--account"):
			aws_accounts = arg.split(",")
		elif opt in ("-s", "--severity"):
			severity_labels = arg.split(",")
		elif opt in ("-d", "--dryrun"):
			dry_run=True
      	
	suppress_findings(aws_accounts, severity_labels, dry_run)
	
		
if __name__ == '__main__':
	main()
