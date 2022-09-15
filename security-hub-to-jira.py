import boto3
import json
from atlassian import Jira
import os
import getopt
import sys

# https://atlassian-python-api.readthedocs.io/
# pip install atlassian-python-api

security_hub_label='security-hub'
auto_generated_label='auto-generated'
jql_request = f"labels = {security_hub_label} and labels={auto_generated_label}"
limit = 20

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

# retrieve SecurityHub findings, grouping together findings having the same
# AwsAccountId and Title and grouping the associated "resources" into a single list
def get_sec_hub_findings(aws_account_ids, severity_labels):
	# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/securityhub.html
	session = boto3.Session(profile_name='security-account', region_name='us-east-1')
	client = session.client('securityhub')
	filters = create_filter(aws_account_ids, severity_labels)
	findings = {}
	response = None
	next_token = None
	finding_count = 0
	while response is None or next_token is not None:
		if next_token is None:
			response = client.get_findings(Filters=filters)
		else:
			response = client.get_findings(Filters=filters, NextToken=next_token)
		for f in response['Findings']:
			finding_count = finding_count + 1
			account = f['AwsAccountId']
			severity = f['Severity']['Label']
			title = f['Title']
			description = f['Description']
			resources = [] # subselect critical metadata
			for r in f['Resources']:
				resources.append({"Type":r["Type"], "Id":r["Id"], "Name":r.get("Tags",{"Name":None}).get("Name", None)})
			key = (account, title)
			if key in findings:
				record = findings[key]
			else:
				record = {"account":account, "title":title, "severity":severity, "description":description, "resources":[]}
				findings[key] = record
			record["resources"].extend(resources)
		if 'NextToken' in response:
			next_token = response['NextToken']
		else:
			next_token = None
	return findings.values()

# return all the JIRA issues labeled with 'security-hub' and 'auto-generated'
def get_jira_sec_hub_issues(jira):
	total = None
	start=0
	result = {}
	while total is None or start<total:
		response = jira.jql(jql_request, start=start, limit=limit)
		total = response['total']
		issues = response['issues']
		for issue in issues:
			key = issue['key']
			priority = issue['fields']['priority']['name']
			status = issue['fields']['status']['name']
			summary = issue['fields']['summary']
			description = issue['fields']['description']
			if summary in result:
				raise Error(f"Repeated issue title: {summary}")
			result[summary]={"key":key, "summary":summary, "description":description, 'status':status}
		start=start+limit
		return result
		
def resources_to_text(resources):
	result = ""
	for r in resources:
		result = result + f"\n\tType: {r['Type']}, Id: {r['Id']}"
		if "Name" in r and r["Name"] is not None:
			result = result + f", Name: {r['Name']}"
	return result
		
ARG_HELP =  'python3 security-hub-to-jira.py --account 325565585839[,383874245509,...] --severity CRITICAL[,HIGH,...] --dryrun'

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
      	
  	# get SecHub findings
	sec_hub_findings = get_sec_hub_findings(aws_accounts, severity_labels)
	
	# get Jira issues
	jira = Jira(
	    url='https://sagebionetworks.jira.com/',
	    username=os.environ['JIRA_USER_EMAIL_ADDRESS'],
	    password=os.environ['JIRA_API_TOKEN'],
	    cloud=True)
	    
	issues = get_jira_sec_hub_issues(jira)
	
	# create or update Jira issues
	for finding in sec_hub_findings:
		jira_summary=f"{finding['account']} {finding['title']}"
		description = f"Machine generated description.  Do not alter.\n\n{finding['description']}\n\nAffected resources:\n{resources_to_text(finding['resources'])}"
		if jira_summary in issues:
			issue = issues[jira_summary]
			key = issue['key']
			status = issue['status']
			current_content = {"description": issue["description"]}
			fields_to_update = {"description": description}
			if current_content == fields_to_update:
				print(f"Nothing to update in **{status}** {key} {jira_summary}")
			else:
				if dry_run:
					print(f"UPDATE existing issue {key} {jira_summary}")
				else:
					jira.issue_update(key, fields_to_update)
		# otherwise create a new issue
		else:
			fields_to_create = {
				"summary": jira_summary,
				"description": description,
				"labels":[security_hub_label, auto_generated_label],
				"project": {"key": "IT"},
				"issuetype": { "name": "Bug" }
			}
			if dry_run:
				print(f"CREATE new issue {jira_summary}")
			else:
				jira.issue_create(fields_to_create)
		
if __name__ == '__main__':
	main()
