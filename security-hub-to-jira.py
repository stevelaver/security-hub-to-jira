import boto3
import json
from atlassian import Jira
import os
import getopt
import sys
from enum import Enum

# https://atlassian-python-api.readthedocs.io/
# pip install atlassian-python-api

security_hub_label='security-hub'
auto_generated_label='auto-generated'
jql_request = f"labels = {security_hub_label} and labels={auto_generated_label}"
limit = 20
LEN=100

class Finding_Group_By(Enum):
	VULNERABILITY=1,
	RESOURCE=2

Product_To_Group_by={"Inspector": Finding_Group_By.RESOURCE}

# Group by Vulnerability unless otherwise specified
def get_group_by(product):
	return Product_To_Group_by.get(product, Finding_Group_By.VULNERABILITY)


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
	if "Name" in r and r["Name"] is not None:
		result = result + f", Name: {r['Name']}"
	return result
	
def resource_name(r):
	return r.get("Tags",{"Name":None}).get("Name", None)
		
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
			product = f['ProductName']
				
			group_by = get_group_by(product)
			if group_by==Finding_Group_By.VULNERABILITY:
				key = (account, title)
				if key in findings:
					record = findings[key]
				else:
					record = {"account":account, "product":product, "title":title, "severity":severity, "description":description, "resources":[]}
					findings[key] = record
				resources = []
				for resource in f['Resources']:
					resources.append(resource_descriptor({"Type":resource["Type"], "Id":resource["Id"], "Name":resource_name(resource)}))
				record["resources"].extend(resources)	
			elif group_by==Finding_Group_By.RESOURCE:
				for resource in f['Resources']:
					name = resource_name(resource) if resource_name(resource) is not None else resource["Id"]
					key = (account, name)
					if key in findings:
						record = findings[key]
					else:
						record = {"account":account, "product":product, "name":name, "vulnerabilities":[], "severity":severity,  "resources":set()}
						findings[key] = record
					record["resources"].add(resource_descriptor(resource))	
					record["vulnerabilities"].append(f"{title}: {description}")	
			else:
				raise Error(f"Unexpected: {group_by}")

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
	list(resources).sort()
	result = ""
	for r in resources:
		result = result + f"\n\t{r}"
	return result
		
def vulnerabilities_to_text(vs):
	vs.sort()
	result = ""
	for v in vs:
		result = result + f"\n\t{v}"
	return result
		
ARG_HELP =  'python3 security-hub-to-jira.py --account 325565585839[,383874245509,...] --severity CRITICAL[,HIGH,...] --dryrun  --verbose'
WARNING_HDR = "Machine generated description.  Do not alter.\n\n"

def main():
	dry_run=False
	verbose=False
	try:
		opts, args = getopt.getopt(sys.argv[1:],"a:s:dv",["account=", "severity=", "dryrun", "verbose"])
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
		elif opt in ("-v", "--verbose"):
			verbose=True
      	
  	# get SecHub findings
	sec_hub_findings = get_sec_hub_findings(aws_accounts, severity_labels)
	
	# get Jira issues
	jira = Jira(
	    url='https://sagebionetworks.jira.com/',
	    username=os.environ['JIRA_USER_EMAIL_ADDRESS'],
	    password=os.environ['JIRA_API_TOKEN'],
	    cloud=True)
	    
	issues = get_jira_sec_hub_issues(jira)
	
	# create a dict of unmatched issues. As we find them in SecurityHub, we will remove them
	unmatched_issues = {}
	for summary in issues:
		issue = issues[summary]
		unmatched_issues[issue["key"]]=issue
	
	# create or update Jira issues
	for finding in sec_hub_findings:
		group_by = get_group_by(finding['product'])
		if group_by==Finding_Group_By.VULNERABILITY:
			jira_summary=f"{finding['account']} {finding['title']}"
			description = f"{WARNING_HDR}{finding['description']}\n\nAffected resources:\n{resources_to_text(finding['resources'])}"
		elif group_by==Finding_Group_By.RESOURCE:
			jira_summary=f"{finding['account']} {finding['name']}"
			description = f"{WARNING_HDR}Vulnerabilities:\n{vulnerabilities_to_text(finding['vulnerabilities'])}\n\nResources:\n{resources_to_text(finding['resources'])}"
		else:
			raise Error(f"Unexpected: {group_by}")
		if jira_summary in issues:
			issue = issues[jira_summary]
			key = issue['key']
			del unmatched_issues[key]
			status = issue['status']
			current_content = {"description": issue["description"]}
			fields_to_update = {"description": description}
			if current_content == fields_to_update:
				print(f"Nothing to update in **{status}** {key} {jira_summary}")
			else:
				if dry_run:
					print(f"UPDATE existing issue {key} {jira_summary} {description if verbose else ''}")
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
				print(f"CREATE new issue {jira_summary} {description if verbose else ''}")
			else:
				jira.issue_create(fields_to_create)
		
	print(f"\n\nThe following Jira issues are no longer found in AWS SecurityHub and can be closed in Jira:")
	for key in unmatched_issues:
		issue = unmatched_issues[key]
		if issue['status'] not in ('Resolved', 'Closed', 'Done'):
			print(f"{key} {issue['status']} {issue['summary']}")
		
if __name__ == '__main__':
	main()
