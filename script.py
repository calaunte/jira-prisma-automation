#!/usr/bin/env python3
import requests
import sys
from os import getenv
from jira import JIRA


endpoint = getenv("PRISMA_SCAN_JIRA_BASE_URL")
email = getenv("PRISMA_SCAN_JIRA_USER_EMAIL")
api_token = getenv("PRISMA_SCAN_JIRA_API_TOKEN")

project_name = "PRIS"
prisma_token = getenv("PRISMA_TOKEN")
prisma_cloud_url = getenv("PRISMA_CLOUD_URL")
image_id = sys.argv[1]

# Connect to jira instance
jira = JIRA(endpoint, basic_auth=(email, api_token))

# Define JQL query string
jql_str = f'project={project_name} AND issuetype=Epic'

# Search for issues
epics = jira.search_issues(jql_str)

epics_array = []

for epic in epics:
    issues = []
    child_issues = jira.search_issues(f'"Epic Link" = {epic.key}')
    for issue in child_issues:
        issues.append({
            "key": issue.key,
            "issue_name": issue.fields.summary,
            "status": issue.fields.status.name
        })

    epics_array.append({
        "key": epic.key,
        "epic_name": epic.fields.summary,
        "child_issues": issues
    })


def get_scanned_image_results():
    headers = {
        "Accept": "application/json",
        "Authorization": f"Bearer {prisma_token}"
    }
    payload = {}
    response = requests.get(
        f'https://prisma.anpulabs.co/api/v1/scans?imageID={image_id}', headers=headers, data=payload)
    if response.status_code == 200:
        data = response.json()
        return data
    else:
        print('Error: Unable to decode JSON data')


scanned_results = get_scanned_image_results()
repo_name = ''
cves = []

if scanned_results is not None:
    if scanned_results[0]['entityInfo']['vulnerabilities'] is not None:
        for result in scanned_results[0]['entityInfo']['vulnerabilities']:
            if 'CVE' in result['cve']:
                cves.append(result['cve'])

    if scanned_results[0]['entityInfo']['instances'] is not None:
        for result in scanned_results[0]['entityInfo']['instances']:
            if "anpulabs" in result['repo']:
                repo_name = result['repo'].replace('anpulabs/', '')

    resolved_issues = []

    for epic in epics_array:
        if epic['epic_name'] == repo_name:
            for issue in epic['child_issues']:
                contains_cve = False
                for cve in cves:
                    if cve in issue['issue_name']:
                        contains_cve = True
                        break
                if not contains_cve:
                    resolved_issues.append(issue)


    def close_patched_vulns():
        for item in resolved_issues:
            if item['status'] == 'Inbox' or item['status'] == 'In Progress':
                issue = jira.issue(item['key'])
                jira.transition_issue(issue, 'Done')

    close_patched_vulns()

if scanned_results is None:
    print("Unable to retrieve prisma scan results")