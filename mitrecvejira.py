import requests
from requests.auth import HTTPBasicAuth
import json

# Jira credentials
JIRA_URL = "https://ucdconnect-team-cybersecurity.atlassian.net/rest/api/3/issue"
JIRA_EMAIL = ""
JIRA_API_TOKEN = ""
JIRA_PROJECT_KEY = ""  # Replace with your project key

# MITRE CVE API base URL
MITRE_API_URL = "https://cveawg.mitre.org/api/cve/"

def fetch_cve_details(cve_id):
    """Fetch CVE details from MITRE's CVE.org API."""
    try:
        response = requests.get(MITRE_API_URL + cve_id)
        response.raise_for_status()
        cve_data = response.json()

        # Extract relevant details
        description = cve_data.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "N/A")
        title = cve_data.get("cve", {}).get("id", "N/A")
        cvss_score = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", "N/A")
        vector_string = cve_data.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("vectorString", "N/A")

        return {
            "cve_id": cve_id,
            "title": title,
            "description": description,
            "cvss_score": cvss_score,
            "vector_string": vector_string,
        }
    except Exception as e:
        print(f"Error fetching CVE details: {e}")
        return None

def create_jira_issue(issue_data):
    """Create a Jira issue using the Jira REST API."""
    headers = {"Accept": "application/json", "Content-Type": "application/json"}

    # Convert description to Atlassian Document Format (ADF)
    adf_description = {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"text": f"CVE ID: {issue_data['cve_id']}", "type": "text"}]},
            {"type": "paragraph", "content": [{"text": f"CVSS Score: {issue_data['cvss_score']}", "type": "text"}]},
            {"type": "paragraph", "content": [{"text": f"Vector String: {issue_data['vector_string']}", "type": "text"}]},
            {"type": "paragraph", "content": [{"text": f"Description: {issue_data['description']}", "type": "text"}]},
        ]
    }

    issue_payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"CVE: {issue_data['cve_id']} - {issue_data['title']}",
            "description": adf_description,
            "issuetype": {"name": "Task"},  # Change issue type as needed
        }
    }

    try:
        response = requests.post(
            JIRA_URL,
            headers=headers,
            data=json.dumps(issue_payload),
            auth=HTTPBasicAuth(JIRA_EMAIL, JIRA_API_TOKEN),
        )
        if response.status_code == 201:
            print(f"Issue created successfully: {response.json()['key']}")
        else:
            print(f"Failed to create issue: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"Error creating Jira issue: {e}")

def main():
    """Main script to fetch CVE details and create a Jira issue."""
    cve_id = input("Enter a CVE ID (e.g., CVE-2023-1234): ").strip()
    cve_details = fetch_cve_details(cve_id)
    if cve_details:
        print("\nCVE Details:")
        print(f"CVE ID: {cve_details['cve_id']}")
        print(f"Title: {cve_details['title']}")
        print(f"Description: {cve_details['description']}")
        print(f"CVSS Score: {cve_details['cvss_score']}")
        print(f"Vector String: {cve_details['vector_string']}")
        
        # Create Jira issue
        create_jira_issue(cve_details)
    else:
        print("Failed to fetch CVE details. Please try again.")

if __name__ == "__main__":
    main()