import requests
import csv
import base64
import sys
from urllib.parse import urljoin
import json

# SonarCloud Configuration - UPDATE THESE VALUES
SONAR_HOST = "https://sonarcloud.io"
SONAR_TOKEN = "ca5d024528b7e007af4bf8672aee6a15dfa2215b"  # Replace with your actual token
ORGANIZATION_KEY = "maheenrz"  # Your organization key
PROJECT_KEY = "Maheenrz_eclipse-ditto"  # Updated format: organization_repository
OUTPUT_FILE = "sonarcloud_issues.csv"

def get_auth_header(token):
    """Create authentication header for SonarCloud"""
    auth_string = f"{token}:"
    encoded = base64.b64encode(auth_string.encode()).decode()
    return {"Authorization": f"Basic {encoded}"}

def test_connection_and_find_project(host, token, organization_key):
    """Test connection and help find the correct project key"""
    headers = get_auth_header(token)
    
    print("Testing connection to SonarCloud...")
    
    try:
        # Test organization access
        url = urljoin(host, "/api/organizations/search")
        params = {'organizations': organization_key}
        
        response = requests.get(url, headers=headers, params=params)
        print(f"Organization test - Status: {response.status_code}")
        
        if response.status_code != 200:
            print(f"Organization test failed. Response: {response.text}")
            return None
            
        # List all projects in the organization
        url = urljoin(host, "/api/projects/search")
        params = {
            'organization': organization_key,
            'ps': 100  # Page size
        }
        
        response = requests.get(url, headers=headers, params=params)
        print(f"Projects search - Status: {response.status_code}")
        
        if response.status_code == 200:
            data = response.json()
            projects = data.get('components', [])
            print(f"\nFound {len(projects)} projects in organization '{organization_key}':")
            
            for i, project in enumerate(projects, 1):
                key = project.get('key', 'N/A')
                name = project.get('name', 'N/A')
                qualifier = project.get('qualifier', 'N/A')
                print(f"  {i}. Key: {key}")
                print(f"     Name: {name}")
                print(f"     Type: {qualifier}")
                print()
            
            if projects:
                return [p.get('key') for p in projects]
            else:
                print("No projects found in the organization!")
                return []
        else:
            print(f"Failed to fetch projects. Response: {response.text}")
            return None
            
    except Exception as e:
        print(f"Connection test failed: {e}")
        return None

def fetch_all_issues(host, token, organization_key, project_key):
    """Fetch all issues from SonarCloud API"""
    headers = get_auth_header(token)
    issues = []
    page = 1
    page_size = 500
    
    print(f"\nStarting to fetch issues for project: {project_key}")
    
    while True:
        print(f"Fetching page {page}...")
        
        url = urljoin(host, "/api/issues/search")
        params = {
            'organization': organization_key,
            'componentKeys': project_key,
            'ps': page_size,
            'p': page,
            'additionalFields': 'rules,users,comments,transitions,actions,languages',
            's': 'FILE_LINE',
            'asc': 'true'
        }
        
        try:
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                print(f"Error: HTTP {response.status_code}")
                print(f"Response: {response.text}")
                break
                
            data = response.json()
            page_issues = data.get('issues', [])
            
            if not page_issues:
                print("No more issues found.")
                break
                
            issues.extend(page_issues)
            
            total = data.get('total', 0)
            current_count = len(issues)
            
            print(f"Fetched {current_count} of {total} total issues")
            
            if current_count >= total:
                break
                
            page += 1
            
        except requests.RequestException as e:
            print(f"Error fetching data: {e}")
            break
    
    return issues

def export_to_csv(issues, output_file, host, organization_key, project_key):
    """Export issues to CSV file with comprehensive data"""
    print(f"\nExporting {len(issues)} issues to {output_file}...")
    
    fieldnames = [
        'issue_url', 'key', 'rule', 'rule_name', 'severity', 'component', 
        'project', 'line', 'message', 'effort', 'debt', 'author', 
        'creation_date', 'update_date', 'close_date', 'status', 'resolution', 
        'type', 'type_description', 'tags', 'assignee', 'hash',
        'text_range_start_line', 'text_range_end_line', 'text_range_start_offset', 
        'text_range_end_offset', 'scope', 'quickFixAvailable',
        'cleanCodeAttribute', 'cleanCodeAttributeCategory',
        'impacts_RELIABILITY', 'impacts_SECURITY', 'impacts_MAINTAINABILITY',
        'file_path', 'language'
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        
        for issue in issues:
            # Extract text range
            text_range = issue.get('textRange', {})
            
            # Generate SonarCloud issue URL
            issue_key = issue.get('key', '')
            issue_url = f"{host}/project/issues?id={project_key}&open={issue_key}&organizationKey={organization_key}"
            
            # Extract impacts (new SonarQube format)
            impacts = issue.get('impacts', [])
            impact_reliability = impact_security = impact_maintainability = ''
            
            for impact in impacts:
                quality = impact.get('softwareQuality', '')
                severity = impact.get('severity', '')
                
                if quality == 'RELIABILITY':
                    impact_reliability = severity
                elif quality == 'SECURITY':
                    impact_security = severity
                elif quality == 'MAINTAINABILITY':
                    impact_maintainability = severity
            
            # Issue type descriptions
            issue_type = issue.get('type', 'UNKNOWN')
            type_descriptions = {
                'CODE_SMELL': 'Maintainability issue',
                'BUG': 'Reliability issue (potential bug)',
                'VULNERABILITY': 'Security vulnerability',
                'SECURITY_HOTSPOT': 'Security-sensitive code requiring review',
                'UNKNOWN': 'Unknown issue type'
            }
            
            # Extract file path from component
            component = issue.get('component', '')
            file_path = component.split(':')[-1] if ':' in component else component
            
            row = {
                'issue_url': issue_url,
                'key': issue_key,
                'rule': issue.get('rule', ''),
                'rule_name': issue.get('ruleName', ''),
                'severity': issue.get('severity', ''),
                'component': component,
                'project': issue.get('project', ''),
                'line': issue.get('line', ''),
                'message': issue.get('message', '').replace('\n', ' ').replace('\r', '').replace(',', ';'),
                'effort': issue.get('effort', ''),
                'debt': issue.get('debt', ''),
                'author': issue.get('author', ''),
                'creation_date': issue.get('creationDate', ''),
                'update_date': issue.get('updateDate', ''),
                'close_date': issue.get('closeDate', ''),
                'status': issue.get('status', ''),
                'resolution': issue.get('resolution', ''),
                'type': issue_type,
                'type_description': type_descriptions.get(issue_type, 'Unknown'),
                'tags': ';'.join(issue.get('tags', [])),
                'assignee': issue.get('assignee', ''),
                'hash': issue.get('hash', ''),
                'text_range_start_line': text_range.get('startLine', ''),
                'text_range_end_line': text_range.get('endLine', ''),
                'text_range_start_offset': text_range.get('startOffset', ''),
                'text_range_end_offset': text_range.get('endOffset', ''),
                'scope': issue.get('scope', ''),
                'quickFixAvailable': issue.get('quickFixAvailable', ''),
                'cleanCodeAttribute': issue.get('cleanCodeAttribute', ''),
                'cleanCodeAttributeCategory': issue.get('cleanCodeAttributeCategory', ''),
                'impacts_RELIABILITY': impact_reliability,
                'impacts_SECURITY': impact_security,
                'impacts_MAINTAINABILITY': impact_maintainability,
                'file_path': file_path,
                'language': issue.get('lang', '')
            }
            
            writer.writerow(row)
    
    print(f"✅ Export completed successfully!")

def print_summary(issues):
    """Print a detailed summary of the issues"""
    if not issues:
        print("No issues to summarize.")
        return
    
    print(f"\n{'='*50}")
    print(f"SONARCLOUD ISSUES SUMMARY")
    print(f"{'='*50}")
    print(f"Total issues found: {len(issues)}")
    
    # Count by status
    status_counts = {}
    severity_counts = {}
    type_counts = {}
    language_counts = {}
    
    for issue in issues:
        status = issue.get('status', 'UNKNOWN')
        severity = issue.get('severity', 'UNKNOWN')
        issue_type = issue.get('type', 'UNKNOWN')
        language = issue.get('lang', 'UNKNOWN')
        
        status_counts[status] = status_counts.get(status, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        type_counts[issue_type] = type_counts.get(issue_type, 0) + 1
        language_counts[language] = language_counts.get(language, 0) + 1
    
    print(f"\n📊 Issues by Status:")
    for status, count in sorted(status_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {status}: {count}")
    
    print(f"\n⚠️  Issues by Severity:")
    severity_order = ['BLOCKER', 'CRITICAL', 'MAJOR', 'MINOR', 'INFO']
    for severity in severity_order:
        if severity in severity_counts:
            print(f"  {severity}: {severity_counts[severity]}")
    
    print(f"\n🔍 Issues by Type:")
    for issue_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {issue_type}: {count}")
    
    print(f"\n💻 Issues by Language:")
    for language, count in sorted(language_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {language}: {count}")

def main():
    """Main function"""
    print("🔍 SonarCloud Issues Extractor")
    print("=" * 40)
    
    # Validate configuration
    if SONAR_TOKEN == "YOUR_TOKEN_HERE":
        print("❌ Error: Please update SONAR_TOKEN in the script")
        print("   Get your token from: https://sonarcloud.io/account/security")
        sys.exit(1)
    
    # Test connection and find projects
    available_projects = test_connection_and_find_project(SONAR_HOST, SONAR_TOKEN, ORGANIZATION_KEY)
    
    if available_projects is None:
        print("❌ Failed to connect to SonarCloud. Check your token and organization key.")
        sys.exit(1)
    
    if not available_projects:
        print("❌ No projects found. Make sure you've run analysis on your repository.")
        sys.exit(1)
    
    # Use the configured project key or let user choose
    if PROJECT_KEY not in available_projects:
        print(f"⚠️  Configured project key '{PROJECT_KEY}' not found.")
        print("Available project keys:")
        for i, key in enumerate(available_projects, 1):
            print(f"  {i}. {key}")
        
        choice = input("\nEnter the number of the project to analyze (or press Enter for first): ")
        
        if choice.strip():
            try:
                index = int(choice) - 1
                if 0 <= index < len(available_projects):
                    selected_project = available_projects[index]
                else:
                    print("Invalid choice, using first project.")
                    selected_project = available_projects[0]
            except ValueError:
                print("Invalid input, using first project.")
                selected_project = available_projects[0]
        else:
            selected_project = available_projects[0]
    else:
        selected_project = PROJECT_KEY
    
    print(f"\n🎯 Analyzing project: {selected_project}")
    
    # Fetch issues
    issues = fetch_all_issues(SONAR_HOST, SONAR_TOKEN, ORGANIZATION_KEY, selected_project)
    
    if not issues:
        print("❌ No issues found! This could mean:")
        print("   - The analysis hasn't completed yet")
        print("   - All issues have been resolved")
        print("   - The project has no code quality issues")
        return
    
    # Export to CSV
    export_to_csv(issues, OUTPUT_FILE, SONAR_HOST, ORGANIZATION_KEY, selected_project)
    
    # Print summary
    print_summary(issues)
    
    print(f"\n✅ Complete! Issues exported to: {OUTPUT_FILE}")
    print(f"🔗 View in SonarCloud: {SONAR_HOST}/organizations/{ORGANIZATION_KEY}/projects")

if __name__ == "__main__":
    main()