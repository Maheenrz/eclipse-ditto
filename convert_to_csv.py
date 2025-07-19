import json
import csv

# Load the JSON data
with open('ditto_issues.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

issues = data.get('issues', [])

# Create CSV file
with open('ditto_issues.csv', 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['key', 'component', 'file', 'line', 'message', 'severity', 'type', 'status']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()

    for issue in issues:
        writer.writerow({
            'key': issue.get('key', ''),
            'component': issue.get('component', ''),
            'file': issue.get('component', '').split(':')[-1],
            'line': issue.get('line', ''),
            'message': issue.get('message', ''),
            'severity': issue.get('severity', ''),
            'type': issue.get('type', ''),
            'status': issue.get('status', '')
        })

print("✅ CSV file 'ditto_issues.csv' created successfully!")
