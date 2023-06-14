#!/usr/bin/env python3

import argparse
from jsonpath_ng import jsonpath
from jsonpath_ng.ext import parse
from packaging.version import Version

import jinja2
import json
import sys
import os.path
import re

def filePath(vulnerability):
    return vulnerability['location']['file']

def countSeverities(vulnerabilities):
    # Pre-define severities we expect so we don't have to sort later
    frequencies = {
        '4 - Critical': 0,
        '3 - High': 0,
        '2 - Medium': 0,
        '1 - Low': 0,
        '0 - Unknown': 0
    }

    for vulnerability in vulnerabilities:
        if vulnerability['severity'] in frequencies:
            frequencies[vulnerability['severity']] += 1
        else: # If we don't have a category for a severity create it here
            frequencies[vulnerability['severity']] = 1

    return frequencies

parser = argparse.ArgumentParser(description='Parse a GitLab SAST report to HTML')
parser.add_argument('files', metavar='files', nargs='+',
                    help='The files that should be converted to HTML.')
parser.add_argument('--only-severities', type=str, required=False,
                    help='A comma delimited list of the vulnerabilities to keep (defaults to all)')
parser.add_argument('--jsonpath-filter', type=str, required=False,
                    help='Provide a custom jsonpath filter to apply to all JSON files')
parser.add_argument('--no-verify-version', dest='verify_version', action='store_false',
                    help='Disable verification of the report version before attempting to parse it.' )
parser.set_defaults(verify_version=True)
args = parser.parse_args()

if args.jsonpath_filter is not None:
    try:
        jsonpath_expr = parse(args.jsonpath_filter)
    except:
        print('Invalid jsonpath filter provided')
        sys.exit(1)
# Build a filter based on severities
elif args.only_severities is not None:
    severities = args.only_severities.split(',')
    filters = list()
    for severity in severities:
        filters.append("$.vulnerabilities[?(@.severity == '" + severity + "')]")
    filter = ' | '.join(filters)
    jsonpath_expr = parse(filter)
else:
    jsonpath_expr = parse("$.vulnerabilities[*]")

vulnerabilities = list()

# Iterate over all the JSON files provided
for json_file in args.files:
    with open(json_file) as f:
        data = json.load(f)

        if Version(data['version']) >= Version("16.0") and args.verify_version:
            print('We don\'t know how to parse this version of SAST report')
            sys.exit(1)

        vulns = jsonpath_expr.find(data)
        for vuln in vulns:
            severity = vuln.value.get('severity') or 'Unknown'
            if severity == "Critical":
                vuln.value['severity'] = "4 - Critical"
            elif severity == "High":
                vuln.value['severity'] = "3 - High"
            elif severity == "Medium":
                vuln.value['severity'] = "2 - Medium"
            elif severity == "Low":
                vuln.value['severity'] = "1 - Low"
            else:
                vuln.value['severity'] = f"0 - {severity}"

            confidence = vuln.value.get('confidence') or 'Unknown'
            if confidence == "Critical":
                vuln.value['confidence'] = "4 - Critical"
            elif confidence == "High":
                vuln.value['confidence'] = "3 - High"
            elif confidence == "Medium":
                vuln.value['confidence'] = "2 - Medium"
            elif confidence == "Low":
                vuln.value['confidence'] = "1 - Low"
            else:
                vuln.value['confidence'] = f"0 - {confidence}"

            p = re.compile("gl-(?P<step>[a-zA-Z0-9-_]+)-report(-(?P<analyzer>[a-zA-Z0-9-_]+))?\.json")
            m = p.match(json_file)
            vuln.value['source'] = json_file
            if m.group("step"):
                vuln.value['step'] = m.group("step")
            if m.group("analyzer"):
                vuln.value['analyzer'] = m.group("analyzer")

            vuln.value['name'] = vuln.value.get('name') or ''

            vulnerabilities.append(vuln.value)

frequencies=countSeverities(vulnerabilities)

project_dir = os.path.dirname(__file__)
env = jinja2.Environment(loader=jinja2.FileSystemLoader(os.path.join(project_dir, 'templates')))
template = env.get_template('vulnerability_report.html')
rendered = template.render(vulnerabilities=vulnerabilities, frequencies=countSeverities(vulnerabilities))
print(rendered)
