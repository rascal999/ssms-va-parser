#!/usr/bin/env python3

from os.path import exists
from pathlib import Path
from string import Template

import argparse
import csv
import glob
import os
import sys

class bcolours:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class Range(object):
    def __init__(self, start, end):
        self.start = start
        self.end = end
    def __eq__(self, other):
        return self.start <= other <= self.end

def welcome():
  print("Parse SSMS CSV to output issues based on template file.")
  print()

def main():
  parser = argparse.ArgumentParser(description="Parse SSMS CSV directory to output issues based on template file.")
  parser.add_argument("--csv-directory", required=True,
                      help="SSMS CSV directory")
  parser.add_argument("--template", required=True,
                      help="Template to build issues from")
  parser.add_argument("--cvss", required=False, type=float, default=0, choices=[Range(0.0, 10.0)],
                      help="Only include issues with this rating or above (default: 0)")
  parser.add_argument("--output", required=False, default="ssms-output",
                      help="Output directory to create issues (default: ssms-output)")

  parsed = parser.parse_args()

  # Open template
  template_string = Path(parsed.template).read_text()

  # List all *.csv in target directory
  # All files and directories ending with .txt and that don't begin with a dot:
  csv_files = glob.glob(parsed.csv_directory + "/*.csv")
  if len(csv_files) == 0:
    print("ERROR: No CSV files identified, bailing..")
    sys.exit(1)

  init_dict = {}
  for csv_file in csv_files:
    csv_data = csv.DictReader(open(csv_file))
    init_dict[csv_file] = csv_data

  dedupe_list = []
  servers = {}
  for csv_file in init_dict:
    for row in init_dict[csv_file]:
      try:
        servers[row['ID']].append(row['Server'])
      except:
        servers[row['ID']] = []
        servers[row['ID']].append(row['Server'])
      row['Server'] = []
      if row['ID'] != "" and row not in dedupe_list:
        dedupe_list.append(row)

  for row in dedupe_list:
    row['Server'] = servers[row['ID']]

  #for row in dedupe_list:
  #  print(row)

  # Check / create output directory
  if os.path.exists(parsed.output):
    print("ERROR: Output directory exists, bailing..")
    sys.exit(1)
  os.mkdir(parsed.output)

#{
#  "Status": "Fail",
###  "Risk": "Medium",
###  "ID": "VA1219",
###  "Server": "",
###  "Database": "",
#  "Applies to": "database",
#  "Security Check": "Transparent data encryption should be enabled",
###  "Description": "Transparent data encryption (TDE) helps to protect the database files against information disclosure by performing real-time encryption and decryption of the database, associated backups, and transaction log files 'at rest', without requiring changes to the application. This rule checks that TDE is enabled on the database.",
#  "Category": "Data Protection",
#  "Benchmark References": "FedRAMP",
###  "Rule Query": "SELECT CASE WHEN EXISTS\n( SELECT *\n    FROM sys.databases\n    WHERE name = db_name()\n    AND is_encrypted = 0)\nTHEN 1\nELSE 0\nEND AS [Violation]",
###  "Actual Result": "1",
###  "Expected Result": "0",
###  "Remediation": "Enable TDE on the affected database. Please follow the instructions on https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption",
###  "Remediation Script": ""
#}

  # For each issue in dedupe dict
  for issue in dedupe_list:
    if issue['Status'] != "Fail":
      continue
    #risk_rating = dedupe_dict[issue]['CVSS v3.0 Base Score']
    #if risk_rating == "":
    #  risk_rating = 0

    # Don't include issue if CVSS score too low
    #if float(risk_rating) < parsed.cvss:
    #  continue
    temp_obj = Template(template_string)

    if issue['Expected Result'] == "":
      issue['Expected Result'] = "N/A"

    if issue['Actual Result'] == "":
      issue['Actual Result'] = "N/A"

    issue_file = open(parsed.output + "/" + issue['ID'] + ".tex", "w")
    issue_file.write(
      temp_obj.substitute(
        risk=issue['Risk'],
        name=issue['Security Check'].replace("_","\_"),
        synopsis=issue['Description'].replace("_","\_"),
        description=issue['Description'].replace("_","\_"),
        rule_query = issue['Rule Query'],
        expected_result = issue['Expected Result'],
        actual_result = issue['Actual Result'],
        database = issue['Database'],
        # There must be a better way..
        #cve="        \item \\href{{https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}}}{{{0}}}\n".format("".join(cve for cve in issue['CVE'].split())),
        host=''.join('        \item %s\n' % host for host in issue['Server']),
        #see_also=''.join('%%        \\url{%s}\n\n' % see_also for see_also in issue['See Also'].split()),
        solution=issue['Remediation'].replace("_","\_"),
      )
    )
    issue_file.close()

if __name__ == "__main__":
    main()
