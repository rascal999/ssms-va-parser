#!/usr/bin/env python3

from os.path import exists
from pathlib import Path
from string import Template

import argparse
import csv
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
    parser = argparse.ArgumentParser(description="Parse SSMS CSV to output issues based on template file.")
    parser.add_argument("--csv", required=True,
                        help="SSMS CSV file")
    parser.add_argument("--template", required=True,
                        help="Template to build issues from")
    parser.add_argument("--cvss", required=False, type=float, default=0, choices=[Range(0.0, 10.0)],
                        help="Only include issues with this rating or above (default: 0)")
    parser.add_argument("--output", required=False, default="nessus",
                        help="Output directory to create issues (default: nessus)")

    parsed = parser.parse_args()

    # Open template
    template_string = Path(parsed.template).read_text()

    # Open CSV
    csv_file = csv.DictReader(open(parsed.csv))
    for row in csv_file:
      print(row)
    sys.exit(1)
    dedupe_dict = {}
    for row in csv_file:
      if row['Plugin ID'] not in dedupe_dict:
        dedupe_dict[row['Plugin ID']] = dict(row)
        # Hosts list
        dedupe_dict[row['Plugin ID']]['Hosts'] = []
      if row['Host'] not in dedupe_dict[row['Plugin ID']]['Hosts']:
        dedupe_dict[row['Plugin ID']]['Hosts'].append(row['Host'])

    # Check / create output directory
    if os.path.exists(parsed.output):
      print("ERROR: Output directory exists, bailing..")
      sys.exit(1)
    os.mkdir(parsed.output)

    # For each issue in dedupe dict
    for issue in dedupe_dict:
      risk_rating = dedupe_dict[issue]['CVSS v3.0 Base Score']
      if risk_rating == "":
        risk_rating = 0

      # Don't include issue if CVSS score too low
      if float(risk_rating) < parsed.cvss:
        continue
      temp_obj = Template(template_string)
      # Plugin ID,CVE,CVSS v2.0 Base Score,Risk,Host,Protocol,Port,Name,Synopsis,Description,Solution,See Also,Plugin Output,STIG Severity,CVSS v3.0 Base Score
      # CVSS v2.0 Temporal Score,CVSS v3.0 Temporal Score,Risk Factor,BID,XREF,MSKB,Plugin Publication Date,Plugin Modification Date,Metasploit,Core Impact,CANVAS
      if len(dedupe_dict[issue]['CVE']) == 0:
        dedupe_dict[issue]['CVE'] = "N/A"
      if len(dedupe_dict[issue]['Plugin Output']) == 0:
        dedupe_dict[issue]['Plugin Output'] = "N/A"
      issue_file = open(parsed.output + "/" + issue + ".tex", "w")
      issue_file.write(
        temp_obj.substitute(
          plugin_id=dedupe_dict[issue]['Plugin ID'],
          cvss3=dedupe_dict[issue]['CVSS v3.0 Base Score'],
          risk=dedupe_dict[issue]['Risk'],
          name=dedupe_dict[issue]['Name'],
          plugin_output=dedupe_dict[issue]['Plugin Output'],
          synopsis=dedupe_dict[issue]['Synopsis'].replace("_","\_"),
          description=dedupe_dict[issue]['Description'].replace("_","\_"),
          # There must be a better way..
          cve="        \item \\href{{https://cve.mitre.org/cgi-bin/cvename.cgi?name={0}}}{{{0}}}\n".format("".join(cve for cve in dedupe_dict[issue]['CVE'].split())),
          host=''.join('        \item %s\n' % host for host in dedupe_dict[issue]['Hosts']),
          see_also=''.join('%%        \\url{%s}\n\n' % see_also for see_also in dedupe_dict[issue]['See Also'].split()),
          solution=dedupe_dict[issue]['Solution'].replace("_","\_"),
        )
      )
      issue_file.close()

if __name__ == "__main__":
    main()
