#!/usr/bin/env python3

import argparse
from csv import QUOTE_ALL
import xml.etree.ElementTree as ET
import csv
import os
from datetime import datetime
import sys


csvHeaders = ['Severity', 'CVSS Score', 'IP Address', 'FQDN', 'Port', 'OS', 'Vulnerability', 'CVE']
nessusFields = ['risk_factor','cvss_base_score', 'host-ip', 'host-fqdn', 'port', 'operating-system', 'plugin_name', 'cve']
reportRows = []
findings = []

# Clean values from Nessus report
def getValue(rawValue):
    if rawValue == None:
        rawValue = "empty"
    else:
        cleanValue = rawValue.replace('\n', ' ').strip(' ')
        if len(cleanValue) > 32000:
            cleanValue = cleanValue[:32000] + ' [Trimmed due to length]'
        return cleanValue

# Helper function for handleReport()
def getKey(rawKey):
    return csvHeaders[nessusFields.index(rawKey)]

# Handle a single report item
def handleReport(report):
    findings = []
    reportHost = dict.fromkeys(csvHeaders, '')
    for item in report:
        if item.tag == 'HostProperties':
            for tag in (tag for tag in item if tag.attrib['name'] in nessusFields):
                reportHost[getKey(tag.attrib['name'])] = getValue(tag.text)
        if item.tag == 'ReportItem':
            reportRow = dict(reportHost)
            reportRow['Port'] = item.attrib['port']
            reportRow['Vulnerability'] = item.attrib['pluginName']
            for tag in (tag for tag in item if tag.tag in nessusFields):
                reportRow[getKey(tag.tag)] = getValue(tag.text)
            if reportRow['CVSS Score'] != "":
                findings.append(reportRow)
    return findings

# Get files 
def getargs():
    parser = argparse.ArgumentParser(description="Merge all .nessus files within a folder into one .csv report in that folder", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(type=str, dest="directory", help="Folder containing .nessus files")
    args = parser.parse_args()
    return args

# Main
if __name__ == '__main__':
    args = getargs()
    if not os.path.isdir(args.directory):
        print('[!] Cannot find specified directory')
        exit()

    # find all .nessus files in the directory
    nessusFiles = [os.path.join(args.directory, file) for file in os.listdir(args.directory) if file.endswith('.nessus')]

    if len(nessusFiles) == 0:
        print('[!] No .nessus files found!')
        exit()
    else:
         print(f'[*] Found {len(nessusFiles)} nessus files!')

    # Get reports from nessus file
    for file in nessusFiles:
        reportRows = []
        findings = []

        tree = ET.parse(file)
        root = tree.getroot()
    
            ## Get reports rows from each report
        try:
            scanFile = ET.parse(file)
            xmlRoot = scanFile.getroot()
            for report in xmlRoot.findall('./Report/ReportHost'):
                rootReport = root.find('Report')
                for report in xmlRoot.findall('./Report/ReportHost'):
                    findings = handleReport(report)
                    reportRows.extend(findings)
        except IOError:
            print("Could not find file \"" + file + "\"")

    # Create csv report
    timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
    fname = os.path.join(f'{args.directory}_{timestamp}.csv')
    with open(fname, 'w', newline='') as csvfile:
        fieldnames = csvHeaders
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        try:
            for D in reportRows:
                writer.writerow({k:v for k, v in D.items() if v})
        except:
                print("error writing rows")