# WS1UEM_BaselinesReporting

## Overview

Author: Phil Helmling
Updated By: helmlingp@omnissa.com
Date updated: 8/16/2022

## Purpose

This script will create a report and also export the data to CSV of a chosen Baseline within a chosen OG using REST API.
Choose to report on non-compliant devices, those with a status of `NonCompliant`, `Intermediate`, or `NotAvailable`, or all devices, those that are non-compliant as well as `Compliant`.

## Report

The report provides the following sections:

- Summary Information for Baseline
- Install Summary
- Version Summary
- Compliance Summary
- Baseline Customisations
- Baseline Additional Policies
- Assignments
- Device list of devices that match the specified compliance type and baseline
- Individual settings of all the devices for the **specified compliance type** (all devices or non-compliant devices) for a **specified baseline** (basically all the devices listed in the previous section, but all the individual settings)

### Example report - [Sample_WS1BaselinesReport_20210223_0409.log](Sample_WS1BaselinesReport_20210224_0409.log)

## Export

The export is essentially the individual settings of all the devices for the specified compliance type (all devices or non-compliant devices) for a specified baseline in tabular format. The following fields are provided:
- Device UUID
- Device Name
- Policy Setting
- Compliance Status
- Policy
- Policy Path

### Example export - [Sample_WS1BaselinesReport_20210224_0409_CIS%20L1](Sample_WS1BaselinesReport_20210224_0409_CIS%20L1.csv)

## Requirements

The following Workspace ONE UEM API details are required:

- Workspace ONE UEM Server Name
- Username to authenticate
- Password to above user
- AW-Tenent-Key (API Key)
- Organizational Group Name (will search using beginning of name not case sensitive)

## Usage

You can either provide connection parameters on command line or be prompted for connection parameters when running the script. This script will also run on a Windows Desktop, Windows Server or a macOS device with Powershell installed (pwsh).

```pwsh
powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -ApiKey RESTAPIKEY
```

```pwsh
powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1
```
