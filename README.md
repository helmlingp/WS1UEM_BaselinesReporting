# WS1UEM_BaselinesReporting

## Overview

Author: Phil Helmling
Updated By: helmlingp@omnissa.com
Date updated: 9/29/2026

## Purpose

This script will create a report and also export the data to CSV of a chosen Baseline within a chosen OG using REST API.
Choose to report on non-compliant devices, those with a status of `NonCompliant`, `Intermediate`, or `NotAvailable`, or all devices, those that are non-compliant as well as `Compliant`.

## Requires

The [WS1API](https://github.com/helmlingp/WS1API) PowerShell module, either:
- installed from the PowerShell Gallery (`Install-Module WS1API`), or
- imported from a local clone of the WS1API repo, by setting `$UseLocalWS1APIModule = $true` and `$LocalWS1APIModulePath` near the top of the script (useful for local development/testing).

## Report

The report provides the following sections:

- Summary Information for Baseline
- Install Summary
- Version Summary
- Compliance Summary
- Baseline Customisations
- Baseline Additional Policies
- Assignments (SmartGroups the Baseline is assigned to and excluded from)
- Device list of devices that match the specified compliance type and baseline, including each device's Organization Group
- Individual settings of all the devices for the **specified compliance type** (all devices or non-compliant devices) for a **specified baseline** (basically all the devices listed in the previous section, but all the individual settings)

Sections with no data (e.g. no devices assigned/installed, no customizations, no additional policies) are reported as such instead of an empty table.

### Example report - [Sample_ws1baselinereport_20260929_1352.log](Sample_ws1baselinereport_20260929_1352.log)

## Export

Two CSV files are written per Baseline reported on, alongside the log file, in tabular format:

- `<log-basename>_Device_Compliance_Status_<BaselineName>.csv` - one row per device in the Baseline, with:
  - Device UUID
  - Device Name
  - userName
  - Organization Group
  - Install Status
  - Baseline Version
  - Compliance Status
  - Reported On

- `<log-basename>_<ComplianceLevel>_<BaselineName>.csv` - one row per non-compliant/unavailable policy setting per device, with:
  - Device UUID
  - Device Name
  - User Name
  - Organization Group
  - Policy Setting
  - Compliance Status
  - Policy
  - Policy Path

### Example exports
- [Sample_ws1baselinereport_20260929_1352_Device_Compliance_Status_MS25H2.csv](Sample_ws1baselinereport_20260929_1352_Device_Compliance_Status_MS25H2.csv)
- [Sample_ws1baselinereport_20260929_1352_NonCompliant_NotAvailable_MS25H2.csv](Sample_ws1baselinereport_20260929_1352_NonCompliant_NotAvailable_MS25H2.csv)

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
