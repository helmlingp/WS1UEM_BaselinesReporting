<#	
  .Synopsis
    Script to create Omnissa Workspace ONE Baseline Report using REST API
  .NOTES
	  Created:   	    December, 2020
    Updated:        September, 2026
    Version:        1.2.1
	  Created by:	    Phil Helmling
	  Organization:   Omnissa, Inc.
    Filename:       WS1BaselinesReporting.ps1
    GitHub:         https://github.com/helmlingp/WS1UEM_BaselinesReporting
    Requires        WS1API module - installed from the PowerShell Gallery (Install-Module WS1API),
                    or imported from a local clone of https://github.com/helmlingp/WS1API when
                    $UseLocalWS1APIModule is set to $true
  .DESCRIPTION
    Writes output to Log file and Device Policy setting status to CSV for selected Baseline.
    Log and CSV written to same directory as script.

  .PARAMETER username
    Workspace ONE UEM console username to authenticate the REST API calls with. Prompted for if not supplied.

  .PARAMETER password
    Password for the above username. Prompted for if not supplied.

  .PARAMETER OGName
    Name (or leading characters, case-insensitive) of the Organization Group to search for and report against. Prompted for if not supplied.

  .PARAMETER Server
    Workspace ONE UEM API server URL, e.g. https://as1234.awmdm.com. Prompted for if not supplied.

  .PARAMETER ApiKey
    Workspace ONE UEM REST API key (AW-Tenant-Code) for the target environment. Prompted for if not supplied.

  .OUTPUTS
    Log file (.log) - written to the script directory as ws1baselinereport_yyyyMMdd_HHmm.log.
    Contains the full run transcript: baseline summary (name, description, template, version,
    parent OG, assignment count), install/version/compliance summaries, baseline customizations
    and additional policies, SmartGroup assignments/exclusions, and the device compliance listing.
    See Sample_WS1BaselinesReporting_20260929_1627.log for an example.

    CSV files (.csv) - written to the script directory alongside the log, one per Baseline reported on:
    - <log-basename>_Device_Compliance_Status_<BaselineName>.csv - one row per device in the Baseline,
      with Device UUID, Device Name, Serial Number, OS Version, Last Seen, userName, Organization Group,
      Install Status, Baseline Version, Compliance Status, Reported On.
    - <log-basename>_<ComplianceLevel>_<BaselineName>.csv (e.g. NonCompliant_NotAvailable) - one row per
      non-compliant/unavailable policy setting per device, with Device UUID, Device Name, Serial Number,
      OS Version, Last Seen, User Name, Organization Group, Compliance Status, Policy Setting, Policy,
      Policy Path. See "WS1BaselinesReporting_20260929_1627_NonCompliant_NotAvailable_MS25H2.csv" for an
      example.

    See CHANGELOG.md for schema changes between versions.

  .EXAMPLE
    Provide connection parameters on command line
    powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -ApiKey RESTAPIKEY

    Prompt for connection parameters
    powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1

#>
param (
    [Parameter(Mandatory=$false)]
    [string]$username=$script:Username,

    [Parameter(Mandatory=$false)]
    [string]$password=$script:Password,

    [Parameter(Mandatory=$false)]
    [string]$OGName=$script:OGName,

    [Parameter(Mandatory=$false)]
    [string]$Server=$script:Server,

    [Parameter(Mandatory=$false)]
    [string]$ApiKey=$script:ApiKey
)
#----------------------------------------------------------[Declarations]----------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#-----------------------------------------------------------[Functions]------------------------------------------------------------

$Debug = $false
$DebugPreference = 'SilentlyContinue'
[string]$psver = $PSVersionTable.PSVersion

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path
    $current_path = "C:\Temp";
}

#Set to $true to load WS1API from disk during local testing instead of the PowerShell Gallery version.
$UseLocalWS1APIModule = $true
$LocalWS1APIModulePath = "~/GitHub/WS1API/WS1API.psm1"
if ($UseLocalWS1APIModule) {

    # --- Import Local Module ---
    Unblock-File $LocalWS1APIModulePath
    Import-Module $LocalWS1APIModulePath -Scope Local -ErrorAction Stop -PassThru -Force | Out-Null;
    Write-Host "WS1API module loaded from local path: $LocalWS1APIModulePath"

} else {

    # First, check if the final goal—the module—is already installed.
    if (-not (Get-Module -ListAvailable -Name WS1API)) {

        Write-Host "WS1API module not found. Beginning installation process..."

        # --- Prerequisite Check: NuGet Provider ---
        # This check only runs if the module needs to be installed.
        if (-not (Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue)) {
            Write-Host "Prerequisite 'NuGet' is missing. Installing NuGet provider..."
            Install-PackageProvider -Name NuGet -Force
        }

        # --- Module Installation ---
        # Now that the prerequisite is confirmed, install the main module.
        Write-Host "Installing WS1API module..."
        Install-Module -Name WS1API -Force -Scope CurrentUser

    }

    # --- Import Module ---
    # This line runs regardless, ensuring the module is loaded into the current session.
    Import-Module -Name WS1API -MinimumVersion 1.1
    Write-Host "WS1API module is ready to use."

}

#setup Report/Log file
$logFileName = [System.IO.Path]::GetFileNameWithoutExtension($PSCommandPath)
$Script:Path = Get-Log -logFileName $logFileName -current_path $current_path
$Script:pathfile = Join-Path -Path (Split-Path -Path $Script:Path -Parent) -ChildPath ([System.IO.Path]::GetFileNameWithoutExtension($Script:Path))

Write-2Report -Path $Script:Path -Message "WS1 Baseline Report" -Level "Title"

# Get Server Authentication setup for API calls
$auth = Get-ServerAuth -Server $Server -Username $Username -Password $Password -ApiKey $ApiKey -OGName $OGName

Function Get-BaselineList {
  [CmdletBinding()]
  param(
    [Parameter(Mandatory=$true)]
    [string]$Server,

    [Parameter(Mandatory=$true)]
    [string]$Auth,

    [Parameter(Mandatory=$true)]
    [string]$ApiKey,

    [Parameter(Mandatory=$true)]
    [string]$GroupUuid
  )

  $APIEndpoint = "$Server/api/mdm/groups/$GroupUuid/baselines";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Auth -Apikey $ApiKey

  return $WebRequest

}

Function ChooseBaseline {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory=$true)]
    [array]$BaselineList
  )
  #$ValidChoices = 0..($BaselineList.Count)
  $ValidChoices = 0..($BaselineList.Count -1)
  $ValidChoices += 'Q'
  Write-Host "`nPlease select a Baseline from the list:" -ForegroundColor Yellow
  $Choice = ''
  while ([string]::IsNullOrEmpty($Choice)) {

    $i = 0
    foreach ($Baseline in $BaselineList) {
      Write-Host ('{0}: {1}       {2}' -f $i, $Baseline.name, $Baseline.description)
      $i += 1
    }

    $Choice = Read-Host -Prompt 'Type the number that corresponds to the Baseline to report on or Press "Q" to quit'
    if ($Choice -in $ValidChoices) {
      if ($Choice -eq 'Q'){
        Write-2Report -Path $Script:Path -Message " Exiting Script" -Level "Footer"
        exit
      } else {

        return [PSCustomObject]@{
          BaselineName            = $BaselineList[$Choice].name
          BaselineUUID            = $BaselineList[$Choice].baselineUUID
          BaselineDescription     = $BaselineList[$Choice].description
          BaselineTemplate        = $BaselineList[$Choice].templateName
          BaselineCurrentVersion  = $BaselineList[$Choice].version
          BaselineParentOG        = $BaselineList[$Choice].rootLocationGroupName
          BaselineAssignmentCount = $BaselineList[$Choice].assignmentCount
        }
      }
    } else {
      [console]::Beep(1000, 300)
      Write-Warning ('    [ {0} ] is NOT a valid selection.' -f $Choice)
      Write-Warning '    Please try again ...'
      pause

      $Choice = ''
    }
  }
}

Function noncompliantdevices {
  #Variables
  $status = "All"
  #$status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  $compliance_level = "NonCompliant,Intermediate,NotAvailable"
  
  #Search OG Name to get OG ID
  $ogSearchResult = Invoke-OGSearch -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -OrgGroup $script:OGName

  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for a selected Baseline in $script:OGName OG" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  ##Get a list of Baselines
  $BaselineList = Get-BaselineList -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid

  #Choose a Baseline
  $SelectedBaseline = ChooseBaseline -BaselineList $BaselineList

  #Call Report Function
  Invoke-Report -status $status -compliance_level $compliance_level -Baseline $SelectedBaseline

}

Function alldevices {
  #Variables
  #$status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  $status = "All"
  $compliance_level = "Compliant,NonCompliant,Intermediate,NotAvailable"
  
  #Search OG Name to get OG ID
  $ogSearchResult = Invoke-OGSearch -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -OrgGroup $script:OGName
  
  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for a selected Baseline in $script:OGName OG" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow

  ##Get a list of Baselines
  $BaselineList = Get-BaselineList -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid

  #Choose a Baseline
  $SelectedBaseline = ChooseBaseline -BaselineList $BaselineList

  #Call Report Function
  Invoke-Report -status $status -compliance_level $compliance_level -Baseline $SelectedBaseline

}

Function alldevicesallbaselines {
  #Variables
  $status = "All"
  #$status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  $compliance_level = "Compliant,NonCompliant,Intermediate,NotAvailable"

  #Search OG Name to get OG ID
  $ogSearchResult = Invoke-OGSearch -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -OrgGroup $script:OGName

  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for all Baselines in OG $script:OGName" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  ##Get a list of Baselines
  $BaselineList = Get-BaselineList -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid

  #Choose a Baseline
  foreach ($baseline in $BaselineList){
    $SelectedBaseline = [PSCustomObject]@{
      BaselineName            = $Baseline.name
      BaselineUUID            = $Baseline.baselineUUID
      BaselineDescription     = $Baseline.description
      BaselineTemplate        = $Baseline.templateName
      BaselineCurrentVersion  = $Baseline.version
      BaselineParentOG        = $Baseline.rootLocationGroupName
      BaselineAssignmentCount = $Baseline.assignmentCount
    }

    #Call Report Function
    Invoke-Report -status $status -compliance_level $compliance_level -Baseline $SelectedBaseline
  }
}

Function Invoke-Report {
  <#
  .SYNOPSIS
  Generates the compliance/settings report for a single Baseline.
  #>
  [CmdletBinding()]
  param(
    [Parameter(Mandatory = $true)]
    [string]$status,
    
    [Parameter(Mandatory = $true)]
    [string]$compliance_level,

    [Parameter(Mandatory = $true)]
    [PSCustomObject]$Baseline
  )

  $BaselineName = $Baseline.BaselineName
  $BaselineUUID = $Baseline.BaselineUUID
  $BaselineDescription = $Baseline.BaselineDescription
  $BaselineTemplate = $Baseline.BaselineTemplate
  $BaselineCurrentVersion = $Baseline.BaselineCurrentVersion
  $BaselineParentOG = $Baseline.BaselineParentOG
  $BaselineAssignmentCount = $Baseline.BaselineAssignmentCount

  ##Get Baseline Summary
  Write-2Report -Path $Script:Path -Message "`nSummary Information for Baseline" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Baseline: $BaselineName" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Description: $BaselineDescription" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Template: $BaselineTemplate" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Current Version: $BaselineCurrentVersion" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Parent OG: $BaselineParentOG" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Assignment Count: $BaselineAssignmentCount" -Level "Body"


  $BaselineSummary = Get-BaselineSummary -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid -baselineUUID $BaselineUUID
  #$vendortemplateUUID = $BaselineSummary.vendorTemplateUUID
  #$OSVersionUUID = $BaselineSummary.osVersionUUID
  #$securityLevelUUID = $BaselineSummary.securityLevelUUID

  $installsummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}},
    @{N="Reasons";E={$_.reasons}}
  )
  $strBaselineSummaryInstalls = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty installs | Select-Object -Property $installsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "`nInstall Summary" -Level "Header"
  if([string]::IsNullOrEmpty($strBaselineSummaryInstalls)){
    Write-2Report -Path $Script:Path -Message "No Devices Assigned or Installed" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message $strBaselineSummaryInstalls -Level "Body"
  }
  $versionsummaryproperties = @(
    @{N="Count";E={$_.count}},
    @{N="Versions";E={$_.version}}
  )
  $strBaselineSummaryVersions = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty versions | Select-Object -Property $versionsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Version Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Note: Version Summary Count does not include NotAvailable devices" -Level "Body"
  if([string]::IsNullOrEmpty($strBaselineSummaryVersions)){
    Write-2Report -Path $Script:Path -Message "No Devices Assigned or Installed" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message $strBaselineSummaryVersions -Level "Body"
  }

  $compliancesummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}}
  )
  $strBaselineSummaryCompliance = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty compliance | Select-Object -Property $compliancesummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Compliance Summary" -Level "Header"
  if([string]::IsNullOrEmpty($strBaselineSummaryCompliance)){
    Write-2Report -Path $Script:Path -Message "No Devices Assigned or Installed" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message $strBaselineSummaryCompliance -Level "Body"
  }

  ##Get Baseline Customisations
  $customizationssummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Setting";E={$_.status}}
  )
  $strBaselineSummaryCustomizations = $BaselineSummary | Select-Object -ExpandProperty customizations | Select-Object -Property $customizationssummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  if([string]::IsNullOrEmpty($strBaselineSummaryCustomizations)){
    Write-2Report -Path $Script:Path -Message "No Baseline Customizations found" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message "Baseline Customizations" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineSummaryCustomizations -Level "Body"
  }

  ##Get Baseline Additional Policies
  $policysummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Setting";E={$_.status}}
  )
  $strBaselineSummaryPolicies = $BaselineSummary | Select-Object -ExpandProperty policies | Select-Object -Property $policysummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  if([string]::IsNullOrEmpty($strBaselineSummaryPolicies)){
    Write-2Report -Path $Script:Path -Message "No Baseline Additional Policies found" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message "Baseline Additional Policies" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineSummaryPolicies -Level "Body"
  }

  ##Get Baseline Assignments
  $BaselineAssignment = Get-BaselineAssignments -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid -baselineUUID $BaselineUUID
  $strBaselineAssign = $BaselineAssignment | Select-Object -ExpandProperty assigned_smart_groups
  if([string]::IsNullOrEmpty($strBaselineAssign)){
    Write-2Report -Path $Script:Path -Message "No Devices Assigned" -Level "Header"
  }else{
    $strBaselineAssignments = $BaselineAssignment | Select-Object -ExpandProperty assigned_smart_groups | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
    Write-2Report -Path $Script:Path -Message "Baseline Selected is assigned to the following SmartGroups" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineAssignments -Level "Body"  
  }
  $strBaselineExcl = $BaselineAssignment | Select-Object -ExpandProperty excluded_smart_groups
  if([string]::IsNullOrEmpty($strBaselineExcl)){
    Write-2Report -Path $Script:Path -Message "No Devices Excluded" -Level "Header"
  }else{
    $strBaselineExclusions = $BaselineAssignment | Select-Object -ExpandProperty excluded_smart_groups | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
    Write-2Report -Path $Script:Path -Message "Baseline Selected is excluded from the following SmartGroups" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineExclusions -Level "Body"
  }

  ##Get all devices in the OG once, used below to look up each device's Organization Group name
  $allDevices = Get-Devices -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid

  ##List devices in Baseline with selected Compliance Level
  Write-2Report -Path $Script:Path -Message "Devices with compliance status of $compliance_level in $BaselineName Baseline" -Level "Header"
  $TotalDevicesinBaseline = Get-DevicesInBaseline -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid -BaselineUuid $BaselineUUID 
  $max_results = $TotalDevicesinBaseline.total
  $selectDevicesinBaseline = Get-DevicesInBaseline -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid -BaselineUuid $BaselineUUID -MaxResults $max_results -status $status -ComplianceLevel $compliance_level
  $selectedDevicesinBaseline = $selectDevicesinBaseline.results

  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.friendlyName}},
    @{N="Serial Number";E={
      $deviceUuid = $_.DeviceUUID
      ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).serial_number}},
    @{N="OS Version";E={
      $deviceUuid = $_.DeviceUUID
      ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).operating_system}},
    @{N="Last Seen";E={
      $deviceUuid = $_.DeviceUUID
      ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).last_seen}},
    @{N="userName";E={$_.userName}},
    @{N="Organization Group";E={
      $deviceUuid = $_.DeviceUUID
      ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).organization_group_name}},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}},
    @{N="Reported On";E={$_.status | Select-Object -ExpandProperty reportedOn}}
  )
  $strDevicesinBaseline = $selectedDevicesinBaseline | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  if([string]::IsNullOrEmpty($strDevicesinBaseline)){
    Write-2Report -Path $Script:Path -Message "No Devices Assigned or Installed" -Level "Header"
  }else{
    Write-2Report -Path $Script:Path -Message $strDevicesinBaseline -Level "Body"
  }

<#   ##Export this list to CSV?
  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.friendlyName}},
    @{N="userName";E={$_.userName}},
    @{N="Organization Group";E={
      $deviceUuid = $_.DeviceUUID
      ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).organization_group_name
    }},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}},
    @{N="Reported On";E={$_.status | Select-Object -ExpandProperty reportedOn}}
  ) #>
  $csvLocation = $Script:pathfile+"_Device_Compliance_Status_"+$BaselineName+".csv"
  $selectedDevicesinBaseline | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

  ##Report on devices that have the baseline installed, but are non-compliant or partially compliant (Intermediate) and report on individual setting compliance
  $compliance_level = "NonCompliant,Intermediate,NotAvailable"
  Write-2Report -Path $Script:Path -Message "Settings for devices with Compliance Stats of NotAvailable or NonCompliant (includes Intermediate) with $BaselineName Baseline Installed" -Level "Header"
  $selectedNCDevicesinBaseline = $selectedDevicesinBaseline | Where-Object {($_.compliance.status -match "NonCompliant") -or ($_.compliance.status -match "NotAvailable") -or ($_.compliance.status -match "Intermediate")}
  $selectedDevicesinBaselineTotal = $selectedNCDevicesinBaseline | Measure-Object
  $selectedDevicesinBaselinetotal = $selectedDevicesinBaselineTotal.Count

  Write-2Report -Path $Script:Path -Message "Total number of devices with NotAvailable or NonCompliant Compliance Status = $selectedDevicesinBaselinetotal" -Level "Body"
  if($selectedDevicesinBaselinetotal -lt 1){
    #Write-host "Zero devices to report on, exiting."
  } else {
    Write-Host "Please wait this process can take quite some time...."
    ##Create array to store Device UUID and Name
    $devicepoliciesarray = @();
    $batch = 100;
    #$compliance_level = "All"
    $compliance_level = "NonCompliant,NotAvailable"
    $k = 1
    #$count = 1
    $l = [Math]::Ceiling($selectedDevicesinBaselinetotal / $batch)
    #(Initialize; condition to keep the loop running; iteration/repeat)
    for ($i = 0; $i -le $selectedDevicesinBaselinetotal; $i += $batch) {
      #create end index
      $j = $i + ($batch - 1)
      if ($j -ge $selectedDevicesinBaselinetotal) {
        $j = $selectedDevicesinBaselinetotal -1
      }
      Write-Host "Starting Batch $k of $l"
      #create batch
      if ($i -eq $j) {
        $myTmpObj = $selectedNCDevicesinBaseline[$i]
      } else {
        $myTmpObj = $selectedNCDevicesinBaseline[$i..$j]
      }
      #process batch
      foreach ($device in $myTmpObj) {
        $DeviceUUID = $device.deviceUUID
        $DeviceName = $device.friendlyName
        $DeviceSerialNumber = ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).serial_number
        $OSVersion = ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).operating_system
        $DeviceLastSeen = ($allDevices | Where-Object { $_.Uuid -eq $deviceUuid }).last_seen
        $DeviceUserName = $device.userName
        $DeviceOGName = ($allDevices | Where-Object { $_.Uuid -eq $DeviceUUID }).organization_group_name
        $DevicePolicies = Get-DevicePoliciesInBaseline  -Server $auth.Server -Auth $auth.Cred -ApiKey $auth.ApiKey -GroupUuid $ogSearchResult.uuid -BaselineUuid $BaselineUUID -DeviceUuid $DeviceUUID -limit 1000 -ComplianceLevel $compliance_level
        foreach ($policy in $DevicePolicies){
          $PSObject = [PSCustomObject]@{
            DeviceUUID = $DeviceUUID
            DeviceName = $DeviceName
            DeviceSerialNumber = $DeviceSerialNumber
            OSVersion = $OSVersion
            DeviceLastSeen = $DeviceLastSeen
            DeviceUserName = $DeviceUserName
            DeviceOGName = $DeviceOGName
            ComplianceStatus=$policy.compliance.status
            Policy=$policy.name
            PolicyPath=$policy.path
            PolicyStatus=$policy.status
          }
          $devicepoliciesarray += $PSObject
        }
      }
      $k++
      if($k -eq $l) {
        Start-Sleep -Seconds 60
      }
    }

    $devicepolicyproperties = @(
      @{N="Device UUID";E={$_.DeviceUUID}},
      @{N="Device Name";E={$_.DeviceName}},
      @{N="Serial Number";E={$_.DeviceSerialNumber}},
      @{N="OS Version";E={$_.OSVersion}},
      @{N="Last Seen";E={$_.DeviceLastSeen}},
      @{N="User Name";E={$_.DeviceUserName}},
      @{N="Organization Group";E={$_.DeviceOGName}},
      @{N="Compliance Status";E={$_.ComplianceStatus}},
      @{N="Policy Setting";E={$_.PolicyStatus}},
      @{N="Policy";E={$_.Policy}},
      @{N="Policy Path";E={$_.PolicyPath}}
    )
    $strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $devicepolicyproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table | Out-String
    #$strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table -AutoSize | Out-String
    Write-2Report -Path $Script:Path -Message $strdevicepoliciesarray -Level "Body"

    ##Export this list to CSV?
    $csvLocation = "$Script:pathfile"+"_"+($compliance_level -replace ",","_")+"_"+$BaselineName+".csv"
    $devicepoliciesarray | Select-Object -Property $devicepolicyproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

    Write-2Report -Path $Script:Path -Message "Completed report on $compliance_level Devices and Settings for $BaselineName Baseline in $BaselineParentOG" -Level "Footer"
    $devicepoliciesarray = @()
  }
  
}

Function Show-Menu
  {
    param ([string]$Title = 'VMware Workspace ONE UEM API Menu')
       #Clear-Host
       Write-Host "================ $Title ================"
       Write-Host "Press '1' to Run Report on Non-Compliant Devices for a selected Baseline"
       Write-Host "Press '2' to Run Report on All Devices for a selected Baseline"
       Write-Host "Press '3' to Run Report on All Devices in All Baselines"
       Write-Host "Press 'Q' to quit."
        }

do

  {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {
          #Clear-Host
          noncompliantdevices
        } 
    
    '2' {
          #Clear-Host
          alldevices
        }
    
    '3' {
          #Clear-Host
          alldevicesallbaselines
        }

    'Q' {
          Remove-Module WS1API
        }

    }
    pause
  }
  until ($selection -eq 'q') 

