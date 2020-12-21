<#	
  .Synopsis
    Script to create VMware Workspace ONE Baseline Report using REST API
  .NOTES
	  Created:   	    December, 2020
	  Created by:	    Phil Helmling, @philhelmling
	  Organization:   VMware, Inc.
    Filename:       WS1BaselinesReporting.ps1
    Requires WS1API.psm1 in the same directory
  .DESCRIPTION
    Writes output to Log file and Device Policy setting status to CSV for selected Baseline.
    Log and CSV written to same directory as script.

    Will ask for the following details:
    - Workspace ONE UEM Server Name
    - Username to authenticate
    - Password to above user
    - AW-Tenent-Key (API Key)
    - Organizational Group Name (will search using beginning of name not case sensitive)
    
  .EXAMPLE
    powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1

#>
#----------------------------------------------------------[Declarations]----------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#-----------------------------------------------------------[Functions]------------------------------------------------------------

$Debug = $false

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path
    $current_path = "C:\Temp";
}
Unblock-File "$current_path\WS1API.psm1"
Import-Module "$current_path\WS1API.psm1" -ErrorAction Stop -PassThru -Force;

#setup Report/Log file
$DateNow = Get-Date -Format "yyyyMMdd_hhmm";
$pathfile = "$current_path\WS1BaselinesReport_$DateNow";
$logLocation = "$pathfile.log";
$Script:Path = $logLocation;

$Script:Path

if ($Debug){"LogLocation: $logLocation"}

Write-2Report -Path $Script:Path -Message "WS1 Baseline Report" -Level "Title"

Function setupServerAuth {

  if ([string]::IsNullOrEmpty($script:WSOServer)){
    if ($Debug){
      $script:WSOServer = "https://asXXX.awmdm.com"
      $script:Username = 'username'
      $script:UnsecurePassword = 'password'
      $script:ApiKey = 'Groups & Settings > All Settings > System > Advanced > API > Rest API'
      $script:OrgGroup = 'OGNAME'
    }else{

      $script:WSOServer = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
      $private:Username = Read-Host -Prompt 'Enter the Username'
      $private:Password = Read-Host -Prompt 'Enter the Password' -AsSecureString
      $script:ApiKey = Read-Host -Prompt 'Enter the API Key'
      $script:OrgGroup = Read-Host -Prompt 'Enter the Organizational Group Name'

      #Convert the Password
      $private:UnsecurePassword = ConvertFrom-SecureString -SecureString $private:Password -AsPlainText
    }
    #Base64 Encode AW Username and Password
    $private:combined = $private:Username + ":" + $private:UnsecurePassword
    $private:encoding = [System.Text.Encoding]::ASCII.GetBytes($private:combined)
    $private:encoded = [Convert]::ToBase64String($private:encoding)
    $script:cred = "Basic $private:encoded"

    if($Debug){ 
      Write-host `n"Calling setupServerAuth" 
      write-host "WS1 Host: $script:WSOServer"
      write-host "Base64 creds: $script:cred"
      write-host "APIKey: $script:apikey"
      write-host "OG Name: $script:OrgGroup"
    }

    $OGSearch = Get-OG -WSOServer $script:WSOServer -Cred $script:cred -ApiKey $script:ApiKey -OrgGroup $script:OrgGroup -Debug $Debug
    $script:groupuuid = $OGSearch.OrganizationGroups[0].Uuid;
    if($Debug){ 
      write-host "GroupUUID: $script:groupuuid"
    }
  }
}

Function getBaselineList {
  $APIEndpoint = "$script:WSOServer/api/mdm/groups/$script:groupuuid/baselines";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getDevicesinBaseline {
  param([string]$baselineUUID)
  $APIEndpoint = "$WSOServer/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/devices";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest.results

}

Function getDevicePolicies {
  param([string]$baselineUUID, [string]$deviceUUID)
  $APIEndpoint = "$WSOServer/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/devices/$deviceUUID/policies";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest.results
}

Function getBaselineAssignments {
  param([string]$baselineUUID)
  $APIEndpoint = "$WSOServer/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/assignments";
  $ApiVersion = "2"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getBaselineSummary {
  param([string]$baselineUUID)
  $APIEndpoint = "$WSOServer/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID`?customizations=true&summary=true";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

function noncompliantdevices {
  # Report on Non-Compliant Devices and Settings for a selected Baseline
  write-host "******************************************************************************" -ForegroundColor Cyan
  write-host "`n Report on Non-Compliant Devices and Settings for a selected Baseline in a given OG" -ForegroundColor Cyan
  write-host "`n******************************************************************************" -ForegroundColor Cyan
  Write-2Report -Path $Script:Path -Message "`nReport on Non-Compliant Devices and Settings for a selected Baseline in a given OG" -Level "Header"
  Write-Host "`nPlease select a Baseline" -ForegroundColor Yellow

  #Connect details
  setupServerAuth

  ##Get a list of Baselines
  $BaselineList = getBaselineList

  $ValidChoices = 0..($BaselineList.Count -1)

  $Choice = ''
  while ([string]::IsNullOrEmpty($Choice)) {
    $i = 0
    foreach ($Baseline in $BaselineList) {
      Write-Host ('{0}: {1}       {2}' -f $i, $Baseline.name, $Baseline.description)
      $i += 1
    }

    $Choice = Read-Host -Prompt 'Please choose one of the above items by number '
    if ($Choice -in $ValidChoices) {
        $BaselineName = $BaselineList[$Choice].name
        $BaselineUUID = $BaselineList[$Choice].baselineUUID
        $BaselineDescription = $BaselineList[$Choice].description
        $BaselineTemplate = $BaselineList[$Choice].templateName
        $BaselineCurrentVersion = $BaselineList[$Choice].version
        $BaselineParentOG = $BaselineList[$Choice].rootLocationGroupName
        $BaselineAssignmentCount = $BaselineList[$Choice].assignmentCount
      } else {
        [console]::Beep(1000, 300)
        Write-Warning ('    [ {0} ] is NOT a valid selection.' -f $Choice)
        Write-Warning '    Please try again ...'
        pause

        $Choice = ''
      }
  }
  
  ##Get Baseline Summary
  Write-2Report -Path $Script:Path -Message "`nSummary Information for Baseline" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Baseline: $BaselineName" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Description: $BaselineDescription" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Template: $BaselineTemplate" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Current Version: $BaselineCurrentVersion" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Parent OG: $BaselineParentOG" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Assignment Count: $BaselineAssignmentCount" -Level "Body"
  
  $BaselineSummary = getBaselineSummary -baselineUUID $BaselineUUID

  $installsummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}},
    @{N="Reasons";E={$_.reasons}}
  )
  $strBaselineSummaryInstalls = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty installs | Select-Object -Property $installsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "`nInstall Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryInstalls -Level "Body"

  $versionsummaryproperties = @(
    @{N="Count";E={$_.count}},
    @{N="Versions";E={$_.version}}
  )
  $strBaselineSummaryVersions = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty versions | Select-Object -Property $versionsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Version Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryVersions -Level "Body"

  $compliancesummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}}
  )
  $strBaselineSummaryCompliance = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty compliance | Select-Object -Property $compliancesummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Compliance Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCompliance -Level "Body"

 $customizationssummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Status";E={$_.status}}
  )
  $strBaselineSummaryCustomizations = $BaselineSummary | Select-Object -ExpandProperty customizations | Select-Object -Property $customizationssummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Customizations" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCustomizations -Level "Body"

  $policysummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Status";E={$_.status}}
  )
  $strBaselineSummaryPolicies = $BaselineSummary | Select-Object -ExpandProperty policies | Select-Object -Property $policysummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Additional Policies" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryPolicies -Level "Body"

  ##Get Baseline Assignments
  $BaselineAssignment = getBaselineAssignments -baselineUUID $BaselineUUID
  $strBaselineAssignments = $BaselineAssignment | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Selected is assigned" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineAssignments -Level "Body"
  Write-2Report -Path $Script:Path -Message "Note:Exclusions available in 2101 release" -Level "Body"

  ##Get devices in Baseline
  $DevicesinBaseline = getDevicesinBaseline -baselineUUID $BaselineUUID
  $selectnoncompliantDevicesinBaseline = $DevicesinBaseline | Where-Object {$_.compliance.status -eq "Non-Compliant" -or $_.compliance.status -eq "Intermediate" -or $_.compliance.status -eq "NotAvailable"}
  Write-2Report -Path $Script:Path -Message "Non-Compliant, Intermediate & NotAvailable devices in $BaselineName Baseline" -Level "Header"
  
  $deviceproperties = @(
    @{N="Device Name";E={$_.friendlyName}},
    @{N="userName";E={$_.userName}},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}}
  )
  #$strDevicesinBaseline = $DevicesinBaseline | Where-Object {$_.compliance.status -eq "Non-Compliant" -or $_.compliance.status -eq "Intermediate" -or $_.compliance.status -eq "NotAvailable"} | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  $strDevicesinBaseline = $selectnoncompliantDevicesinBaseline  | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strDevicesinBaseline -Level "Body"

  #Create array to store Device UUID and Name
  $devicepoliciesarray = @()
  foreach ($device in $selectnoncompliantDevicesinBaseline){
    $DeviceUUID = $device.deviceUUID
    $DeviceName = $device.friendlyName
    $DevicePolicies = getDevicePolicies -baselineUUID $BaselineUUID -deviceUUID $DeviceUUID
    foreach ($policy in $DevicePolicies){

      $PSObject = New-Object PSObject -Property @{
        DeviceUUID = $DeviceUUID
        DeviceName = $DeviceName
        Policy=$policy.name
        PolicyPath=$policy.path
        ComplianceStatus=$policy.compliance.status
      }
      $devicepoliciesarray += $PSObject
    }
  }

  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.DeviceName}},
    @{N="Policy";E={$_.Policy}},
    @{N="PolicyPath";E={$_.PolicyPath}},
    @{N="Compliance Status";E={$_.ComplianceStatus}}
  )
  $strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strdevicepoliciesarray -Level "Body"

  #Export this list to CSV?
  $csvLocation = $pathfile+"_"+$BaselineName+".csv"
  $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

  Write-2Report -Path $Script:Path -Message "Completed report on Non-Compliant Devices and Settings for $BaselineName Baseline in $BaselineParentOG" -Level "Footer"
  $devicepoliciesarray = @()
}

function alldevices {
  # Report on Non-Compliant Devices and Settings for a selected Baseline
  write-host "******************************************************************************" -ForegroundColor Cyan
  write-host "`n Reporting on All Devices for a selected Baseline in given OG" -ForegroundColor Cyan
  write-host "`n******************************************************************************" -ForegroundColor Cyan
  Write-2Report -Path $Script:Path -Message "`nReporting on All Devices for a selected Baseline in given OG" -Level "Header"
  Write-Host "`nPlease select a Baseline" -ForegroundColor Yellow

  #Connect details
  setupServerAuth

  ##Get a list of Baselines
  $BaselineList = getBaselineList

  $ValidChoices = 0..($BaselineList.Count -1)

  $Choice = ''
  while ([string]::IsNullOrEmpty($Choice)) {
    $i = 0
    foreach ($Baseline in $BaselineList) {
      Write-Host ('{0}: {1}       {2}' -f $i, $Baseline.name, $Baseline.description)
      $i += 1
    }

    $Choice = Read-Host -Prompt 'Please choose one of the above items by number '
    if ($Choice -in $ValidChoices) {
        $BaselineName = $BaselineList[$Choice].name
        $BaselineUUID = $BaselineList[$Choice].baselineUUID
        $BaselineDescription = $BaselineList[$Choice].description
        $BaselineTemplate = $BaselineList[$Choice].templateName
        $BaselineCurrentVersion = $BaselineList[$Choice].version
        $BaselineParentOG = $BaselineList[$Choice].rootLocationGroupName
        $BaselineAssignmentCount = $BaselineList[$Choice].assignmentCount
      } else {
        [console]::Beep(1000, 300)
        Write-Warning ('    [ {0} ] is NOT a valid selection.' -f $Choice)
        Write-Warning '    Please try again ...'
        pause

        $Choice = ''
      }
  }
  
  ##Get Baseline Summary
  Write-2Report -Path $Script:Path -Message "`nSummary Information for Baseline" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Baseline: $BaselineName" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Description: $BaselineDescription" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Template: $BaselineTemplate" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Current Version: $BaselineCurrentVersion" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Parent OG: $BaselineParentOG" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Assignment Count: $BaselineAssignmentCount" -Level "Body"
  
  $BaselineSummary = getBaselineSummary -baselineUUID $BaselineUUID

  $installsummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}},
    @{N="Reasons";E={$_.reasons}}
  )
  $strBaselineSummaryInstalls = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty installs | Select-Object -Property $installsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "`nInstall Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryInstalls -Level "Body"

  $versionsummaryproperties = @(
    @{N="Count";E={$_.count}},
    @{N="Versions";E={$_.version}}
  )
  $strBaselineSummaryVersions = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty versions | Select-Object -Property $versionsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Version Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryVersions -Level "Body"

  $compliancesummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}}
  )
  $strBaselineSummaryCompliance = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty compliance | Select-Object -Property $compliancesummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Compliance Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCompliance -Level "Body"

 $customizationssummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Status";E={$_.status}}
  )
  $strBaselineSummaryCustomizations = $BaselineSummary | Select-Object -ExpandProperty customizations | Select-Object -Property $customizationssummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Customizations" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCustomizations -Level "Body"

  $policysummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Status";E={$_.status}}
  )
  $strBaselineSummaryPolicies = $BaselineSummary | Select-Object -ExpandProperty policies | Select-Object -Property $policysummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Additional Policies" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryPolicies -Level "Body"

  ##Get Baseline Assignments
  $BaselineAssignment = getBaselineAssignments -baselineUUID $BaselineUUID
  $strBaselineAssignments = $BaselineAssignment | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Selected is assigned" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineAssignments -Level "Body"
  Write-2Report -Path $Script:Path -Message "Note:Exclusions available in 2101 release" -Level "Body"

  ##Get devices in Baseline
  $DevicesinBaseline = getDevicesinBaseline -baselineUUID $BaselineUUID
  $selectnoncompliantDevicesinBaseline = $DevicesinBaseline #| Where-Object {$_.compliance.status -eq "Non-Compliant" -or $_.compliance.status -eq "Intermediate" -or $_.compliance.status -eq "NotAvailable"}
  Write-2Report -Path $Script:Path -Message "All devices in $BaselineName Baseline" -Level "Header"
  
  $deviceproperties = @(
    @{N="Device Name";E={$_.friendlyName}},
    @{N="userName";E={$_.userName}},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}}
  )
  #$strDevicesinBaseline = $DevicesinBaseline | Where-Object {$_.compliance.status -eq "Non-Compliant" -or $_.compliance.status -eq "Intermediate" -or $_.compliance.status -eq "NotAvailable"} | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  $strDevicesinBaseline = $selectnoncompliantDevicesinBaseline  | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strDevicesinBaseline -Level "Body"

  #Create array to store Device UUID and Name
  $devicepoliciesarray = @()
  foreach ($device in $selectnoncompliantDevicesinBaseline){
    $DeviceUUID = $device.deviceUUID
    $DeviceName = $device.friendlyName
    $DevicePolicies = getDevicePolicies -baselineUUID $BaselineUUID -deviceUUID $DeviceUUID
    foreach ($policy in $DevicePolicies){

      $PSObject = New-Object PSObject -Property @{
        DeviceUUID = $DeviceUUID
        DeviceName = $DeviceName
        Policy=$policy.name
        PolicyPath=$policy.path
        ComplianceStatus=$policy.compliance.status
      }
      $devicepoliciesarray += $PSObject
    }
  }

  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.DeviceName}},
    @{N="Policy";E={$_.Policy}},
    @{N="PolicyPath";E={$_.PolicyPath}},
    @{N="Compliance Status";E={$_.ComplianceStatus}}
  )
  $strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strdevicepoliciesarray -Level "Body"

  #Export this list to CSV?
  $csvLocation = $pathfile+"_"+$BaselineName+".csv"
  $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

  Write-2Report -Path $Script:Path -Message "Completed report on All Devices and Settings for $BaselineName Baseline in $BaselineParentOG" -Level "Footer"
  $devicepoliciesarray = @()
}

function Show-Menu
  {
    param ([string]$Title = 'VMware Workspace ONE UEM API Menu')
       #Clear-Host
       Write-Host "================ $Title ================"
       Write-Host "Press '1' to Report on Non-Compliant Devices and Settings for a selected Baseline"
       Write-Host "Press '2' to Reporting on Compliant & Non-Compliant Devices for a selected Baseline"
       #Write-Host "Press '99' to clear cached connection details"
       Write-Host "Press 'Q' to quit."
        }

do

  {
    Show-Menu
    $selection = Read-Host "Please make a selection"
    switch ($selection)
    {
    
    '1' {
          Clear-Host
          noncompliantdevices
        } 
    
    '2' {
          Clear-Host
          alldevices
        }
    
    #'99' {
    #      clearcache
    #    }
    }
    pause
  }
  until ($selection -eq 'q') 

