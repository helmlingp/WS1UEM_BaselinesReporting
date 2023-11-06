<#	
  .Synopsis
    Script to create VMware Workspace ONE Baseline Report using REST API
  .NOTES
	  Created:   	    December, 2020
	  Created by:	    Phil Helmling, @philhelmling
	  Organization:   VMware, Inc.
    Filename:       WS1BaselinesReporting.ps1
    GitHub:         https://github.com/helmlingp/WS1UEM_BaselinesReporting
    Requires        WS1API.psm1 in the same directory - https://github.com/helmlingp/WS1API
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
    Provide connection parameters on command line
    powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1 -username USERNAME -password PASSWORD -Server DESTINATION_SERVER_URL -OGName DESTINATION_OG_NAME -ApiKey RESTAPIKEY

    Prompt for connection parameters 
    powershell.exe -ep bypass -file .\WS1BaselinesReporting.ps1

#>
param (
    [Parameter(Mandatory=$false)]
    [string]$username=$script:Username,
    [Parameter(Mandatory=$false)]
    [string]$password=$script:password,
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
[string]$psver = $PSVersionTable.PSVersion

$current_path = $PSScriptRoot;
if($PSScriptRoot -eq ""){
    #default path
    $current_path = "C:\Temp";
}
Unblock-File "$current_path\WS1API.psm1"
Import-Module "$current_path\WS1API.psm1" -Scope Local -ErrorAction Stop -PassThru -Force | Out-Null;

#setup Report/Log file
$DateNow = Get-Date -Format "yyyyMMdd_HHmm";
$pathfile = "$current_path\WS1BaselinesReport_$DateNow";
$Script:logLocation = "$pathfile.log";
$Script:Path = $logLocation;
if($Debug){
  write-host "Path: $Path"
  write-host "LogLocation: $LogLocation"
}

Write-2Report -Path $Script:Path -Message "WS1 Baseline Report" -Level "Title"

Function setupServerAuth {

  if ([string]::IsNullOrEmpty($script:Server)){
      $script:Server = Read-Host -Prompt 'Enter the Workspace ONE UEM Server Name'
      $script:Username = Read-Host -Prompt 'Enter the Username'
      $script:SecurePassword = Read-Host -Prompt 'Enter the Password' -AsSecureString
      $script:ApiKey = Read-Host -Prompt 'Enter the API Key'
      $script:OGName = Read-Host -Prompt 'Enter the Organizational Group Name'
    
      #Convert the Password
      if($psver -lt 7){
        #Powershell 6 or below
        $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($script:SecurePassword)
        $script:Password = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
      } else {
        #Powershell 7 or above
        #$script:Password = ConvertFrom-SecureString -SecureString $private:SecurePassword -AsPlainText
        $script:Password = ConvertFrom-SecureString $script:SecurePassword -AsPlainText
      }
    }


  #Base64 Encode AW Username and Password
  $private:combined = $script:Username + ":" + $script:Password
  $private:encoding = [System.Text.Encoding]::ASCII.GetBytes($private:combined)
  $private:encoded = [Convert]::ToBase64String($private:encoding)
  $script:cred = "Basic $private:encoded"

  if($Debug){ 
    Write-host `n"Server Auth" 
    write-host "WS1 Host: $script:Server"
    write-host "Base64 creds: $script:cred"
    write-host "APIKey: $script:apikey"
    write-host "OG Name: $script:OGName"
  }
}

Function getBaselineList {
  $APIEndpoint = "$script:Server/api/mdm/groups/$script:groupuuid/baselines";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getDevicesinBaseline {
  param([string]$baselineUUID,
  [int]$max_results,
  [string]$status,
  [string]$compliance_level
  )

  <#  if(!$max_results){
    $max_results = 20
  }
   if(!$status){
    $status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  }
  if(!$compliance_level){
    $compliance_level="Compliant,NonCompliant,Intermediate,NotAvailable"
  } #>

  $APIEndpoint = "$script:Server/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/devices?start_index=0&sort_asc=true&max_results=$max_results&sort_by=id&status=$status&compliance_level=$compliance_level";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getDevicePolicies {
  param([string]$baselineUUID, 
  [string]$deviceUUID,
  [int]$limit,
  [string]$compliance_level
  )

  <# if(!$limit){
    $limit = 100
  }
  if(!$compliance_level){
    $compliance_level="NonCompliant,NotAvailable"
  } #>
  $APIEndpoint = "$script:Server/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/devices/$deviceUUID/policies?offset=0&sort_order=asc&limit=$limit&sort_by=compliance_level&compliance_level=$compliance_level";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest.results
}

Function getBaselineAssignments {
  param([string]$baselineUUID)
  $APIEndpoint = "$script:Server/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID/assignments";
  $ApiVersion = "2"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getBaselineSummary {
  param([string]$baselineUUID)
  $APIEndpoint = "$script:Server/api/mdm/groups/$script:groupuuid/baselines/$baselineUUID`?customizations=true&summary=true";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function getBaselineTemplateDetail {
  param([string]$vendortemplateUUID,
  [string]$OSVersionUUID,
  [string]$securityLevelUUID)
  $APIEndpoint = "$script:Server/api/mdm/baselines/templates/search/$vendortemplateUUID?osVersionUUID=$OSVersionUUID&securityLevelUUID=$securityLevelUUID&policyTree=true";
  $ApiVersion = "1"
  $WebRequest = Invoke-AWApiCommand -Method Get -Endpoint $APIEndpoint -ApiVersion $ApiVersion -Auth $Script:cred -Apikey $Script:apikey -Debug $Debug

  return $WebRequest

}

Function OGSearch {

  #may be able to check if variable exists before making API call. Will make script quicker
  $OGSearch = Get-OG -Server $script:Server -Cred $script:cred -ApiKey $script:ApiKey -OrgGroup $script:OGName -Debug $Debug
  $OGSearchOGs = $OGSearch.OrganizationGroups
  $OGSearchTotal = $OGSearch.TotalResults
  if($Debug){ 
    write-host "OGSearch: $OGSearch"
  }
  if($Null -eq $OGSearch){
    Write-2Report -Path $Script:Path -Message "Server Authentication or Server Connection Failure`n`n`tExiting" -Level "Error"
    exit
  } elseif ($OGSearchTotal -eq 1){
      $script:groupuuid = $OGSearch.OrganizationGroups[0].Uuid;
      $script:OGName = $OGSearch.OrganizationGroups[0].Name
      if($Debug){ 
        write-host "GroupUUID: $script:groupuuid"
      }
  } elseif ($OGSearchTotal -gt 1) {
      $ValidChoices = 0..($OGSearchOGs.Count -1)
      $ValidChoices += 'Q'
      Write-Host "`nMultiple OGs found. Please select an OG from the list:" -ForegroundColor Yellow
      $Choice = ''
      while ([string]::IsNullOrEmpty($Choice)) {

        $i = 0
        foreach ($OG in $OGSearchOGs) {
          Write-Host ('{0}: {1}       {2}       {3}' -f $i, $OG.name, $OG.GroupId, $OG.Country)
          $i += 1
        }

        $Choice = Read-Host -Prompt 'Type the number that corresponds to the Baseline to report on or Press "Q" to quit'
        if ($Choice -in $ValidChoices) {
          if ($Choice -eq 'Q'){
            Write-2Report -Path $Script:Path -Message " Exiting Script" -Level "Footer"
            exit
          } else {
            
            $script:groupuuid = $OGSearchOGs[$Choice].Uuid
            $script:OGName = $OGSearchOGs[$Choice].Name
            
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
}

Function ChooseBaseline {
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
        
        $script:BaselineName = $BaselineList[$Choice].name
        $script:BaselineUUID = $BaselineList[$Choice].baselineUUID
        $script:BaselineDescription = $BaselineList[$Choice].description
        $script:BaselineTemplate = $BaselineList[$Choice].templateName
        $script:BaselineCurrentVersion = $BaselineList[$Choice].version
        $script:BaselineParentOG = $BaselineList[$Choice].rootLocationGroupName
        $script:BaselineAssignmentCount = $BaselineList[$Choice].assignmentCount
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
  
  #Connect details
  setupServerAuth
  #Search OG Name to get OG ID
  OGSearch
  
  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for a selected Baseline in $script:OGName OG" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  ##Get a list of Baselines
  $BaselineList = getBaselineList

  #Choose a Baseline
  ChooseBaseline

  #Call Report Function
  report -status $status -compliance_level $compliance_level

}

Function alldevices {
  #Variables
  #$status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  $status = "All"
  $compliance_level = "Compliant,NonCompliant,Intermediate,NotAvailable"
  
  #Connect details
  setupServerAuth
  #Search OG Name to get OG ID
  OGSearch
  
  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for a selected Baseline in $script:OGName OG" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow

  ##Get a list of Baselines
  $BaselineList = getBaselineList

  #Choose a Baseline
  ChooseBaseline
  
  #Call Report Function
  report -status $status -compliance_level $compliance_level

}

Function alldevicesallbaselines {
  #Variables
  $status = "All"
  #$status = "CONFIRMED_INSTALL,CONFIRMED_REMOVAL,FAILED_REMOVAL,PENDING_REBOOT,PENDING_REMOVAL"
  $compliance_level = "Compliant,NonCompliant,Intermediate,NotAvailable"

  #Connect details
  setupServerAuth
  #Search OG Name to get OG ID
  OGSearch
  
  # Report on Devices and Settings for a selected Baseline
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  Write-2Report -Path $Script:Path -Message "`nReport on $compliance_level and Settings for a selected Baseline in a given OG" -Level "Header"
  write-host "`n********************************************************************************************************" -ForegroundColor Yellow
  ##Get a list of Baselines
  $BaselineList = getBaselineList

  #Choose a Baseline
  foreach ($baseline in $BaselineList){
    $BaselineName = $Baseline.name
    $BaselineUUID = $Baseline.baselineUUID
    $BaselineDescription = $Baseline.description
    $BaselineTemplate = $BaselineList.templateName
    $BaselineCurrentVersion = $Baseline.version
    $BaselineParentOG = $Baseline.rootLocationGroupName
    $BaselineAssignmentCount = $Baseline.assignmentCount
    
    #Call Report Function
    report -status $status -compliance_level $compliance_level
  }
}

Function report {
  param([string]$status,
  [string]$compliance_level
  )
  
  ##Get Baseline Summary
  Write-2Report -Path $Script:Path -Message "`nSummary Information for Baseline" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Baseline: $BaselineName" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Description: $BaselineDescription" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Template: $BaselineTemplate" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Current Version: $BaselineCurrentVersion" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Parent OG: $BaselineParentOG" -Level "Body"
  Write-2Report -Path $Script:Path -Message "Assignment Count: $BaselineAssignmentCount" -Level "Body"
  
  $BaselineSummary = getBaselineSummary -baselineUUID $BaselineUUID
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
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryInstalls -Level "Body"

  $versionsummaryproperties = @(
    @{N="Count";E={$_.count}},
    @{N="Versions";E={$_.version}}
  )
  $strBaselineSummaryVersions = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty versions | Select-Object -Property $versionsummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Version Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message "Note: Version Summary Count does not include NotAvailable devices" -Level "Body"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryVersions -Level "Body"

  $compliancesummaryproperties = @(
    @{N="Status";E={$_.status}},
    @{N="Count";E={$_.count}}
  )
  $strBaselineSummaryCompliance = $BaselineSummary | Select-Object -ExpandProperty summary | Select-Object -ExpandProperty compliance | Select-Object -Property $compliancesummaryproperties | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Compliance Summary" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCompliance -Level "Body"

  ##Get Baseline Customisations
  $customizationssummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Setting";E={$_.status}}
  )
  $strBaselineSummaryCustomizations = $BaselineSummary | Select-Object -ExpandProperty customizations | Select-Object -Property $customizationssummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Customizations" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryCustomizations -Level "Body"

  ##Get Baseline Additional Policies
  $policysummaryproperties = @(
    @{N="Name";E={$_.name}},
    @{N="Path";E={$_.path}},
    @{N="Setting";E={$_.status}}
  )
  $strBaselineSummaryPolicies = $BaselineSummary | Select-Object -ExpandProperty policies | Select-Object -Property $policysummaryproperties | Sort-Object -Property "Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message "Baseline Additional Policies" -Level "Header"
  Write-2Report -Path $Script:Path -Message $strBaselineSummaryPolicies -Level "Body"

  ##Get Baseline Assignments
  $BaselineAssignment = getBaselineAssignments -baselineUUID $BaselineUUID
  $strBaselineAssign = $BaselineAssignment | Select-Object -ExpandProperty assigned_smart_groups
  if($Null -eq $strBaselineAssign){
  }else{
    $strBaselineAssignments = $BaselineAssignment | Select-Object -ExpandProperty assigned_smart_groups | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
    Write-2Report -Path $Script:Path -Message "Baseline Selected is assigned to the following SmartGroups" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineAssignments -Level "Body"  
  }
  $strBaselineExcl = $BaselineAssignment | Select-Object -ExpandProperty excluded_smart_groups
  if($Null -eq $strBaselineExcl){
  }else{
    $strBaselineExclusions = $BaselineAssignment | Select-Object -ExpandProperty excluded_smart_groups | Select-Object -Property @(@{N="SmartGroup";E={$_.name}}) | Sort-Object "SmartGroup" | Format-Table -AutoSize | Out-String
    Write-2Report -Path $Script:Path -Message "Baseline Selected is excluded from the following SmartGroups" -Level "Header"
    Write-2Report -Path $Script:Path -Message $strBaselineExclusions -Level "Body"
  }

  ##List devices in Baseline with selected Compliance Level
  Write-2Report -Path $Script:Path -Message "Devices with compliance status of $compliance_level in $BaselineName Baseline" -Level "Header"
  $TotalDevicesinBaseline = getDevicesinBaseline -baselineUUID $BaselineUUID
  $max_results = $TotalDevicesinBaseline.total
  $selectDevicesinBaseline = getDevicesinBaseline -baselineUUID $BaselineUUID -max_results $max_results -status $status -compliance_level $compliance_level
  $selectedDevicesinBaseline = $selectDevicesinBaseline.results
  $deviceproperties = @(
    @{N="Device Name";E={$_.friendlyName}},
    @{N="UserName";E={$_.userName}},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}},
    @{N="Reported On";E={$_.status | Select-Object -ExpandProperty reportedOn}}
  )
  $strDevicesinBaseline = $selectedDevicesinBaseline  | Select-Object -Property $deviceproperties | Sort-Object "Device Name" | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strDevicesinBaseline -Level "Body"

  ##Export this list to CSV?
  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.friendlyName}},
    @{N="userName";E={$_.userName}},
    @{N="Install Status";E={$_.status | Select-Object -ExpandProperty status}},
    @{N="Baseline Version";E={$_.status | Select-Object -ExpandProperty version}},
    @{N="Compliance Status";E={$_.compliance | Select-Object -ExpandProperty status}},
    @{N="Reported On";E={$_.status | Select-Object -ExpandProperty reportedOn}}
  )
  $csvLocation = $pathfile+"_Device_Compliance_Status_"+$BaselineName+".csv"
  $selectedDevicesinBaseline | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

  ##Report on devices that have the baseline installed, but are non-compliant or partially compliant (Intermediate) and report on individual setting compliance
  $compliance_level = "NonCompliant,Intermediate,NotAvailable"
  Write-2Report -Path $Script:Path -Message "Settings for devices with Compliance Stats of NotAvailable or NonCompliant (includes Intermediate) with $BaselineName Baseline Installed" -Level "Header"
  $selectedNCDevicesinBaseline = $selectedDevicesinBaseline | Where-Object {($_.compliance.status -match "NonCompliant") -or ($_.compliance.status -match "NotAvailable") -or ($_.compliance.status -match "Intermediate")}
  $selectedDevicesinBaselineTotal = $selectedNCDevicesinBaseline | measure
  $selectedDevicesinBaselinetotal = $selectedDevicesinBaselineTotal.Count

  Write-2Report -Path $Script:Path -Message "Total number of devices with NotAvailable or NonCompliant Compliance Status = $selectedDevicesinBaselinetotal" -Level "Body"
  Write-host "Please wait this process can take quite some time...."

  ##Create array to store Device UUID and Name
  $devicepoliciesarray = @();
  $batch = 100;
  #$compliance_level = "All"
  $compliance_level = "NonCompliant,NotAvailable"
  $k = 1
  $count = 1
  #(Initialize; condition to keep the loop running; iteration/repeat)
  for ($i = 0; $i -le $selectedDevicesinBaselinetotal; $i += $batch) {
      #create end index
      $j = $i + ($batch - 1)
      if ($j -ge $selectedDevicesinBaselinetotal) {
        $j = $selectedDevicesinBaselinetotal -1
      }
      write-host "Starting Batch $k"
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
        write-host "getDevicePolicies for $DeviceUUID"
        $DevicePolicies = getDevicePolicies -baselineUUID $BaselineUUID -deviceUUID $DeviceUUID -limit 1000 -compliance_level $compliance_level
        foreach ($policy in $DevicePolicies){
          $PSObject = New-Object PSObject -Property @{
            DeviceUUID = $DeviceUUID
            DeviceName = $DeviceName
            Policy=$policy.name
            PolicyPath=$policy.path
            PolicyStatus=$policy.status
            ComplianceStatus=$policy.compliance.status
          }
          $devicepoliciesarray += $PSObject
        }
      }
      $k++
      sleep 60
    }

  $deviceproperties = @(
    @{N="Device UUID";E={$_.DeviceUUID}},
    @{N="Device Name";E={$_.DeviceName}},
    @{N="Policy Setting";E={$_.PolicyStatus}},
    @{N="Compliance Status";E={$_.ComplianceStatus}},
    @{N="Policy";E={$_.Policy}},
    @{N="Policy Path";E={$_.PolicyPath}}
  )
  $strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table | Out-String
  #$strdevicepoliciesarray = $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Format-Table -AutoSize | Out-String
  Write-2Report -Path $Script:Path -Message $strdevicepoliciesarray -Level "Body"

  ##Export this list to CSV?
  $csvLocation = $pathfile+"_Device_NonCompliantControls_"+$BaselineName+".csv"
  $devicepoliciesarray | Select-Object -Property $deviceproperties | Sort-Object -Property @{Expression = {"Device UUID"}; Ascending = $false} | Export-CSV $csvLocation -noTypeInformation

  Write-2Report -Path $Script:Path -Message "Completed report on $compliance_level Devices and Settings for $BaselineName Baseline in $BaselineParentOG" -Level "Footer"
  $devicepoliciesarray = @()
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

