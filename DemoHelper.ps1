#main()  

Import-Module PSPKI

<# Get the path, name and PID to the actual script #>
 # In addition, lets try and execute abpath.ps1 if it exists.
 # This allows us to execute standalone scripts in their local directory without causing problems 
 # due to paths to other files
$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptName = split-path -leaf $MyInvocation.MyCommand.Definition
$scriptPid = $Pid
Try {. $scriptPath\abspath.ps1} Catch {$absPath = $scriptPath}

<# Copy runbooks #>
. $absPath\include\Generic_SharedFunctions.ps1
. $absPath\include\Ini_SharedFunctions.ps1
. $absPath\include\RestApi_SharedFunctions.ps1

# Get Computer Name
$ThisComputerName = $env:computername

# Get Ini file Content
$Ini = Get-IniContent "$absPath\ini\$ThisComputerName_DemoHelper.ini"

<# Start a new log #>
WriteToLog -NewLog

# Even tho this script is running the DC, we need to wait for AD service
# to start because we are doing a couple of queries that will fail if AD is not completely up
# Lets just check and if the services are slow to start lets give them a couple of extra seconds
While ($True)
{
  Try
  {
    $DomainController = Get-ADDomainController -Discover -ForceDiscover
    WriteToLog "main() - Domain Controller ($($DomainController.HostName)) is available"

    $ADPingGroup = $Ini["PKI"]["TargetADGroup"]
    $ADPingGroupUsers = Get-ADGroupMember $ADPingGroup
    WriteToLog "main() - Domain is available"
    Break
  }
  Catch
  {
    $ADPingSleepTime = $Ini["Global"]["ADPingSleepTime"]
    WriteToLog "main() - ActiveDirectory is offline. Waiting $ADPingSleepTime seconds and then redriving"
    Start-Sleep -s $ADPingSleepTime
    Continue
  }
}

<# Say we are processing, thus remove the frogs on workstation #>
<# Also clear the temp directory                               #>
Remove-ItemIfExists -Path $Ini["Global"]["TargetFilename"]
Remove-ItemIfExists -Path $Ini["O365"]["WorkstationTargetFile"]
Remove-ItemIfExists -Path $Ini["PKI"]["TargetFilename-Smartcard"]
Remove-ItemIfExists -Path "$absPath\tmp\*"

<# Revoke all certificates generated for YubiKey (except for exclude list) #>
 # Note: this is one of the places where i found that if AD is not completely up and running,
 # then the query to retrieve the group membership of "SmartCard Users Group" will fail,
 # thus the need for the delay at the beginning of program
$SmartCardUsersGroup = $Ini["PKI"]["TargetADGroup"]
$SmartCardUsers = Get-ADGroupMember $SmartCardUsersGroup | select -ExpandProperty samAccountName
$Condition = '$_."Request.RequesterName" -notlike "*\'
$Filter = @()
ForEach ($SmartCardUser in $SmartCardUsers) {$Filter += "$Condition" + $SmartCardUser + '"'}
$WhereClause = $Filter -join " -and "
$WhereClause = [scriptblock]::Create($WhereClause)

$CertificateFilter = "CertificateTemplate -eq " + $Ini["PKI"]["CertificateTemplate"]
Get-CertificationAuthority | Get-IssuedRequest -Filter $CertificateFilter | Where-Object $WhereClause | Revoke-Certificate -Reason "CeaseOfOperation"

 # If we are doing Linux Onboarding, then check connectivity to the TargetServer and if
 # successful, run the script that resets things to initial state 
If (Test-Connection -computer $Ini["AutoOnboarding"]["TargetServerName"] -count 1 -quiet)
{
  WriteToLog "main() - Starting $($Ini["AutoOnboarding"]["OnboardingResetScriptName"])"
  $ArgumentList = $absPath + "\" + $Ini["AutoOnboarding"]["OnboardingResetScriptName"]
  $p = Start-Process -FilePath "powershell" -WindowStyle Minimized -ArgumentList $ArgumentList
}


<# Check state of connectivity to internet #>
If ($Ini["Global"]["UseInternet"] -eq "True") 
{ 
  If (Test-Connection -computer $Ini["Global"]["InternetHostToCheck"] -count 1 -quiet)
    {
      $InternetIsAvailable = $true
      WriteToLog "main () - Internet is up"
    } 
  Else 
    {
      $InternetIsAvailable = $false
      WriteToLog "main () - Internet is down"
    } 
} 
Else 
{
  WriteToLog "main () - UseInternet set to False"
  $InternetIsAvailable = $false
  WriteToLog "main () - Internet is down"
}

<# Check if we are provisioning O365 #>
 # If we are doing O365 Provisioning, then we need to reset things to 
 # an initial state. 1) Remove any users in the cloud service that my be hanging
 # around from a previous demo. Lets exclude users that we specifically call out
 # in the config file and also lets ignore users that are explicitly already in the 
 # O365 Licensed Users group in AD. There may be a specifc reason that we have left this
 # user in this group so lets dont do a wholesale purge of the provisioning group on the cloud 
 # service. Note: in the past, we just did a purge of the O365 Licensed Users Role in the cloud.
 # 2) We also cant wait for the cloud service to clean things up in the case where we still have
 # mailboxes provisioned in O365. Thus we need to call the O365 helper utility to delete any mailboxes
 # that may be lingering from a previous demo. Again, lets ignore the users in O365 Licensed Users AD group
If (($Ini["O365"]["ProvisionO365"] -eq "True") -and ($InternetIsAvailable))
{
  <# Log on to Centrify Cloud Service  #>
  $Username = $Ini["CentrifyCloud"]["CloudAdmin"]
  $Password = $Ini["CentrifyCloud"]["CloudAdminPassword"]
  $CloudFriendlyName = $Ini["CentrifyCloud"]["CloudFriendlyName"]
  $Uri = "https://$CloudFriendlyName.centrify.com"

  $AuthToken = GetAuthToken -Username $Username -Password $Password -Uri $Uri

  
  <# Get list of users in the O365 Provisioning Group. Lets ignore these users  #>
  $O365UsersGroupName = $Ini["O365"]["GroupName"]
  $O365Users = Get-ADGroupMember $O365UsersGroupName | select -ExpandProperty samAccountName

  <# Get UUID of the O365 Role  #>
  $O365RoleName = $Ini["CentrifyCloud"]["O365RoleName"]
  $Api = "RedRock/Query"
  $Request = "{""Script"":""SELECT ID FROM Role WHERE name = '$O365RoleName'""}"
  $Response = DoHttpPost -Auth $AuthToken -Api $Api -Request $Request -Uri $Uri
  $Results = $Response.Results | Select-Object -ExpandProperty Row | Select ID 

  foreach ($Result in $Results)
  {
    $O365RoleID = $Result.ID
  }
    
   # In earlier versions, we simply clobbered all the users in the O365 Licensed Users role
   # on the cloud service. This way we made sure that we were in a known initial state to start the demo
   # However, now we simply purge all the users in the cloud service that dont need to be there. ie not
   # explictily called out in ignore in config or member of O365 Licensed Users in AD   
  <# Build SQL query to retrieve list of users in Centrify Cloud Service, minus exclude list #>
  $UsersToIgnore = ($Ini["CentrifyCloud"]["UsersToIgnore"]).Split(",")
  $UsersToIgnore = $($UsersToIgnore + $SmartCardUsers + $O365Users | sort -Unique)
  $UsersToIgnoreCSV = $UsersToIgnore -join ","
  
  $SQL = "SELECT ID, Username FROM User WHERE username NOT LIKE '%" + '$@' + "%'"
  ForEach ($UserToIgnore in $UsersToIgnore) {$SQL += " AND username NOT LIKE '$UserToIgnore%' "}

  $Api = "RedRock/Query"
  $Request = "{""Script"":""$SQL"", ""Args"": {""Caching"":""-1""}}"
  $Response = DoHttpPost -Auth $AuthToken -Api $Api -Request $Request -Uri $Uri
  $Results = $Response.Results | Select-Object -ExpandProperty Row | Select ID, Username

  ForEach ($Result in $Results)
    {
    <# Delete users in the Centrify Cloud Service #>
      $ID = $Result.ID
      $Api = "/UserMgmt/RemoveUsers"
      $Request = "{""Users"":[""$ID""]}"
      $Response = DoHttpPost -Auth $AuthToken -Api $Api -Request $Request -Uri $Uri
    }

  <# If O365Utility program is already running, kill it  #>
   # Note: Check to see if script is already running. If it is, then kill it.
   # Again, this is a very cheap way to fix a problem
  $PidFile = $absPath + "\" + $Ini["O365"]["O365PidFilename"] 
  If (Test-Path $PidFile) 
  {
    $UtilityScriptPid = Get-Content $PidFile
    WriteToLog "O365UtilityScript is running. Killing Process: $UtilityScriptPid"
    Stop-Process -id $UtilityScriptPid
    Remove-ItemIfExists -Path $PidFile
  }

  # This utility will login to O365 and explicitly delete any users/mailboxes that are hanging around
  # from a previous demo. This is a reset of the environment
  <# Start the O365Utility to Delete the user in O365  #>
  $ArgumentList = $absPath + "\" + $Ini["O365"]["O365UtilityScriptFilename"] + " -Action DeleteAllO365Users -UsersToIgnore '$UsersToIgnoreCSV'"
  $p = Start-Process -FilePath "powershell" -WindowStyle Minimized -ArgumentList $ArgumentList

}

<# Purge any Existing WMI Subscriptions #>
Get-EventSubscriber -Force | Unregister-Event -Force


 # One of the things that i have found, is that over time, the WMI async handlers can 
 # hang in conditions where network is unreliable. If one of the WMI Async handlers hangs, 
 # then all of them hang. What i have done to try and minimize this is to have a totally different
 # process do the Onboarding and ExpiredRole deletion. The Onboarding task uses REST calls to the cloud service, thus
 # i believe this to be the reason the task hangs from time to time. Moving it to a separate
 # process seems to solve the problem. Yes, i know, its a cheap fix but it works.
<# Start the Worker Utility  #>
$WorkerScripts = ($Ini["Global"]["WorkerScripts"]).Split(",")
ForEach ($WorkerScript In $WorkerScripts)
{
  $ArgumentList = "-noexit -file " + $absPath + "\" + $WorkerScript.Trim()
  $WorkerScriptProcess = Start-Process -PassThru -FilePath "powershell.exe" -WindowStyle Minimized -ArgumentList $ArgumentList
}


$RegisterWMIEventCount = [int]($Ini["WMI"]["RegisterWMIEventCount"])
$RegisterWMIEventPath = $Ini["WMI"]["RegisterWMIEventPath"]
For ($i=1; $i -le $RegisterWMIEventCount; $i++)
{
  $Description = $Ini["WMI"]["$i.Description"]
  $EventsToMonitor = $Ini["WMI"]["$i.EventsToMonitor"]
  $EventHandlerPath = $Ini["WMI"]["$i.EventHandlerPath"]
  $EventHandlerIsMutex = $Ini["WMI"]["$i.EventHandlerIsMutex"]
  $TargetComputer = $Ini["WMI"]["$i.TargetComputer"]

  $ArgumentList = "-noexit -file " + $absPath + "\" + $RegisterWMIEventPath.Trim() + " " +
                                                                               "-Description ""$Description"" " + 
                                                                               "-EventsToMonitor ""$EventsToMonitor"" " + 
                                                                               "-EventHandlerPath ""$EventHandlerPath"" " + 
                                                                               "-EventHandlerIsMutex ""$EventHandlerIsMutex"" " +  
                                                                               "-TargetComputer ""$TargetComputer"" " 

  $WorkerScriptProcess = Start-Process -PassThru -FilePath "powershell.exe" -WindowStyle Minimized -ArgumentList $ArgumentList
}


 # Heartbeat
<# Setup timer event to fire for heartbeat #>
$HeartbeatIncrements = $Ini["Global"]["HeartbeatIncrements"]

$Code = ""
$Code = $Code + '$scriptPath = "' + $scriptPath + '"' + "`n"
$Code = $Code + '$scriptName = "' + $scriptName + '"' + "`n"
$Code = $Code + '$scriptPid = ' + $scriptPid + "`n"
$Code = $Code + '$absPath = "' + $absPath + '"' + "`n"
$Code = $Code + "`n"
$Code = $Code + '. $absPath\include\Generic_SharedFunctions.ps1' + "`n"
$Code = $Code + '. $absPath\include\Ini_SharedFunctions.ps1' + "`n"
$Code = $Code + '. $absPath\include\RestApi_SharedFunctions.ps1' + "`n"
$Code = $Code + "`n"
$Code = $Code + '$Ini = Get-IniContent "$absPath\CentrifyDemoHelper.ini"' + "`n"
$Code = $Code + 'WriteToLog "Heartbeat - $scriptName"' + "`n"
$Code = $Code + "`n"

$ScriptBlock = [scriptblock]::Create($Code)

$heartbeatTimer = New-Object System.Timers.Timer
WriteToLog "Creating TimerEvent for Heartbeat at $heartbeatIncrements seconds"
$LogLine = Register-ObjectEvent -InputObject $heartbeatTimer -EventName Elapsed -Action $ScriptBlock | out-string
WriteToLog "$LogLine"

$heartbeatTimer.Interval = ([int]$HeartbeatIncrements * 1000) 
$heartbeatTimer.AutoReset = $true
$heartbeatTimer.Enabled = $true


# The last thing we will do is to setup an async WMI watcher for the creation of a specific shutdown file
# When we get a notification that this file has been created, we initiate the shutdown process
# Kill all the running tasks and processes, and purge all of the WMI subscriptions we have set
$ShutdownFile = $absPath + "\" + $Ini["Global"]["ShutdownFilename"]

$PathArray = $ShutdownFile.Split("\")
$filename = Split-Path $ShutdownFile -leaf
$folder = Split-Path $ShutdownFile

# Create a file system watcher. This does not turn it on. We do that later in the code
$fileSystemWatcher = New-Object IO.FileSystemWatcher $folder, $filename -Property @{
 IncludeSubdirectories = $false 
 NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite'
}

# This is where we define what we want to do when the file is created. Its a Script block
# So again, we dont have access to local variables. It runs in a vaccuum.
$Code = ""
$Code = $Code + '$scriptPath = "' + $scriptPath + '"' + "`n"
$Code = $Code + '$scriptName = "' + $scriptName + '"' + "`n"
$Code = $Code + '$scriptPid = ' + $scriptPid + "`n"
$Code = $Code + '$absPath = "' + $absPath + '"' + "`n"
$Code = $Code + "`n"
$Code = $Code + '. $absPath\include\Generic_SharedFunctions.ps1' + "`n"
$Code = $Code + '. $absPath\include\Ini_SharedFunctions.ps1' + "`n"
$Code = $Code + '. $absPath\include\RestApi_SharedFunctions.ps1' + "`n"
$Code = $Code + "`n"
$Code = $Code + '$Ini = Get-IniContent "$absPath\CentrifyDemoHelper.ini"' + "`n"
$Code = $Code + "`n"
$Code = $Code + 'Remove-Item ' + $ShutdownFile + "`n" 
$Code = $Code + 'WriteToLog "Shutdown sequence started"' + "`n"
$Code = $Code + 'WriteToLog "UnRegistering WMI subscription"' + "`n"
$Code = $Code + 'Get-EventSubscriber -Force | Unregister-Event -Force' + "`n"
$Code = $Code + "`n"
$Code = $Code + '$WorkerScriptPIDPath = $absPath + "\" + $Ini["Global"]["WorkerScriptPIDPath"] + "\*.pid"' + "`n"
$Code = $Code + '$PIDFiles = Get-ChildItem $WorkerScriptPIDPath' + "`n"
$Code = $Code + 'ForEach ($PidFile In $PidFiles)' + "`n"
$Code = $Code + '{' + "`n"
$Code = $Code + '  $PidFilename = $PidFile.FullName' + "`n"
$Code = $Code + '  $MyPID = Get-Content $PidFilename' + "`n"
$Code = $Code + '  WriteToLog "Stopping process $MyPID"' + "`n"
$Code = $Code + '  Stop-Process -Id $MyPID' + "`n"
$Code = $Code + '  WriteToLog "Removing file: $PidFilename"' + "`n"
$Code = $Code + '  Remove-Item $PidFilename' + "`n" 
$Code = $Code + '}' + "`n"
$Code = $Code + 'WriteToLog "Shutdown Complete"' + "`n"
$Code = $Code + 'Exit 0' + "`n"

$ScriptBlock = [scriptblock]::Create($Code)

# This is where we actually register the WMI subscription to wait for the file to be created
$onCreated = Register-ObjectEvent $fileSystemWatcher Created -SourceIdentifier FileCreated -Action $ScriptBlock



<# Update status that we are done processing. Copy Frog to workstation #>
UpdateStatus -Done
WriteToLog "Waiting for Events"

