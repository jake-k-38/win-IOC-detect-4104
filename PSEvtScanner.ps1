#Requires -RunAsAdministrator

<#
.SYNOPSIS
Window Event 4104 IOC Detection Script
.DESCRIPTION
TL;DR the script will search 4104 event logs for exploitation attempts on machine.
Feel free to incorporate more patterns to detect additional dangerous patterns observed in the wild. 
*Use it on live system*
*Syslog support*
.EXAMPLE
PS> . .\PSEvtScanner.ps1
Run the script with default settings search live local logs and allowing a variety of output methods and types, including JSON, HTML, CSV, etc

PS> . .\PSEvtScanner.ps1 "IP"
Run the script with syslog via IP parameter
.NOTES
#>

# Syslog functionality from https://github.com/dfirale/evtscanner
param ([Parameter(Mandatory=$false)]$ip)

# Get current timestamp when the log was analyzed
$getdate   = Get-Date -UFormat "%Y %b %d %R:%S"
$timestamp = $getdate.replace(".",":")

# Syslog parameters 
$UdpClient = New-Object System.Net.Sockets.UdpClient
$adr       = $ip
$Port      = "514"

# Syslog + message function
# https://github.com/dfirale/evtscanner
Function Send-Syslog {
    param(
        [Parameter()][string]$Parameter1,
        [Parameter()][string]$Parameter2,
        [Parameter()][string]$Parameter3,
        [Parameter()][string]$Parameter4,
        [Parameter()][string]$Parameter5,
        [Parameter()][string]$Parameter6,
        [Parameter()][string]$Parameter7
    )

    # The actual message format with parameters
    $msg       = "$time WinEvtLog: $channel`: EVENT-ID($id)`: $provider`: COMPUTER: $computer`: $message CollectTime: $timestamp"
    $bytearray = $([System.Text.Encoding])::ASCII.GetBytes($msg)
    $UdpClient.Connect($adr,$Port)
    $UdpClient.Send($bytearray, $bytearray.length) | out-null
}

# Parameters for Send-Syslog function. Needed for messages
$Parameters = @{
    Parameter1 = $time
    Parameter2 = $channel
    Parameter3 = $id
    Parameter4 = $provider
    Parameter5 = $computer
    Parameter6 = $message
    Parameter7 = $timestamp
}

$winPSFilter = @{
  LogName = 'Microsoft-Windows-PowerShell/Operational'
  ID = 4104 #Powershell Scriptblock - Execute a Remote Command
}

$winPSFilter2 = @{
  LogName = 'Windows PowerShell'
  ID = 400 #Powershell Classic log - find any downgrade attacks
}

$psIOC = New-Object System.Collections.ArrayList

$CurrentPath = Get-Location

# Regexes from https://github.com/splunk/security_content/blob/develop/detections/endpoint/powershell_4104_hunting.yml
# Importing content from file to avoid powershell blocked command warnings
$4104patterns = @([IO.File]::ReadLines("$CurrentPath\4104patterns.txt")) 

# Syslog support idea from https://github.com/dfirale/evtscanner
Get-WinEvent -FilterHashtable $winPSFilter | Foreach-Object {
    $entry            = [xml]$_.ToXml()
    $provider         = $entry.Event.System.Provider.Name
    $id               = $entry.Event.System.EventID
    $time             = $entry.Event.System.TimeCreated.SystemTime
    $channel          = $entry.Event.System.Channel
    $computer         = $entry.Event.System.Computer
    $message          = $_."Message" -replace "\r\n"," " -replace "\s"," "
    $scriptblocktext  = $entry.SelectSingleNode("//*[@Name='ScriptBlockText']")."#text"

    foreach ($pattern in $4104patterns) {
        if ($scriptblocktext -match ($pattern)) {
            $psIOC.Add($_) > $null
            if ($ip -ne $null){ Send-Syslog @Parameters }
        }
    }
}

# Original idea from Lee Holmes https://www.leeholmes.com/detecting-and-preventing-powershell-downgrade-attacks/
Get-WinEvent -FilterHashtable $winPSFilter2 | Foreach-Object {
    $entry            = [xml]$_.ToXml()
    $provider         = $entry.Event.System.Provider.Name
    $id               = $entry.Event.System.EventID
    $time             = $entry.Event.System.TimeCreated.SystemTime
    $channel          = $entry.Event.System.Channel
    $computer         = $entry.Event.System.Computer
    $message          = $_.Message -replace "\r\n"," " -replace "\s"," "
    $version          = [Version] ($_.Message -replace '(?s).*EngineVersion=([\d\.]+)*.*','$1')

    if($version -lt ([Version] "5.0")) {
        $psIOC.Add($_) > $null
        if ($ip -ne $null){ Send-Syslog @Parameters }
    }
}

$psIOC
