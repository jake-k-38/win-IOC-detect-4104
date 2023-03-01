# Win-IOC-Detect-4104
Search 4104 event logs for exploitation attempts with variety of output methods including SysLog support.
## Table of contents
* [General info](#general-info)
* [Getting started](#getting-started)
* [Usage](#usage)

## General info
The script scans Windows event viewer logs for indicators of exploitation attempts using Powershell's Get-WinEvent EventID: 4104. The script can be used to output the collected information in variety of methods including JSON, HTML, CSV, and SysLog support.

TL;DR search 4104 event logs for exploitation attempts with customizable patterns in txt file.
	
## Getting started
Users may need to change the default PowerShell execution policy. This can be achieved in a number of different ways:<br />

Open a command prompt and run ```powershell.exe -ExecutionPolicy Unrestricted``` and run scripts from that PowerShell session.<br />
Open a PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted -Scope Process``` and run scripts from the current PowerShell session.<br />
Open an administrative PowerShell prompt and run ```Set-ExecutionPolicy Unrestricted``` and run scripts from any PowerShell session.<br />

Keep in mind the script requires certain security audit logging enabled to function and extract suspicious activity!!<br />

<b>REQUIRES Powershell Script Block Logging. Audit event 4104: Log name: Microsoft-Windows-PowerShell/Operational</b><br />

## Usage
Simply just run the script PsEvtScanner.ps1 to scan live event logs with an option to send data via syslog by providing IP
```
.\PSEvtScanner.ps1 <ip>
```
```
.\PsEvtScanner.ps1 | Format-List
```
```
.\PsEvtScanner.ps1 | Format-Table
```
```
.\PsEvtScanner.ps1 | Out-GridView
```
```
.\PsEvtScanner.ps1 | ConvertTo-Html
```
```
.\PsEvtScanner.ps1 | ConvertTo-Json
```
## Notes
