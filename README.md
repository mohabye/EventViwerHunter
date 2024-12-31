# EventViwerHunter
# PhoenixHunter

## Overview
**PhoenixHunter** is a PowerShell tool for analyzing Windows Event Logs to detect threats and anomalies. It supports parsing `.evtx` files and categorizing logs for efficient threat hunting.

## Features
- Parses `.evtx` files.
- Detects suspicious activities (e.g., privilege escalation, malicious indicators).
- Supports Windows and Sysmon event categories.
- Filters by category and Event IDs.

## Usage
### Basic
```powershell
. PhoenixHunter.ps1 -FilePath "C:\Logs\MyLog.evtx"
```
### Filter by Category
```powershell
. PhoenixHunter.ps1 -FilePath "C:\Logs\MyLog.evtx" -FilterCategory "Sysmon: Miscellaneous"
```
### Filter by Event IDs
```powershell
. PhoenixHunter.ps1 -FilePath "C:\Logs\MyLog.evtx" -FilterCategory "Sysmon: Miscellaneous" -DesiredEventIDs 90,95
```


## Output
Sample:
```plaintext
![image](https://github.com/user-attachments/assets/26ae5d5b-88e6-4cab-8d0f-68e935880026)

![image](https://github.com/user-attachments/assets/29ea939f-d551-415a-9d63-669edbc474a4)



## Contributions
Submit issues or pull requests on GitHub.
