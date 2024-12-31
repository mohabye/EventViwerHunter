![image](https://github.com/user-attachments/assets/24c224fc-753c-4521-bd9c-332d93fb9141)# EventViwerHunter
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
```plaintext
=== Authentication Events ===
Date:     12/31/2024 10:15:00 AM
Log:      Security
EventID:  4625
Message:  An account failed to log on.
```
## Contributions
Submit issues or pull requests on GitHub.

![image](https://github.com/user-attachments/assets/a48368b6-1457-4214-ba11-b565e8511864)


![image](https://github.com/user-attachments/assets/467b0071-303e-4513-b330-fa219c43f3a3)


