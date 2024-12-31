[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$FilePath,

    [Parameter(Mandatory=$false)]
    [string]$FilterCategory,

    [Parameter(Mandatory=$false)]
    [int[]]$DesiredEventIDs
)

function Get-EventLogsFromFile {
    param (
        [string]$File
    )
    try {
        Get-WinEvent -Path $File
    }
    catch {
        Write-Host "Failed to load the event log file. Ensure it's EVTX format." -ForegroundColor Red
        $null
    }
}

function Print-EventCategory {
    param (
        [string]$CategoryName,
        [int[]]$EventIDs,
        [System.Diagnostics.Eventing.Reader.EventLogRecord[]]$AllEvents,
        [int[]]$DesiredEventIDs
    )
    if ($DesiredEventIDs) {
        $filteredIDs = $EventIDs | Where-Object { $DesiredEventIDs -contains $_ }
    } else {
        $filteredIDs = $EventIDs
    }

    $matchedEvents = $AllEvents | Where-Object { $filteredIDs -contains $_.Id }
    if ($matchedEvents) {
        Write-Host "`n=== $CategoryName ===" -ForegroundColor Cyan
        foreach ($event in $matchedEvents) {
            $eventDetails = [PSCustomObject]@{
                Date    = $event.TimeCreated
                Log     = $event.LogName
                EventID = $event.Id
                Message = $event.Message
            }
            Write-Host "Date:     $($eventDetails.Date)"
            Write-Host "Log:      $($eventDetails.Log)"
            Write-Host "EventID:  $($eventDetails.EventID)"
            Write-Host "Message:  $($eventDetails.Message)"
            Write-Host ""
        }
    }
}

if (-not (Test-Path $FilePath)) {
    Write-Host "File not found: $FilePath" -ForegroundColor Red
    return
}

$eventLogs = Get-EventLogsFromFile -File $FilePath
if (-not $eventLogs) {
    Write-Host "No logs or invalid EVTX file." -ForegroundColor Red
    return
}

$windowsEventCategories = @{
    "Authentication Events"          = 4624,4625,4634,4648,4675,4768,4769,4771,4776,4627,4635,4649,4800,4801,4965,4770,4774
    "Account Management"             = 4720,4722,4723,4724,4725,4726,4738,4756,4757,4780,4781,4732,4733,4735,4737,4739,4740,4783,4794
    "Privilege Escalation"           = 4672,4697,4964,1102,4968,4673,4674,4969
    "Suspicious Process Activity"    = 4688,4689,4698,4699,7040,7045
    "File and Registry Monitoring"   = 4663,5145,4657,4660,4656,4658,4661,4670
    "Network Activity"               = 5156,5157,5140,4751,4752
    "Malicious Indicators"           = 4104,4103,4699,7010,7040
    "Group Policy"                   = 4739,5136,5141
    "Firewall Events"                = 5025,5027,5031,5157
    "Advanced Threats"               = 4772,4778,4779,5378,6416,7045
    "Event Forwarding and Audit Policies" = 4882,4883,4884
    "Additional Investigative IDs"   = 1100,4728,4729,4753,4765,4766,5024,5155
    "Policy & Config Changes"        = 4946,4947,4948,4950,4954,4957
    "Process & Execution Events"     = 4688,4689,4690,4691
    "Network & Firewall Events"      = 4960,4961,4963,5029,5038,5142,5143,5144
    "Malware & Advanced Threat Detection" = 7024,7030,7034,7040,8004
    "WMI Events"                     = 5861,5860,5862,5863
    "Audit Policy Changes"           = 4719,4902,4904,4905,4907,4908,4912
    "DNS & Remote Access"            = 5139,5146,5147,5148
    "Advanced Persistence"           = 5888,5890,7046,4662,4692
    "Custom & Ransomware Indicators" = 5002,5004,10000
}

$sysmonEventCategories = @{
    "Sysmon: Process Monitoring"     = 1,2,3,4,5,6,7
    "Sysmon: File Monitoring"        = 8,9,10,11
    "Sysmon: Advanced Persistence"   = 12,13,14,15,16,17,18,19,20
    "Sysmon: Image Loading"          = 21,22,23,24
    "Sysmon: Networking Activity"    = 25,26,27,28,29,30,31
    "Sysmon: Privilege Escalation"   = 32,33,34,35
    "Sysmon: Detailed Monitoring"    = 36,37,38,39
    "Sysmon: File System Activity"   = 40,41,42,43
    "Sysmon: Registry Persistence"   = 44,45,46
    "Sysmon: Command & Scripting Abuse" = 47,48,49
    "Sysmon: Network Indicators"     = 50,51,52,53,54
    "Sysmon: System-Level Activity"  = 55,56,57,58
    "Sysmon: Authentication Monitoring" = 59,60,61,62
    "Sysmon: Additional Advanced"    = 63,64,65,66,67
    "Sysmon: Indicator Detection"    = 68,69,70,71
    "Sysmon: Exploitation Indicators"= 72,73,74
    "Sysmon: Tools & Tactics"        = 75,76,77,78,79
    "Sysmon: Threat Actor Techniques"= 80,81,82
    "Sysmon: Evasion Techniques"     = 83,84,85,86
    "Sysmon: Miscellaneous"          = 87,88,89
    "Sysmon: Remaining"              = 90,91,92,93,94,95,96,97,98,99,100
}

if ($FilterCategory) {
    if ($windowsEventCategories.ContainsKey($FilterCategory)) {
        Print-EventCategory $FilterCategory $windowsEventCategories[$FilterCategory] $eventLogs $DesiredEventIDs
    }
    elseif ($sysmonEventCategories.ContainsKey($FilterCategory)) {
        Print-EventCategory $FilterCategory $sysmonEventCategories[$FilterCategory] $eventLogs $DesiredEventIDs
    }
    else {
        Write-Host "Category '$FilterCategory' not found." -ForegroundColor Yellow
    }
} else {
    foreach ($category in $windowsEventCategories.GetEnumerator()) {
        Print-EventCategory $category.Key $category.Value $eventLogs $null
    }
    foreach ($category in $sysmonEventCategories.GetEnumerator()) {
        Print-EventCategory $category.Key $category.Value $eventLogs $null
    }
}
