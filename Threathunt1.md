
# Threat Hunt Report- "Help Desk Troubleshooting"
**November 11 2025**

<img width="637" height="156" alt="image" src="https://github.com/user-attachments/assets/677bd9f2-f2ca-4fa5-bc51-6c21779e90a9" />

## Table of Contents
1. [Scenario](## Scenario)
2. [Start Here - Identify most suspicious machine]()
3. [Usage](#usage)
4. [Troubleshooting](#troubleshooting)
5. [Conclusion](#conclusion)
## Scenario

A routine support request should have ended with a reset and reassurance. Instead, the so-called “help” left behind a trail of anomalies that don’t add up.

What was framed as troubleshooting looked more like an audit of the system itself — probing, cataloging, leaving subtle traces in its wake. Actions chained together in suspicious sequence: first gaining a foothold, then expanding reach, then preparing to linger long after the session ended.

And just when the activity should have raised questions, a neat explanation appeared — a story planted in plain sight, designed to justify the very behavior that demanded scrutiny.

This wasn’t remote assistance. It was a misdirection.

**Your mission this time is to reconstruct the timeline**, connect the scattered remnants of this “support session”, and decide what was legitimate, and what was staged.

The evidence is here. The question is whether you’ll see through the story or believe it.

**Additional Information:**
1. Multiple machines in the department started spawning processes originating from the **download** folders. This unexpected scenario occurred during the **first half of October**. 
2. Several machines were found to share the same types of files — similar executables, naming patterns, and other traits.
3. Common keywords among the discovered files included **“desk,”** **“help,”** **“support,”** and **“tool.”**
4. Intern operated machines seem to be affected to certain degree.

## Start Here - Identify most suspicious machine

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01T00:00:00Z) .. datetime(2025-10-15T23:59:59Z))
| where FolderPath contains @"C:\users"
| where FileName has_any ("desk", "support", "help", "tool") and ActionType == "FileCreated"
| where InitiatingProcessCommandLine has_any ("cmd.exe", "powershell.exe")
| project TimeGenerated, ActionType, DeviceName, FileName, FolderPath, InitiatingProcessCommandLine
| order by TimeGenerated asc

```
**Most suspicious device:**

**HostName:** gab-intern-vm   **User Account Name:** g4bri3lintern **Date:** October 9th, 2025 



<img width="1219" height="270" alt="image" src="https://github.com/user-attachments/assets/f79cbd1e-cb36-4229-ac6b-46843243a249" />


## Flag 1 – Initial Execution Detection

**Objective:**
Detect the earliest anomalous execution that could represent an entry point.

**What to Hunt:**
*Look for atypical script* or *interactive command activity* that deviates from normal user behavior or baseline patterns.

**Thought:**
Pinpointing the first unusual execution helps you anchor the timeline and follow the actor’s parent/child process chain.

**Hint:**
1. Downloads
2. Two

**Process:  I ended up using two queries to find initial execution**

**Query 1: DeviceFileEvents - Finding the suspicous file .ps1 file**

```kql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == @"gab-intern-vm" 
| where FolderPath contains @"C:\Users\g4bri3lintern\Downloads"

```

**Gathered Info:**

*Found suspicious file: SupportTool.ps1*

<img width="670" height="311" alt="image" src="https://github.com/user-attachments/assets/dcd56bcf-6be5-4eab-8978-d97ec0a113bd" />

**Query 2: DeviceProcessEvents-Finding the initial execution**

*Powershell CLI: "powershell.exe" -ExecutionPolicy Bypass -File C:\Users\g4bri3lintern\Downloads\SupportTool.ps1*


```kql

DeviceProcessEvents
| where TimeGenerated between (datetime(2025-10-01) .. datetime(2025-10-15))
| where DeviceName == @"gab-intern-vm"
| where ProcessCommandLine contains "SupportTool.ps1"
| project TimeGenerated, DeviceName, FileName, ProcessCommandLine
| order by TimeGenerated asc

```

<img width="1169" height="172" alt="image" src="https://github.com/user-attachments/assets/a0cde094-a7a1-4a4e-8d46-9ce08adc3fdc" />

## Flag 2: Defense Disabling (Simulated Tamper Indicator)








