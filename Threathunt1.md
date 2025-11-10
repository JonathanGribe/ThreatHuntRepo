
# Threat Hunt Report- "Help Desk Troubleshooting"
**November 11 2025**

<img width="637" height="156" alt="image" src="https://github.com/user-attachments/assets/677bd9f2-f2ca-4fa5-bc51-6c21779e90a9" />

## Table of Contents

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


<img width="1218" height="273" alt="image" src="https://github.com/user-attachments/assets/794b2c1a-296e-48d2-8c9d-a89aca2642a1" />

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

**Gathered Info:**
<img width="1147" height="184" alt="image" src="https://github.com/user-attachments/assets/ea2b09ff-40c5-4536-99da-c7099b4de70c" />





