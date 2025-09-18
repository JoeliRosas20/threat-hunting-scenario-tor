<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/JoeliRosas20/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “jrosas” downloaded a tor installer, did something that resulted in many TOR-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at: `2025-09-17T01:25:10.4949111Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName contains "joel-final-mde-"
| where InitiatingProcessAccountName == "jrosas"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-09-17T01:25:10.4949111Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1657" height="432" alt="image" src="https://github.com/user-attachments/assets/8392627b-8c27-46ef-b506-086dbe9e82ce" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any `ProcessCommandLine` that started with the string “tor-browser”. Based on the logs returned, at `9:32 PM on September 16, 2025`, on the computer named “joel-final-mde”, the user “jrosas” ran an installer called `tor-browser-windows-x86\_64-portable-14.5.7.exe` from their “Downloads” folder using a silent install command.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName contains "joel-final-mde-"
| where ProcessCommandLine startswith "tor-browser"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1671" height="193" alt="image" src="https://github.com/user-attachments/assets/41ff8a99-dcb3-4e89-8d54-7da928da536c" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that user “jrosas” actually opened the tor browser. There was evidence that they did open it at `2025-09-17T01:25:10.4949111Z`. There were several others instances of firefox.exe (Tor) as well as `tor.exe` spawned afterwards. 

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "joel-final-mde-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1656" height="437" alt="image" src="https://github.com/user-attachments/assets/63b57a41-c5f1-4a77-b7aa-cf083b1701da" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports.  At `9:36 PM on September 16, 2025`, on the computer named “joel-final-mde”, the user “jrosas” used “tor.exe” from their “Desktop” to successfully connect to the remote IP address `103.209.24.218` on port `9001`, which is commonly used for TOR network traffic.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "joel-final-mde-"
| where Timestamp >= datetime(2025-09-17T01:25:10.4949111Z)
| where InitiatingProcessAccountName != "system"
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1647" height="441" alt="image" src="https://github.com/user-attachments/assets/a0aba698-9844-41fb-a159-d709f85a3a0e" />

---

## Chronological Event Timeline 

### September 16, 2025 – Initial Activity

- **21:25:10 (9:25 PM)** – User jrosas downloaded tor-browser-windows-x86_64-portable-14.5.7.exe into their Downloads folder (C:\Users\jrosas\Downloads\...).

- **21:27:22 (9:27 PM)** – Multiple file modifications occurred in the system temp folder, linked to extraction/unpacking activities (chrome_Unpacker_BeginUnzip...).

- **21:32:41 (9:32 PM)** – The Tor Browser installer (tor-browser-windows-x86_64-portable-14.5.7.exe) was executed by jrosas using a silent install command.

### September 16, 2025 – Network Usage

- **21:36:15 (9:36 PM)** – Process tor.exe running from the Tor Browser installation directory successfully established a network connection to remote IP 103.209.24.218 over port 9001, which is a known Tor network relay port. This confirms active Tor usage.

### September 17, 2025 – Post-Install File & Process Activity

- **01:25:10 (1:25 AM)** – Logs show multiple Tor-related processes (tor.exe, firefox.exe, and possibly tor-browser.exe) being executed by user jrosas.

- Around the same time, several Tor-related files were created/copied to the desktop, including a suspicious file named tor-shopping-list.txt.

---

## Summary

User jrosas downloaded and silently installed the Tor Browser on `September 16, 2025 at 9:32 PM`. Within minutes, the browser’s background process `(tor.exe)` connected to a known Tor relay server on port `9001`, confirming network usage. By the early hours of `September 17, 2025 (1:25 AM)`, additional Tor-related processes were observed running, along with multiple file writes to the desktop. One notable file was `tor-shopping-list.txt`, which may suggest intentional usage beyond casual browsing. Overall, the user not only installed the Tor Browser but also successfully connected to the Tor network and engaged in follow-up activity (process executions and file creation), indicating sustained usage rather than accidental execution.

---

## Response Taken

TOR usage was confirmed on endpoint `joel-final-mde-` by the user `jrosas`. The device was isolated and the user's direct manager was notified.

---
