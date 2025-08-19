# threat-hunting-tor

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

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

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user ulopez1122 downloaded a tor installer, which resulted in many tor-related files being copied to the desktop and the creation of a file called `tor-shopping-list.txt` on the desktop. These events began at: `2025-08-18T02:45:36.1535505Z`

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "edr-lab-ulises"
| where FileName contains "tor"
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountDomain
| where Timestamp >= datetime(2025-08-18T02:45:36.1535505Z)
```
<img width="549" height="125" alt="First Query" src="https://github.com/user-attachments/assets/24d4d096-f7d7-41da-ac8e-b08e274b1b53" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceFileEvents table for any ProcessCommandLine that contained the string `tor-browser-windows-x86_64-portable-14.0.1.exe`. Based on the logs returned, at `2025-08-14T07:40:24.899923Z`, a user on the `edr-lab-ulises` device ran the file `tor-browser-windows-x86_64-portable-14.5.5.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceFileEvents
| where DeviceName == "edr-lab-ulises"
| where InitiatingProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.5.exe"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessCommandLine

```
<img width="1024" height="331" alt="2nd Query" src="https://github.com/user-attachments/assets/9c1f16e5-c2b9-4178-b8c3-1837fd67d0e9" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any indication that the user actually opened the browser. There was evidence that they opened it at `2025-08-14T07:40:28.0225963Z`. There were several other instances of `firefox.exe` (Tor) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "edr-lab-ulises"
| where FileName has_any ("tor.exe", "firefox.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1021" height="337" alt="3rd Query" src="https://github.com/user-attachments/assets/c9e29f77-baf1-4499-af31-7355d488901c" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceProcessEvents table for any indication that the tor browser was used to establish a connection using any of the known tor ports. On `2025-08-18T19:32:35.8945298Z`, the user on device `edr-lab-ulises` successfully made a network connection using the process tor.exe, located in the Tor Browser folder on their desktop. The connection went out to IP address `208.113.200.37` over port `9001`, which is commonly associated with the Tor network. The `tor.exe` file can be found in the `c:\users\ulopez1122\desktop\tor browser\browser\torbrowser\tor\tor.exe` folder.

**Query used to locate events:**

```kql

DeviceNetworkEvents
| where DeviceName == "edr-lab-ulises"
| where InitiatingProcessAccountDomain != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9151")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath

```
<img width="1037" height="160" alt="4th Query" src="https://github.com/user-attachments/assets/28f4e1a7-5271-41b2-8471-903005f89cc5" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-08-18T02:45:36.1535505Z` 
- **Event:** The user "edr-lab-ulises" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`


### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-08-14T07:40:24.899923Z`
- **Event:** The user "edr-lab-ulises" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-08-14T07:40:28.0225963Z`
- **Event:** User "edr-lab-ulises" opened the TOR browser. Subsequent processes associated with the TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-08-18T19:32:35.8945298Z`
- **Event:** A network connection to IP 176.198.159.33 on port 9001 by user "employee" was established using tor.exe, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:** `2025-08-18T17:28:29.0105827Z-` Local connection to 127.0.0.1 on port 9151.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "edr-lab-ulises" through the TOR browser.
- **Action:** Multiple successful connections detected.


### 6. File Creation - TOR Shopping List

- Timestamp: `2025-08-18T19:55:14.4994248Z`
- Event: The user "edr-lab-ulises" created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- Action: File creation detected.
- File Path: `C:\Users\employee\Desktop\tor-shopping-list.txt`


---

## Summary

The user on the "edr-lab-ulises device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `edr-lab-ulises`. The device was isolated and the user's direct manager was notified.

---
