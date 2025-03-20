<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/csingl202/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md )

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls, because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-03-19T18:51:15.7253841Z`. These events began at `2025-03-19T18:50:59.3332144Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "ovrsr"  
| where InitiatingProcessAccountName == "sperl"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2025-03-19T18:50:59.3332144Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
 ![image](https://github.com/user-attachments/assets/2f694e59-e325-4705-8f1f-d1b60a6a1391)


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.7.exe". Based on the logs returned, at `2025-03-19T18:51:47.3679962Z`, an employee on the "ovrsr" device ran the file `tor-browser-windows-x86_64-portable-14.0.7.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "ovrsr"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.7.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine, FolderPath, SHA256
```
 ![image](https://github.com/user-attachments/assets/74e5e033-994e-4f24-a852-dc8c173256ee)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "sperl" actually opened the TOR browser. There was evidence that they did open it at `2025-03-19T18:52:39.3679962Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "ovrsr"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/d9685dd2-3afc-46de-8fb1-e02e3ee14b40)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-03-19T18:53:01.1246358Z`, an employee on the "ovrsr" device successfully established a connection to the remote IP address `194.15.112.41` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\sperl\desktop\tor browser\browser\torbrowser\tor\tor.exe`.
**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "ovrsr"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
 ![image](https://github.com/user-attachments/assets/18b14de4-889a-45f7-a2d7-133583b651b9)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2025-03-19T18:50:59.3332144Z`
- **Event:** The user "sperl" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.7.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\sperl\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2025-03-19T18:52:07.4484567Z`
- **Event:** The user "sperl" executed the file `tor-browser-windows-x86_64-portable-14.0.7.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.7.exe /S`
- **File Path:** `C:\Users\sperl\Downloads\tor-browser-windows-x86_64-portable-14.0.7.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2025-03-19T18:53:23.6357935Z`
- **Event:** User "sperl" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\sperl\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2025-03-19T18:54:14.1246358Z`
- **Event:** A network connection to IP `194.15.112.41` on port `9001` by user "sperl" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\sperl\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2025-03-19T18:54:56:08Z` - Connected to `209.141.55.26` on port `9001`.
  - `2025-03-19T18:55:12:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "sperl" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2025-03-19T18:51:15.7259964Z`
- **Event:** The user "sperl" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\sperl\Desktop\tor-shopping-list.txt`

---

## Summary

The user "sperl" on the "ovrsr" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `ovrsr` by the user `sperl`. The device was isolated, and the user's direct manager was notified.

---
