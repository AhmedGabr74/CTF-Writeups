# 🧠 Memory Forensics with Volatility3
### Banking Trojan | WannaCry Ransomware | Amadey Trojan (APT-C-36)
#### TryHackMe + CyberDefenders

---

## 📋 Overview

| Field | Details |
|---|---|
| **Tools** | Volatility3, VirusTotal |
| **Platforms** | TryHackMe (Volatility Room), CyberDefenders (Amadey Lab) |
| **Cases** | 3 memory dump investigations |
| **Malware Covered** | Banking Trojan, WannaCry Ransomware, Amadey Trojan |
| **Focus** | Process analysis, C2 tracing, persistence hunting, attack chain reconstruction |

---

## 🛠️ Volatility3 Plugins Reference

| Plugin | Purpose |
|---|---|
| `windows.info` | Host OS details and build version |
| `windows.pslist` | List processes from doubly-linked list |
| `windows.psscan` | Find hidden processes via EPROCESS scan |
| `windows.pstree` | Process hierarchy with parent-child relationships |
| `windows.netstat` | Active network connections |
| `windows.dlllist` | DLLs loaded per process |
| `windows.malfind` | Detect injected code (RWX memory regions) |
| `windows.filescan` | Scan memory for all file objects |
| `windows.handles` | Open handles — used to find mutexes |

---

## 🦠 Case 001 — Banking Trojan (BOB! THIS ISN'T A HORSE!)

**Platform:** TryHackMe | **File:** `Investigation-1.vmem`

> The SOC received an alert about a quarantined endpoint suspected of banking trojan infection. The malware was masquerading as an Adobe document. Suspicious IP provided: `41.168.5.140`

### Step 1 — Image Info
```bash
python3 vol.py -f Investigation-1.vmem windows.info
```
| Field | Value |
|---|---|
| Build Version | `2600.xpsp.080413-2111` |
| Memory Acquired | `2012-07-22 02:45:08` |
| OS | Windows XP SP3 |

### Step 2 — Process Listing
```bash
python3 vol.py -f Investigation-1.vmem windows.pstree
```
`reader_sl.exe` stood out immediately — disguised as Adobe Reader Speed Launcher but initiating suspicious network connections.

| Field | Value |
|---|---|
| Suspicious Process | `reader_sl.exe` |
| PID | `1640` |
| Parent Process | `explorer.exe` |
| Parent PID | `1484` |

### Step 3 — Network Connections
```bash
python3 vol.py -f Investigation-1.vmem windows.netstat
```
Outbound connection from `reader_sl.exe` (PID 1640) confirmed to **`41.168.5.140`** — malicious C2 IP.

### Step 4 — User-Agent & Banking Targets
```bash
python3 vol.py -f Investigation-1.vmem windows.malfind
```
| Indicator | Value |
|---|---|
| User-Agent | `Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)` |
| Banking Domain | Chase Bank — **confirmed (Y)** |
| C2 IP | `41.168.5.140` |

### ✅ Q&A Summary

| Question | Answer |
|---|---|
| Build version? | `2600.xpsp.080413-2111` |
| Time of memory acquisition? | `2012-07-22 02:45:08` |
| Suspicious process? | `reader_sl.exe` |
| Parent process? | `explorer.exe` |
| PID of suspicious process? | `1640` |
| Parent PID? | `1484` |
| User-Agent? | `Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)` |
| Chase Bank domain found? | `Y` |

### 🚩 IOCs — Case 001
| Type | Value |
|---|---|
| Malicious Process | `reader_sl.exe` (PID 1640) |
| C2 IP | `41.168.5.140` |
| Technique | Masquerading — Adobe Reader impersonation |
| Target | Banking credentials (Chase Bank) |

---

## 💀 Case 002 — WannaCry Ransomware (That Kind of Hurt my Feelings)

**Platform:** TryHackMe | **File:** `Investigation-2.raw`

> Post-incident analysis after the corporation was hit by WannaCry. Decryption key was already recovered. Goal: identify actors, document what occurred.

### Step 1 — Identify Suspicious Processes
```bash
python3 vol.py -f Investigation-2.raw windows.pstree
```
At PID 740: `@WanaDecryptor@` — the WannaCry decryptor UI. Process name alone is a confirmed indicator.

| Field | Value |
|---|---|
| Suspicious Process | `@WanaDecryptor@` |
| PID | `740` |
| Full Path | `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe` |
| Parent Process | `tasksche.exe` |
| Parent PID | `1940` |

> **Note:** `C:\Intel\` is WannaCry's known working directory. `tasksche.exe` is a fake task scheduler used by WannaCry to manage encryption.

### Step 2 — DLL Analysis
```bash
python3 vol.py -f Investigation-2.raw windows.dlllist --pid 740
```
| DLL | Purpose |
|---|---|
| `Ws2_32.dll` | Windows Sockets API — confirms network communication capability |

### Step 3 — Mutex Identification
```bash
python3 vol.py -f Investigation-2.raw windows.handles --pid 740
```
| Mutex | Significance |
|---|---|
| `MsWinZonesCacheCounterMutexA` | Known WannaCry mutex — confirms malware identity |

### Step 4 — Files in Working Directory
```bash
python3 vol.py -f Investigation-2.raw windows.filescan | grep ivecuqmanpnirkt615
```
Plugin used: **`windows.filescan`**

### ✅ Q&A Summary

| Question | Answer |
|---|---|
| Suspicious process at PID 740? | `@WanaDecryptor@` |
| Full path of binary at PID 740? | `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe` |
| Parent process of PID 740? | `tasksche.exe` |
| Suspicious parent PID? | `1940` |
| Malware on system? | `WannaCry` |
| DLL for socket creation? | `Ws2_32.dll` |
| Known mutex indicator? | `MsWinZonesCacheCounterMutexA` |
| Plugin for working directory files? | `windows.filescan` |

### 🚩 IOCs — Case 002
| Type | Value |
|---|---|
| Malicious Process | `@WanaDecryptor@.exe` (PID 740) |
| Full Path | `C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe` |
| Fake Parent | `tasksche.exe` (PID 1940) |
| Socket DLL | `Ws2_32.dll` |
| Mutex | `MsWinZonesCacheCounterMutexA` |
| Malware Family | **WannaCry Ransomware** |

---

## 🧠 Case 003 — Amadey Trojan (APT-C-36)

**Platform:** CyberDefenders | **Lab:** Amadey — APT-C-36

> EDR flagged suspicious activity after hours on a Windows workstation. Memory dump provided. Goal: reconstruct the full infection chain.

### Step 1 — Identify the Malicious Process
```bash
python3 vol.py -f amadey.mem windows.pstree
```
`lssass.exe` is masquerading as the legitimate `lsass.exe` (Local Security Authority Subsystem) — one extra `s` added to evade detection.

| Field | Value |
|---|---|
| Malicious Process | `lssass.exe` (masquerading as `lsass.exe`) |
| Full Path | `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` |
| Location | Temp directory — classic malware staging area |

### Step 2 — C2 Communication
```bash
python3 vol.py -f amadey.mem windows.netstat
```
| C2 Server IP | `41.75.84.12` |
|---|---|
| Direction | Outbound from `lssass.exe` |

### Step 3 — Payload Downloads
```bash
python3 vol.py -f amadey.mem windows.filescan
```
| Field | Value |
|---|---|
| Files Downloaded | **2 distinct files** |
| Key Payload | `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll` |
| Payload Type | DLL — clipboard stealer module |

### Step 4 — LOLBin Execution
```bash
python3 vol.py -f amadey.mem windows.pstree
```
| Child Process | `rundll32.exe` |
|---|---|
| Purpose | Executes `clip64.dll` using the legitimate Windows binary |
| MITRE | T1218.011 — Signed Binary Proxy Execution: Rundll32 |

### Step 5 — Persistence
```bash
python3 vol.py -f amadey.mem windows.filescan | grep Tasks
```
| Location | `C:\Windows\System32\Tasks\lssass.exe` |
|---|---|
| Technique | T1053.005 — Scheduled Task |

### 🔗 Full Amadey Infection Chain
```
1. lssass.exe executed from Temp directory (masquerading as lsass.exe)
         ↓
2. Beacons to C2 server: 41.75.84.12
         ↓
3. Downloads 2 payloads including clip64.dll
         ↓
4. rundll32.exe used to execute clip64.dll (LOLBin abuse)
         ↓
5. Persistence established via Scheduled Task:
   C:\Windows\System32\Tasks\lssass.exe
```

### ✅ Q&A Summary

| Question | Answer |
|---|---|
| Parent process triggering malicious behaviour? | `lssass.exe` |
| Full path of malicious process? | `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` |
| C2 server IP? | `41.75.84.12` |
| Number of files downloaded? | `2` |
| Full path of downloaded payload? | `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll` |
| Child process executing payload? | `rundll32.exe` |
| Additional persistence location? | `C:\Windows\System32\Tasks\lssass.exe` |

### 🚩 IOCs — Case 003
| Type | Value |
|---|---|
| Malicious Process | `lssass.exe` (masquerading as `lsass.exe`) |
| Execution Path | `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe` |
| C2 IP | `41.75.84.12` |
| Downloaded Payload | `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll` |
| LOLBin Abused | `rundll32.exe` |
| Persistence | `C:\Windows\System32\Tasks\lssass.exe` |

---

## 📊 All Cases Summary

| Case | Platform | Malware | Key Process | C2 IP | Technique |
|---|---|---|---|---|---|
| 001 | TryHackMe | Banking Trojan | `reader_sl.exe` | `41.168.5.140` | Masquerading + C2 |
| 002 | TryHackMe | WannaCry | `@WanaDecryptor@` | N/A | Ransomware + Mutex |
| 003 | CyberDefenders | Amadey Trojan | `lssass.exe` | `41.75.84.12` | LOLBin + Sched. Task |

---

## ✅ Skills Demonstrated

- 🧠 **Memory Forensics** — Analysed `.vmem` and `.raw` dumps using Volatility3
- 🔍 **Process Analysis** — `pslist`, `psscan`, `pstree` to identify masquerading and hidden processes
- 🎭 **Masquerading Detection** — Identified `reader_sl.exe` (Adobe) and `lssass.exe` (lsass) impersonation
- 🌐 **Network Forensics** — Traced C2 connections via `windows.netstat` + VirusTotal validation
- 📦 **DLL Analysis** — Socket creation DLLs and malicious payload modules via `dlllist`
- 🔒 **Mutex Analysis** — WannaCry mutex identified via `handles` plugin
- ⚙️ **LOLBin Detection** — `rundll32.exe` abuse for payload execution (T1218.011)
- 🗓️ **Persistence Hunting** — Scheduled Task persistence discovered in `System32\Tasks`
- 🔗 **Attack Chain Reconstruction** — Full infection chains mapped for all 3 malware families
- 🗺️ **MITRE ATT&CK Mapping** — T1036 (Masquerading), T1053 (Scheduled Task), T1218 (LOLBin)

---

*TryHackMe — Volatility Room | CyberDefenders — Amadey Lab | Memory Forensics / DFIR*
