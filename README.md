# Network IDS Lab: Snort 3 Detection of ICMP Reconnaissance
          # IDS-Documentation-And-Snort
**Series:** WAJUD SOC Lab, Part 2: Network Security Monitoring
**Analyst:** Wajud | Aspiring SOC Analyst / Blue Team
**Date:** 29 September 2026
**Tools:** Snort 3 (Snort++ 3.12.2.0), Ubuntu on Oracle VirtualBox, Kali Linux (attacker), `ping`

This lab pairs with the host-based Sysmon EDR lab (Part 1). Sysmon covers the endpoint; Snort covers the network.

---

## 1. Summary

I deployed **Snort 3** as a network intrusion detection system (NIDS) on an Ubuntu VM, wrote a custom local rule, and validated it by generating ICMP traffic from a Kali Linux VM. Snort detected the ping activity in real time and logged it with a unique SID, priority, protocol and source/destination.

## 2. Lab Architecture

All VMs run on an isolated VirtualBox host-only network (`192.168.0.0/24`) with no external internet access.

| Role | Host | IP address |
| --- | --- | --- |
| Attacker / scanner | Kali Linux | `192.168.0.3` |
| SOC sensor (Snort IDS) | Ubuntu | `192.168.0.6` |

![Lab architecture](images/01-lab-architecture.jpg)

## 3. How Snort 3 Processes Traffic

Packets are captured from the network interface, decoded and preprocessed, then matched against loaded rules. A match generates an event, which is written by the `alert_fast` output module.

![Snort 3 detection workflow](images/02-snort-detection-workflow.jpg)

## 4. Installation & Configuration Validation

Config validation and startup (`snort.lua` is the Snort 3 config format; Snort 2 used `snort.conf`):

```bash
sudo snort -c /usr/local/etc/snort/snort.lua -T
sudo snort -c /usr/local/etc/snort/snort.lua -i enp0s8 -A alert_fast
```

![Snort configuration validated](images/03-snort-config-validation.png)

What the output shows:

| Item | Value | Meaning |
| --- | --- | --- |
| Config file | `/usr/local/etc/snort/snort.lua` | Snort 3 Lua configuration |
| Text rules loaded | 221 (all enabled) | Every rule loaded with no failures |
| Option chains / chain headers | 221 / 3 | Rules grouped by protocol into 3 headers |
| Port rule counts | tcp 1, icmp 1 | One TCP rule and one ICMP rule are active |
| Service rule counts | file_id 219 (to-server and to-client) | File identification rules, so Snort can inspect file transfers |
| Search engine | `ac_bnfa` | Aho-Corasick pattern matcher used for signature matching |
| DAQ | pcap, passive | Snort monitors traffic and does not block it |
| Result | "successfully validated the configuration (with 0 warnings)" | Clean config |

The 221 rules break down as 219 file identification rules plus the two protocol rules (1 TCP, 1 ICMP). A production deployment would load tens of thousands of rules from a feed such as the Snort/Talos community rules.

## 5. The Custom Detection Rule

Added to `local.rules`:

```
alert icmp any any -> any any (msg:"ICMP Ping Detected - possible Recon"; sid:1000001; rev:1; classtype:attempted-recon; priority:0;)
```

| Element | Meaning |
| --- | --- |
| `alert icmp` | Trigger on ICMP traffic |
| `any any -> any any` | Any source to any destination |
| `sid:1000001` | SIDs of 1,000,000 and above are reserved for local, user-written rules |
| `classtype:attempted-recon` | Classification used by analysts for triage |

## 6. Live Detection

From the Kali VM I sent pings to the sensor (`ping -c 10 192.168.0.6`) while Snort ran in IDS mode on the Ubuntu VM. Snort alerted on each packet.

![Live ICMP alerts in Snort](images/04-live-icmp-alerts.png)

Alert format:

```
[Timestamp] [**] [gid:sid:rev] "Message" [**] [Priority] {Protocol} src -> dst
```

Example from the capture:

```
09/29-12:59:02.664380 [**] [1:1000001:1] "ICMP Ping Detected - possible Recon" [**] [Priority: 0] {ICMP} 192.168.0.6 -> 192.168.0.3
```

Observations:

- Alerts repeat about once per second, matching the one-second interval of `ping`.
- Alerts appear in both directions (`.3 -> .6` and `.6 -> .3`) a fraction of a millisecond apart. The rule matches any ICMP, so it fires on both the echo request and the echo reply.
- The Kali terminal on the left shows the ping replies that generated this traffic.

## 7. SOC Analysis & MITRE ATT&CK Mapping

| Field | Analysis |
| --- | --- |
| Threat level | Low on its own; reconnaissance is the first stage of the kill chain, so it deserves attention |
| MITRE tactic | TA0043 Reconnaissance |
| MITRE techniques | T1018 Remote System Discovery, T1595 Active Scanning (ping sweeps). T1046 Network Service Discovery is the likely next step (port scanning) |
| Kill chain | Reconnaissance, then Weaponization, then Delivery. This was caught at the first step |
| Suggested playbook | 1. Block the source if it is external. 2. Check other network logs (e.g. Zeek `conn.log`) for the same IP. 3. Check Sysmon on the target for suspicious processes after the ping |

## 8. Lessons Learned & Next Steps

- **Rule precision:** the rule matches all ICMP, which produces two alerts per ping and would be noisy on a real network. Narrowing it to echo requests (`itype:8`) and adding a threshold for sweeps would cut noise.
- **Rule coverage:** the rule set is small. Next step is loading the Snort community ruleset (e.g. with PulledPork).
- **TCP detection:** a TCP rule is loaded, but its live detection (e.g. an Nmap SYN scan) is not covered in this write-up and is the next test.
- **Centralization:** forward Snort alerts (`/var/log/snort/`) to a Wazuh manager over syslog and correlate them with the Sysmon logs from Part 1 on one dashboard.

## Repository Structure

```
snort-ids-lab/
├── README.md
└── images/
    ├── 01-lab-architecture.jpg
    ├── 02-snort-detection-workflow.jpg
    ├── 03-snort-config-validation.png
    └── 04-live-icmp-alerts.png
```
