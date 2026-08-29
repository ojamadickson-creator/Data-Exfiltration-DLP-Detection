# Screenshots Index

Every screenshot in this folder was taken during the live lab on August 27, 2026. Each one proves a specific claim made in the repository. If a claim has no screenshot, it was left out.

| Screenshot | What It Proves | Referenced In |
|:---|:---|:---|
| `virtualbox_vm_list.png` | All five lab VMs running (Kali, DC, Win10, OPNsense, Splunk). REMnux powered off. | README.md, architecture/topology.md |
| `fake_pii_database.png` | PII_Database.csv created at 59,624 bytes via PowerShell. | configs/windows_victim/auditing.md |
| `audit_policy_enabled.png` | File System auditing set to Success and Failure via auditpol. | configs/windows_victim/auditing.md |
| `sacl_folder_auditing.png` | SACL applied to Documents folder: Everyone, Special access, applies to subfolders and files. | configs/windows_victim/auditing.md |
| `compress_archive.png` | exfil_package.zip created via Compress-Archive. | configs/windows_victim/auditing.md |
| `copy_over_smb.png` | File copied from Windows to Kali share successfully. | README.md |
| `file_transfer_verified.png` | Zip arrived on Kali; unzip -l confirms PII_Database.csv inside. | README.md |
| `firewall_log_pass_evidence.png` | Filter log shows pass, out, TCP 445, 192.168.56.104 to 192.168.57.10, interface em0. | README.md, architecture/topology.md |
| `splunk_4663_security_log.png` | Event 4663 captured in Splunk from win10.windomain.local. | configs/splunk/detection_queries.md |
| `splunk_4663_event_detail.png` | Process Name: powershell.exe, Object_Name: exfil_package.zip, Accesses: ReadData. | configs/splunk/detection_queries.md |
| `splunk_smb_correlation_query.png` | Query 3 result: one session, action pass, first seen 08/27/2026 08:52:24. | configs/splunk/detection_queries.md |
| `suricata_alert_and_filterlog.png` | Suricata fired "SMB Exfiltration LAN to WAN" alongside filterlog records for same session. | configs/suricata/custom_rules.md, architecture/topology.md |
| `suricata_traffic_detection.png` | Quick hunt for port 445 surfaced 6 matching events in 30 min window. | configs/splunk/detection_queries.md |
| `network_traffic_dashboard.png` | Splunk dashboard showing firewall block and pass entries. | README.md |
| `rule_order_problem.png` | Block SMB egress sitting below Default allow LAN in OPNsense rules list. | configs/opnsense/firewall_rules.md |
| `containment_net_use_fails.png` | System error 67 after containment; net use fails to map attacker share. | configs/opnsense/firewall_rules.md |
| `tcpdump_silence.png` | Kali tcpdump on eth1 shows zero SMB traffic after block rule applied. | configs/opnsense/firewall_rules.md |
| `teardown_and_retest.png` | ipconfig confirms single adapter, gateway 192.168.56.254 after NAT removal. | configs/opnsense/firewall_rules.md, architecture/topology.md |
| `kali_route_fix.png` | Kali default route fixed to 192.168.57.254 via eth1. | architecture/topology.md |

## Note

These screenshots are evidence, not decoration. Each one was captured at the moment the corresponding command or query returned its result. No screenshot was staged after the fact.
