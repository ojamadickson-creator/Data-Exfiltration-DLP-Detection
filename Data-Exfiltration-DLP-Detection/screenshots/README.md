# Screenshots Index

Every screenshot in this folder was taken during the live lab on August 27, 2026. Each one proves a specific claim I made in the repository.

| Screenshot | What It Proves |
|:---|:---|
| `Allowed rules up &Containment rules down.png` | Block SMB egress sitting below Default allow LAN in OPNsense rules list. |
| `Containment succeeded Net tool unable to connect .png` | System error 67 after containment; net use fails to map attacker share. |
| `containment succeeded tcpdump not receiving any traffic.png` | Kali tcpdump on eth1 shows zero SMB traffic after block rule applied. |
| `copying file across the network.png` | File copied from Windows to Kali share successfully. |
| `Evidence of the attack from LAN to WAN in firewall log.png` | Filter log shows pass, out, TCP 445, 192.168.56.104 to 192.168.57.10, interface em0. |
| `Exfiltrated Security log in Splunk.png` | Event 4663 captured in Splunk from win10.windomain.local. |
| `Fake_PII_Database.png` | PII_Database.csv created at 59,624 bytes via PowerShell. |
| `File Transfer Verified.png` | Zip arrived on Kali; unzip -l confirms PII_Database.csv inside. |
| `Firewall log and correlation query.png` | Query 3 result: two packets, action pass, first seen 08/27/2026 08:52:24. |
| `Firewall Rules.png` | Full OPNsense firewall rules page showing all configured rules. |
| `IDS alert and Firewall log from win10 to Attacker machine.png` | Suricata fired "SMB Exfiltration LAN to WAN" alongside filterlog records for same session. |
| `IDS Traffic detection.png` | Quick hunt for port 445 surfaced 6 matching events in 30 min window. |
| `impacket setup.png` | impacket-smbserver running on Kali with SMB2 support. |
| `Network Traffic Dashboard from Firewall.png` | Splunk dashboard showing firewall block and pass entries. |
| `Powershell & Exfil package in Splunk.png` | Process Name: powershell.exe, Object_Name: exfil_package.zip, Accesses: ReadData. |
| `Route configuration.png` | Kali default route fixed to 192.168.57.254 via eth1. |
| `Setting  file &Folder access.png` | SACL applied to Documents folder: Everyone, Special access, applies to subfolders and files. |
| `Successful Exfiltration.png` | exfil_package.zip present in /home/kali/share on Kali. |
| `Tearing down connection and test the applied comtainment rules.png` | ipconfig confirms single adapter, gateway 192.168.56.254 after NAT removal. |
| `verify audit policy enabled.png` | File System auditing set to Success and Failure via auditpol. |
| `Virtual Machines.png` | All five lab VMs running (Kali, DC, Win10, OPNsense, Splunk). REMnux powered off. |
| `WinEventLog Correlation to find exfil_package.png` | 13 events correlating exfil_package.zip access on win10 host. |
| `zip file.png` | exfil_package.zip created via Compress-Archive. |

## Note

These screenshots are evidence, not decoration. Each one was captured at the moment the corresponding command or query returned its result. No screenshot was staged after the fact.
