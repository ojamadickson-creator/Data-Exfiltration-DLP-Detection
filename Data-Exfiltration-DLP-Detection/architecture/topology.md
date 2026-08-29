# Network Topology

This is how I wired the lab. Getting this part right first saved me hours later. Most of my pain came from skipping the preflight checks.

## The Setup

I simulated a small company network. The Windows 10 box is a workstation on the internal LAN. Kali Linux sits on a different subnet and plays an external machine controlled by an attacker. The OPNsense firewall sits between the two, and all traffic between victim and attacker has to pass through it. Splunk is the SIEM: it receives firewall logs from OPNsense and Windows Event Logs from the endpoint through a Universal Forwarder.

## Machines and Addresses

1. **Windows 10, victim endpoint:** `192.168.56.104` (LAN). Compresses and exfiltrates the PII archive; runs the Splunk Universal Forwarder.
2. **Windows Server, domain controller:** `192.168.56.102` (LAN). AD and DNS for `windomain.local`.
3. **OPNsense, perimeter firewall:** `192.168.56.254` (LAN) and `192.168.57.254` (WAN). Segments the lab; sends filter logs to Splunk.
4. **Kali Linux, attacker and exfil target:** `192.168.57.10` (WAN). Runs an SMB server that receives the stolen file.
5. **Splunk Enterprise, SIEM and log collector:** `192.168.56.106` (LAN). Receives Windows Event Logs (forwarder, TCP 9997) and firewall syslog.

The VirtualBox Manager inventory showing these machines: `../screenshots/virtualbox_vm_list.png`. A REMnux VM exists in the inventory but stayed powered off during this project.

## Traffic Flows

1. **Management:** Windows host to the firewall web UI and the Splunk web UI. Day to day administration. Stays inside the LAN and must never be blocked.
2. **Log forwarding:** OPNsense to the Splunk syslog listener (UDP 514 by default, or the custom port you set), and Windows to Splunk on TCP 9997. This is what gets evidence into the SIEM.
3. **Attack path:** Windows 10 to OPNsense to Kali, TCP 445 (SMB). The exfiltration channel this project detects and then blocks.

## Interfaces, as Observed in the Logs

The firewall log records name the interfaces directly. On the exfiltration events, the pass in record rides `em1` (the LAN side) and the pass out record rides `em0` (the WAN side). Proof: `../screenshots/suricata_alert_and_filterlog.png` and `../screenshots/firewall_log_pass_evidence.png`.

## Preflight Checklist

Before I touched anything, I confirmed these. Most of the pain in this project came from skipping one of them.

1. Take a snapshot of every VM so you can roll back.
2. The Windows VM should have only the internal network adapter. If the VirtualBox default NAT adapter is still attached, Windows may use it as its gateway and the traffic never touches the firewall. This exact mistake cost me a full troubleshooting session, and Kali had the same problem on the other side (see `../screenshots/kali_route_fix.png`).
3. From Windows, confirm the firewall is the gateway. After my fix, `ipconfig` on the victim showed a single adapter with default gateway `192.168.56.254`. Proof: `../screenshots/teardown_and_retest.png`.
4. The firewall must allow LAN hosts to reach the WAN segment so the attack works in the first place. I blocked it later, on purpose.
5. Confirm Splunk is receiving both Windows Event Logs and firewall syslog before you start the attack.

## What I Learned Here

The topology is the detection. Two segments with one choke point means every exfiltration attempt has to file past the firewall, and every management connection stays local. If traffic can bypass the choke point, no rule on that firewall will save you. That is exactly what root cause number one turned out to be.
