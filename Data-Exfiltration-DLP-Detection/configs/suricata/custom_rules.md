# Suricata: Custom IDS Rules

Suricata runs on the OPNsense firewall and watches traffic crossing the perimeter. During this project it fired on a custom signature I wrote to detect SMB sessions leaving the internal network.

## Verified Alert

The Suricata alert fired during the exfiltration and was visible in Splunk alongside the firewall filter logs.

**Alert details from the log:**

- **Signature:** `SMB Exfiltration LAN to WAN`
- **Priority:** 3
- **Protocol:** TCP
- **Source:** 192.168.56.104:any
- **Destination:** 192.168.57.10:445
- **Direction:** any

## The Custom Rule

```suricata
alert tcp 192.168.56.0/24 any -> 192.168.57.0/24 445 (msg:"SMB Exfiltration LAN to WAN"; sid:1000003; rev:1;)
```

This is a simple but effective signature. It says: alert on any TCP session from the LAN subnet to the WAN subnet where the destination port is 445. In a production environment you would tune this with flowbytes to avoid noise from legitimate internal SMB, but in this lab the rule proved that two independent sensors (Suricata + filterlog) saw the same theft.

## Why This Matters

The firewall log tells you the packet was allowed. The Suricata alert tells you the packet matched a threat signature. Together they give you both the policy view and the threat view. That is the whole point of defense in depth.
