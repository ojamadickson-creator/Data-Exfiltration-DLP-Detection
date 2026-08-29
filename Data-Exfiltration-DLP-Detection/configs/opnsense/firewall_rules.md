# OPNsense Firewall: Containment Rules and Troubleshooting

This is the most valuable part of the project. The block rule failed twice, for two different reasons, and both root causes are documented here with the exact commands and screenshots that proved each step.

## The Containment Rule

After detecting the simulated data exfiltration in Splunk, my response plan was to stop it at the perimeter. I created a block rule on the OPNsense LAN interface to deny outbound SMB traffic from the internal network to the attacker segment.

| Field | Value |
|:---|:---|
| Action | Block |
| Interface | LAN |
| Direction | in |
| TCP/IP Version | IPv4 |
| Protocol | TCP |
| Source | LAN net (192.168.56.0/24) |
| Destination | WAN net (192.168.57.0/24) |
| Destination port | 445 (SMB / microsoft-ds) |
| Log | Enabled (so the blocks show up in Splunk) |
| Description | Containment: block SMB exfiltration LAN to WAN |

Two details make or break this rule: it must sit **above** the default pass rule in the rule list (pf evaluates top down, first match wins), and after applying it you must kill the existing states for the victim (Firewall, Diagnostics, States), because pf is stateful and an already-open SMB session keeps flowing until its state entry is removed.

## Troubleshooting: Why the Block Rule Failed

### Step 1: Challenging my own assumption about the port

My first suspect was my own claim that the attack used port 445. Modern Windows uses direct-hosted SMB on TCP 445, but it falls back to the older NetBIOS session service on TCP 139 if 445 fails. Before touching anything else, I verified what the traffic actually looked like using the firewall's Live View and checked active connections on the victim machine:

```cmd
netstat -an | findstr 192.168.57
```

To clear out any cached sessions that could survive a rule change, I removed the existing drive mapping and killed the firewall states:

```cmd
net use * /delete /y
```

Then on OPNsense: Firewall, Diagnostics, States, filtered by the workstation IP and killed the entries. A stateful firewall will not re-evaluate packets that belong to an already-established session, so this step matters after every rule change.

### Step 2: The discovery that changed everything

The transfer still succeeded. At that point I stopped looking at the rules and asked a more basic question: is the traffic even reaching the firewall? I ran a packet capture directly on the OPNsense LAN interface:

```bash
tcpdump -i em1 -n host 192.168.56.104
```

Complete silence, while the file transferred successfully on the other side of the glass. That single empty capture reframed the whole problem. A firewall can only block what flows through it, and my packets were not flowing through it.

### Root cause 1: A dual-homed workstation bypassing the perimeter

I traced the actual path from the victim machine:

```cmd
ipconfig
tracert -d 192.168.57.10
arp -a | findstr 192.168.57
```

The tracert reached the Kali machine in one hop at under 1 ms, with no gateway in between. The netstat output then gave it away completely:

```
TCP    10.0.2.15:59003    192.168.57.254:80    TIME_WAIT
```

The workstation had a second network adapter using VirtualBox NAT (`10.0.2.15`), and that adapter held the default gateway. Every packet destined outside the internal subnet, including my simulated exfiltration, left through NAT via the host machine and never touched OPNsense. My firewall rule was correct the whole time. It was guarding a door the traffic never used.

**The fix:** I shut down the VM and detached the NAT adapter, leaving the workstation with a single adapter on the internal LAN. After rebooting, I confirmed the fix:

```cmd
tracert -d 192.168.57.10
```

Hop 1 was now `192.168.56.254` (OPNsense), hop 2 was the Kali machine. The traffic finally flowed through the perimeter.

### Step 3: The transfer still worked, so I captured the receiving end

With the path fixed, I re-ran the attack expecting a block. The file still went through. This time I captured packets on the attacker side to see exactly what arrived:

```bash
sudo tcpdump -i eth1 -n 'tcp and (port 445 or port 139)'
```

The capture showed a clean three-way handshake from `192.168.56.104` to `192.168.57.10` on port 445, followed by the full transfer. Two useful confirmations came out of this: the traffic was definitely SMB on 445 (my original assumption was right), and it was definitely transiting the firewall, which meant the firewall was passing traffic it should have blocked.

### Root cause 2: Rule order

I inspected the rules actually loaded in the running firewall rather than trusting the GUI:

```bash
pfctl -sr
```

One detail tripped me up here: pf prints port 445 by its service name, `microsoft-ds`, so grepping for "445" found nothing and briefly made me think the rule was missing. Reading the full ruleset told the real story. My block rule was loaded, on the correct interface, with the correct source, destination, and port. But above it sat the default rule:

```
pass in log quick on em1 inet from (em1:network) to any
```

Because both rules use the `quick` keyword, the first match wins and evaluation stops. My exfiltration traffic matched "allow LAN to any" before it ever reached my block rule. The rule was never wrong. It was standing in line behind a rule that lets everything through. This is visible in `Allowed rules up &Containment rules down.png`.

**The fix:** In Firewall, Rules, LAN, I dragged the block rule above the default allow rule and clicked Apply Changes. Then I killed the states for the workstation one more time so nothing old could persist.

### Step 4: Validation with a control test

I re-ran the attack:

```cmd
net use Z: \\192.168.57.10\smb_share /user:kali kali
```

The command failed with System error 67. I did not trust the error message alone, since Windows reports different errors for dropped connections, so I verified from three angles:

1. The tcpdump on Kali stayed completely silent. No SYN ever arrived.
2. The OPNsense Live View showed red block entries for `192.168.56.104` to `192.168.57.10` on port 445.
3. The rule counter confirmed the matches:

```bash
pfctl -vvsr | grep -A 8 microsoft-ds
```

Finally, I ran a control test to prove causation. With the rule enabled, the attack failed. I disabled the rule, and the attack succeeded again. I re-enabled it, and the attack failed. That on-off-on sequence proves the rule, and only the rule, stops the exfiltration. The containment failure is shown in `Containment succeeded Net tool unable to connect .png` and the silent tcpdump is shown in `containment succeeded tcpdump not receiving any traffic.png`.

## What I Learned

1. **Verify the traffic path before blaming the control.** My rule was correct twice over, and both failures were environmental: a bypass route around the firewall, then a rule that never got evaluated. An empty packet capture was worth more than an hour of staring at rule settings.
2. **Dual-homed machines defeat perimeter controls silently.** One extra NAT adapter gave the workstation a side exit that made every firewall rule irrelevant. In a real environment this is why endpoint inventory and network segmentation audits matter.
3. **First match wins.** Rule order is not cosmetic. A block rule below a broad allow rule is documentation, not protection.
4. **Trust packet captures and counters over GUI impressions.** The GUI showed a rule that looked right. `pfctl` and `tcpdump` showed what was actually happening.
5. **Prove a fix with a control test.** "It seems to work now" is not evidence. Toggling the control and watching the outcome change is.
