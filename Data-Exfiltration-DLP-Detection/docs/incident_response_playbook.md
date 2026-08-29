# Incident Response Playbook: Data Exfiltration over SMB

When a detection fires, I work through these phases in order. This playbook was built from the actual steps I took during the lab exercise.

## Phase 1: Confirm

I run Query 3 to see the SMB session: who sent it, where it went, how much data moved, and whether the firewall passed or blocked it.

I run the endpoint query (Event 4663) to confirm the sensitive file was actually accessed, and by which account.

If the attacker server is mine (like in this lab), I check the receiving side: `ls -la /home/kali/share` on Kali confirms whether the file landed.

## Phase 2: Contain

I stop the bleeding at the perimeter. I apply the containment rule from `configs/opnsense/firewall_rules.md`, then kill the active states for the victim host under Firewall, Diagnostics, States. Killing states is not optional: an established SMB session will keep flowing until its state entry is removed.

On the victim, I drop the mapped drive so nothing retries in the background:

```cmd
net use * /delete /y
```

## Phase 3: Verify the Containment Worked

I never declare containment on the strength of an error message alone. I verify from three angles:

**Victim side:** the copy now fails with System error 67 or 53.

**Receiver side:** a capture on Kali stays silent while the victim retries:

```bash
sudo tcpdump -i eth1 -n 'tcp and (port 445 or port 139)'
```

**Firewall side:** the block rule's counters climb and the Live View shows red block entries:

```bash
pfctl -vvsr | grep -A 8 microsoft-ds
```

## Phase 4: Eradicate and Recover

I remove any mapped drives, scheduled tasks, or persistence the attacker left behind.

I reset the credentials used in the attack (in this lab, the kali share account) and any account shown in the 4663 events.

I restore the victim from a known-good snapshot if there is any doubt about what else was touched.

## Phase 5: Document

I write up an incident ticket while it is fresh:

- **Timeline:** `first_seen` and `last_seen` from Query 3 give me the window.
- **Scope:** which host, which file, which destination.
- **Actions taken:** screenshots, query output, tcpdump, pfctl counters.
- **Evidence:** The on-off-on control test from the troubleshooting section, where the attack succeeds with the rule disabled and fails with it enabled, is the strongest evidence that the containment actually caused the stop.
