# Incident Response Playbook: Data Exfiltration over SMB

When a detection fires, work through these phases in order. This playbook was built from the actual steps I took during the lab exercise.

## Phase 1: Confirm

Run Query 3 to see the SMB session: who sent it, where it went, how much data moved, and whether the firewall passed or blocked it.

Run the endpoint query (Event 4663) to confirm the sensitive file was actually accessed, and by which account.

If the attacker server is yours (like in this lab), check the receiving side: `ls -la /home/kali/share` on Kali confirms whether the file landed.

## Phase 2: Contain

Stop the bleeding at the perimeter. Apply the containment rule from `configs/opnsense/firewall_rules.md`, then kill the active states for the victim host under Firewall, Diagnostics, States. Killing states is not optional: an established SMB session will keep flowing until its state entry is removed.

On the victim, drop the mapped drive so nothing retries in the background:

```cmd
net use * /delete /y
```

## Phase 3: Verify the Containment Worked

Never declare containment on the strength of an error message alone. Verify from three angles:

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

Remove any mapped drives, scheduled tasks, or persistence the attacker left behind.

Reset the credentials used in the attack (in this lab, the kali share account) and any account shown in the 4663 events.

Restore the victim from a known-good snapshot if there is any doubt about what else was touched.

## Phase 5: Document

Write up an incident ticket while it is fresh:

- **Timeline:** `first_seen` and `last_seen` from Query 3 give you the window.
- **Scope:** which host, which file, which destination.
- **Actions taken:** screenshots, query output, tcpdump, pfctl counters.
- **Evidence:** The on-off-on control test from the troubleshooting section, where the attack succeeds with the rule disabled and fails with it enabled, is the strongest evidence that the containment actually caused the stop.
