# Splunk: Verified Queries

These are the queries I wrote and confirmed on screen during the lab. Each one lists the screenshot that proves it and the result it returned.

A note on field names, because it tripped me up: the endpoint events carry `source = WinEventLog:Security` and `sourcetype = WinEventLog`. An earlier draft of my report used `sourcetype="WinEventLog:Security"`, which matches nothing in this Splunk. The screenshots show the working form, and the working form is what you get below. Same story on the firewall side: `sourcetype = syslog` with extracted fields like `dst_port`, `src_ip`, `dst_ip`, `action`, and `Data_length`.

## Query 1: File Access on the Victim (Event 4663)

The endpoint tripwire. Fires when any audited file under Documents is read.

```spl
# Verified from screenshot: ../screenshots/splunk_4663_security_log.png
index=main source="WinEventLog:Security" EventCode=4663
```

**Verified result:** 2 of 58 events matched inside a 5 minute window, both on `win10.windomain.local`. Event 4663 means an attempt was made to access an object, and because of the SACL from the Windows setup, reading the staged archive lands here.

## Query 2: Correlating the Staged Archive

Narrows the 4663 noise down to the exfiltration package itself.

```spl
# Verified from screenshot: ../screenshots/splunk_4663_event_detail.png
index=main source="WinEventLog:Security" EventCode=4663
| search Object_Name="*exfil_package.zip*"
| table _time, host, Account_Name, Object_Name
```

**Verified result:** 13 events, all host `win10`, object `C:\Users\vagrant.WINDOMAIN\Documents\exfil_package.zip`, mostly account `vagrant` with two hits from `WIN10$` (the machine account). The expanded event detail in `../screenshots/splunk_4663_event_detail.png` shows the smoking gun: Process Name `powershell.exe`, Accesses `ReadData (or ListDirectory)`.

Line by line: the first line pulls Windows Security events and keeps only Event ID 4663. The second line filters to events whose object name contains the archive, because 4663 fires for every audited read and is noisy without a filter. The table line shapes the output: when, which machine, which account, which file.

## Query 3: SMB Leaving the Internal Network (the Star Alert)

The staged zip is small, so volume alone may never flag it. This query instead flags any SMB session whose destination sits outside the internal network, which catches the exfiltration at any file size. It also returns the action field, so both successful transfers (pass) and attempts stopped by the firewall (block) show up.

```spl
# Verified from screenshot: ../screenshots/splunk_smb_correlation_query.png
index=main sourcetype=syslog dst_port=445
| where NOT cidrmatch("192.168.56.0/24", dst_ip)
| stats count as packets sum(Data_length) as total_bytes earliest(_time) as first_seen latest(_time) as last_seen values(action) as action by src_ip dst_ip
| convert ctime(first_seen) ctime(last_seen)
| sort - last_seen
```

**Verified result during the attack window:** one conversation, `192.168.56.104` to `192.168.57.10`, first seen `08/27/2026 08:52:24`, last seen `08/27/2026 08:52:47`, action `pass`. In that run the matched pass records carried `Data_length` of 0, which is exactly why the detection keys on destination instead of byte counts.

Line by line:

1. `index=main sourcetype=syslog dst_port=445`: the data source. Firewall syslog, SMB events only. Filtering this early keeps the search cheap.
2. The `where NOT cidrmatch(...)` line is the detection logic. It checks whether the destination IP belongs to the internal /24 and inverts it, keeping only SMB traffic heading somewhere it should never go. A volume rule can be evaded by compressing or splitting data; SMB leaving the internal network is suspicious at any size. Whitelist thinking: define what is normal, alert on everything else.
3. The `stats` line collapses individual packet logs into one row per conversation: how many packets, how much data, when it started, when it ended, pass or block, who sent it and where to.
4. `convert ctime(...)` turns epoch timestamps into dates a human can read.
5. `sort - last_seen` puts the most recent activity first.

If a legitimate backup or admin share ever crosses segments, add that destination as another `cidrmatch` exception.

## Query 4: Quick Hunt for Anything SMB

The fast triage search I used while correlating the IDS alert with the firewall log:

```spl
# Verified from screenshot: ../screenshots/suricata_traffic_detection.png
index=main sourcetype=syslog "445"
```

**Verified result:** 6 of 8 events matched in a 30 minute window, surfacing both the Suricata alert events and the raw `filterlog` records for the same session. This is the query that proved two independent sensors saw the same theft.

## Query 5: SMB Traffic Baseline by Source

Sum the SMB data volume per source host to establish a baseline of file sharing activity:

```spl
index=main sourcetype=syslog dst_port=445 action=pass
| stats sum(Data_length) as total_out by src_ip
```

## Query 6: Statistical Anomaly Detection

```spl
index=main sourcetype=syslog dst_port=445 action=pass
| stats sum(Data_length) as total_out by src_ip
| eventstats avg(total_out) as avg_out stdev(total_out) as stdev_out
| eval threshold = avg_out + (3 * stdev_out)
| where total_out > threshold
| table src_ip total_out avg_out threshold
```

## Turning a Query into an Alert

In Splunk, run the query, then Save As, Alert. Set it on a schedule (for example every 5 minutes over the last 5 minutes), trigger when the number of results is greater than 0. Query 3 is the best candidate for a real alert, since SMB leaving the internal network should never happen in this lab.

## What I Learned Here

Destination beats volume for exfiltration detection, and two sensors beat one. The endpoint query says the file was touched; the network query says it left; together they reconstruct collect, then exfiltrate.
