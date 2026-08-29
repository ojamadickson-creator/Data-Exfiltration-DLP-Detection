# Windows Victim: Auditing and Staging

Everything here ran on the Windows 10 victim (`192.168.56.104`), in an elevated PowerShell window. My goal was to make the endpoint confess: when the attacker reads the sensitive file, Windows should write Event ID 4663 into the Security log, and the Universal Forwarder ships that log to Splunk.

## 1. Creating the Fake Sensitive Data

I built a CSV with 500 rows of fake names, SSNs, and card numbers in the Documents folder. Nothing real, but it looks like the kind of file a company would panic over.

```powershell
$path = "C:\Users\vagrant.WINDOMAIN\Documents\PII_Database.csv"
"Name,SSN,CreditCard,Email" | Out-File $path
1..500 | ForEach-Object {
    $ssn = '{0:D9}' -f (Get-Random -Maximum 999999999)
    $cc  = '{0:D16}' -f (Get-Random)
    "User$_,$ssn,$cc,user$_@WINDOMAIN.local" | Out-File $path -Append
}
Get-Item $path | Select-Object Name, Length
```

Output: `PII_Database.csv` at 59,624 bytes. The file comes out small, only tens of KB. That mattered later: the network detection cannot rely on a huge spike in bytes, so the key Splunk query finds the traffic by where it went, not by size.

## 2. Turning On File Access Auditing

```powershell
auditpol /set /subcategory:"File System" /success:enable /failure:enable
```

Output: `The command was successfully executed.`

Then I verified it actually applied. A lot of people set the policy and never confirm it:

```powershell
auditpol /get /subcategory:"File System"
```

Output: the File System subcategory reports `Success and Failure`. If it still says No Auditing, the setting did not take and you get zero events later.

## 3. Setting a SACL on the Target Folder

The audit policy alone is not enough. Windows also needs to know which files to watch, and that is the SACL (System Access Control List) on the file or folder. Without it, Event ID 4663 never fires.

GUI steps:

1. Right click the Documents folder, then Properties, Security, Advanced, Auditing tab.
2. Add a principal: `Everyone`.
3. Set the entry to cover read access for both success and failure.
4. Apply.

The result in the Auditing tab reads: Type `All`, Principal `Everyone`, Access `Special`, Inherited from `None`, Applies to `This folder, subfolders and files`. This tells Windows: log an event every time anyone reads a file under this folder.

## 4. Staging the Exfiltration Package

I compressed the PII into a zip, the way a real attacker archives data before stealing it:

```powershell
Compress-Archive -Path "C:\Users\vagrant.WINDOMAIN\Documents\PII_Database.csv" -DestinationPath "C:\Users\vagrant.WINDOMAIN\Documents\exfil_package.zip" -Force
```

The zip shows up in Explorer as 11 KB.

## 5. Proof the Endpoint Telemetry Works

After the attack, Splunk held Event 4663 records showing the archive read by `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` with access `ReadData (or ListDirectory)`, account `vagrant`, computer `win10.windomain.local`.

## What I Learned Here

Audit policy plus SACL: you need both, and each is verified separately. The policy turns the capability on; the SACL points it at the folder. And verify before you attack, because a detection that was never armed is not a detection.
