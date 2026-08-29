# Generate fake PII data for the exfiltration demo
# Run this in an elevated PowerShell window on the Windows 10 victim (192.168.56.104)

$path = "C:\Users\vagrant.WINDOMAIN\Documents\PII_Database.csv"
"Name,SSN,CreditCard,Email" | Out-File $path

1..500 | ForEach-Object {
    $ssn = '{0:D9}' -f (Get-Random -Maximum 999999999)
    $cc  = '{0:D16}' -f (Get-Random)
    "User$_,$ssn,$cc,user$_@WINDOMAIN.local" | Out-File $path -Append
}

Get-Item $path | Select-Object Name, Length

# Expected output: PII_Database.csv at 59624 bytes
# Verified from screenshot: screenshots/fake_pii_database.png
