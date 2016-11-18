# Bro-Scripts
A series of Bro Scripts created for detection purposes. 

# detect-mal-smb-files.bro:
This is a script that detects malicious files transferred via SMB. Anytime Bro detects a file with a source of SMB, also located in (smb_files.log) it will check the hash using Virus Total's API. If there are two or more hits on the submitted hash, it will write a notice to the notice.log. 

This is designed for Bro version 2.5 supporting SMB.

The API request part of the code stems from the following script: https://gist.github.com/hillar/825c36269c2f684a45b3


# bad-share.bro
This script detects anytime a computer accesses the IPC$, ADMIN$ or C$ shares on a network. A notice will be written to the notice.log with the connection details from the event. A constant can be added to exclude host that legitimately access these shares regularly.

Supported for Bro version 2.5

# bad-hostname.bro
This is a script that detects a hostname used in NTLM traffic that is not compliant with your company naming convention. A notice will be written to notice.log.

Supported for Bro version 2.5
