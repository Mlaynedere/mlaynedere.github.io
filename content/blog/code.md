---
title: "Code"
date: 2025-03-29
slug: "code"
tags: ["machines", "code", "walkthrough"]
cover: "/images/code/Pasted image 20250329144142.png"
summary: "Walkthrough of the Code Machines machine covering recon, exploitation, and privilege escalation."
---
https://app.hackthebox.com/machines/Code

## Reconnaissance

```shell
nmap 10.10.11.62
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-29 08:33 EDT
Nmap scan report for 10.10.11.62
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 1.95 seconds
```

```shell
nmap -p- 10.10.11.62
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-29 08:33 EDT
Nmap scan report for 10.10.11.62
Host is up (0.16s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
5000/tcp open  upnp

Nmap done: 1 IP address (1 host up) scanned in 589.84 seconds

```

```shell
nmap -sV -sC -p 22,5000 10.10.11.62                                                                                
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-29 08:38 EDT
Nmap scan report for 10.10.11.62
Host is up (0.15s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b5:b9:7c:c4:50:32:95:bc:c2:65:17:df:51:a2:7a:bd (RSA)
|   256 94:b5:25:54:9b:68:af:be:40:e1:1d:a8:6b:85:0d:01 (ECDSA)
|_  256 12:8c:dc:97:ad:86:00:b4:88:e2:29:cf:69:b5:65:96 (ED25519)
5000/tcp open  http    Gunicorn 20.0.4
|_http-title: Python Code Editor
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.43 seconds
```

## Enumeration

When navigating to http://ip:5000, a page opened which seems like rendering python code

![code-1](/images/code/Pasted image 20250329144142.png)

Tried to run several reverse shell codes but obtained restricted keywords error

I will try to save a reverse shell without running it, the application only saves the file, and then offers you the option to go back to the editor and run the code... which gets us restricted again

![code-2](/images/code/Pasted image 20250329150551.png)


Instead of a reverse shell I will try and add a user...

Still didn't work in addition to not being able to view a file or view who I am. Looks like this code does not allow local commands

Try to open a web server on another port ... didn't work

Tried running a python code that runs a bash script, defined inside the code

Will try obfuscating the code


Then read more about gunicorn 20.04 vulnerabilities so I will try HTTP Request smuggling

## Exploitation

![code-3](/images/code/Pasted image 20250329172800.png)

didn't work

Found path other than this in a writeup:

![code-4](/images/code/Pasted image 20250329175227.png)

the credentials are:

`development:development`
`martin:nafeelswordsmaster`

Now go to SSH

### SSH

```shell
martin@code:~$ ls -la
total 40
drwxr-x--- 7 martin martin 4096 Mar 29 15:55 .
drwxr-xr-x 4 root   root   4096 Aug 27  2024 ..
drwxr-xr-x 2 martin martin 4096 Mar 29 15:55 backups
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .bash_history -> /dev/null
-rw-r--r-- 1 martin martin  220 Aug 27  2024 .bash_logout
-rw-r--r-- 1 martin martin 3771 Aug 27  2024 .bashrc
drwx------ 2 martin martin 4096 Mar 29 15:55 .cache
drwx------ 2 martin martin 4096 Mar 29 14:50 .gnupg
drwxrwxr-x 2 martin martin 4096 Mar 29 15:35 .local
-rw-r--r-- 1 martin martin  807 Aug 27  2024 .profile
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .python_history -> /dev/null
lrwxrwxrwx 1 root   root      9 Aug 27  2024 .sqlite_history -> /dev/null
drwx------ 2 martin martin 4096 Sep 16  2024 .ssh
martin@code:~$ cd backups/
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar.bz2  task.json
martin@code:~/backups$ bunzip2 code_home_app-production_app_2024_August.tar.bz2 
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar  tar  task.json
martin@code:~/backups$ cd tar
-bash: cd: tar: Not a directory
martin@code:~/backups$ cat tar
#!/bin/bash
id > /tmp/whoami.txt
bash
martin@code:~/backups$ ls -la
total 68
drwxr-xr-x 2 martin martin  4096 Mar 29 15:55 .
drwxr-x--- 7 martin martin  4096 Mar 29 15:55 ..
-rw-r--r-- 1 martin martin 51200 Mar 29 15:55 code_home_app-production_app_2024_August.tar
-rwxrwxr-x 1 martin martin    38 Mar 29 15:55 tar
-rw-r--r-- 1 martin martin   181 Mar 29 15:55 task.json
martin@code:~/backups$ cat task.json 
{
        "destination": "/home/martin/backups/",
        "multiprocessing": true,
        "verbose_log": false,
        "directories_to_archive": [
                "/home/app-production/app"
        ],

        "exclude": [
                ".*"
        ]
}
martin@code:~/backups$ 
martin@code:~/backups$ tar -xf code_home_app-production_app_2024_August.tar
martin@code:~/backups$ ls
code_home_app-production_app_2024_August.tar  home  tar  task.json
martin@code:~/backups$ cd home
martin@code:~/backups/home$ ls
app-production
martin@code:~/backups/home$ cd app-production/
martin@code:~/backups/home/app-production$ ls
app
martin@code:~/backups/home/app-production$ cd app/
martin@code:~/backups/home/app-production/app$ ls
app.py  instance  static  templates
martin@code:~/backups/home/app-production/app$ 

```

```shell
martin@code:~/backups/home/app-production/app/instance$ ls
database.db
martin@code:~/backups/home/app-production/app/instance$ cat database.db 
�O"�O�P�tablecodecodeCREATE TABLE code (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        code TEXT NOT NULL, 
        name VARCHAR(100) NOT NULL, 
        PRIMARY KEY (id), 
        FOREIGN KEY(user_id) REFERENCES user (id)
)�*�7tableuseruserCREATE TABLE user (
        id INTEGER NOT NULL, 
        username VARCHAR(80) NOT NULL, 
        password VARCHAR(80) NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (username)
���QQR*Mmartin3de6f30c4a09c27fc71932bfc68474be/#Mdevelopment759b74ce43947f5f4c91aeddc3e5bad3
�����
���&$n# Cprint("Functionality test")Test
```

run linpeas

Then we found a script backy.sh:

```shell
martin@code:/usr/bin$ cat backy.sh
#!/bin/bash

if [[ $# -ne 1 ]]; then
    /usr/bin/echo "Usage: $0 <task.json>"
    exit 1
fi

json_file="$1"

if [[ ! -f "$json_file" ]]; then
    /usr/bin/echo "Error: File '$json_file' not found."
    exit 1
fi

allowed_paths=("/var/" "/home/")

updated_json=$(/usr/bin/jq '.directories_to_archive |= map(gsub("\\.\\./"; ""))' "$json_file")

/usr/bin/echo "$updated_json" > "$json_file"

directories_to_archive=$(/usr/bin/echo "$updated_json" | /usr/bin/jq -r '.directories_to_archive[]')

is_allowed_path() {
    local path="$1"
    for allowed_path in "${allowed_paths[@]}"; do
        if [[ "$path" == $allowed_path* ]]; then
            return 0
        fi
    done
    return 1
}

for dir in $directories_to_archive; do
    if ! is_allowed_path "$dir"; then
        /usr/bin/echo "Error: $dir is not allowed. Only directories under /var/ and /home/ are allowed."
        exit 1
    fi
done

/usr/bin/backy "$json_file"
```

so we need to modify task.json

```shell
root@code:~# ls
root.txt  scripts
root@code:~# cat root.txt 
856e7ddab1785ced27a4a754b8392c7c

```
