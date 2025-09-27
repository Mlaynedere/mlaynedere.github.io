---
title: "Cypher"
date: 2025-03-17
slug: "cypher"
tags: ["machines", "cypher", "walkthrough"]
summary: "Walkthrough of the Cypher Machines machine covering recon, exploitation, and privilege escalation."
---
Link to Machine: https://app.hackthebox.com/machines/Cypher

## Nmap

```shell
 nmap 10.10.11.57 -vv                                                                        
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-16 11:49 PDT
Initiating Ping Scan at 11:49
Scanning 10.10.11.57 [4 ports]
Completed Ping Scan at 11:49, 1.88s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 11:49
Completed Parallel DNS resolution of 1 host. at 11:49, 0.00s elapsed
Initiating SYN Stealth Scan at 11:49
Scanning 10.10.11.57 [1000 ports]
Discovered open port 22/tcp on 10.10.11.57
Discovered open port 80/tcp on 10.10.11.57
Completed SYN Stealth Scan at 11:49, 4.53s elapsed (1000 total ports)
Nmap scan report for 10.10.11.57
Host is up, received reset ttl 63 (0.50s latency).
Scanned at 2025-03-16 11:49:48 PDT for 5s
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack ttl 63
80/tcp open  http    syn-ack ttl 63

Read data files from: /usr/share/nmap
Nmap done: 1 IP address (1 host up) scanned in 6.50 seconds
           Raw packets sent: 1194 (52.512KB) | Rcvd: 1197 (47.888KB)

```

```shell
nmap -p 22,80 -sC -sV 10.10.11.57    
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-16 12:03 PDT
Nmap scan report for cypher.htb (10.10.11.57)
Host is up (0.14s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 be:68:db:82:8e:63:32:45:54:46:b7:08:7b:3b:52:b0 (ECDSA)
|_  256 e5:5b:34:f5:54:43:93:f8:7e:b6:69:4c:ac:d6:3d:23 (ED25519)
80/tcp open  http    nginx 1.24.0 (Ubuntu)
|_http-title: GRAPH ASM
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.89 seconds

```
## Web

When checking http://10.10.11.57, I get redirected to cypher.htb so I will add this domain to /etc/hosts

When clicking on check demo, it redirects to login page. So I will try to perform subdomain enumeration and directory bruteforcing to maybe check for credentials

Hint by Antoine and Mahdi that there is something related to Cyoher Neo4j database injection
