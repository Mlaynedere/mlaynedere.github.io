---
title: "Example HTB Machine"
date: 2025-09-07
slug: example-htb-machine
tags: ["htb","example-machine","linux","privesc"]
summary: "Enumeration to root compromise of an example HackTheBox Linux target."
cover: "/images/example-machine/banner.png"
---

> Replace this example with real content. Structure below is a suggested template.

## Recon

```bash
nmap -p- -sC -sV -oA scans/initial 10.10.10.10
```

Findings:
- Open ports: 22, 80
- Web app reveals upload functionality

## Web Enumeration

```bash
ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt -ic
```
### Test 1

```python
print("Hello World")
```


## Foothold
Describe exploit chain.

## Privilege Escalation
Check sudo, suid, cron, capabilities, PATH hijack candidates.

## Loot
- User flag
- Root flag

## Notes
Add screenshots referenced like: `![Foothold](/images/example-machine/foothold.png)`.
