**Penelope** is an open-source, multi-session shell handler written in Python, designed specifically to replace basic `netcat` listeners during red team operations, penetration testing, and CTFs. Standard `netcat` shells lack tab completion, line editing, and crash if you hit `Ctrl+C`. Penelope automates the process of catching reverse or bind shells and stabilizing them into fully interactive PTYs with proper terminal window resizing.

---

## Key Features & Utilities

* **Automated PTY Upgrade:** Upgrades raw Unix reverse shells to interactive PTYs with `readline` support and real-time terminal window resizing automatically upon connection.
* **Multi-Session Management:** Listens on multiple ports simultaneously and tracks multiple active sessions without losing state.
* **Integrated File Transfers:** Provides built-in commands to upload local files/folders to the target or download remote files directly back to your local attack box.
* **Built-in HTTP File Server (`-s`):** Allows you to quickly serve scripts or payloads over HTTP directly from the tool.
* **In-Memory Script Execution:** Runs enumeration scripts (like LinPEAS) in target memory and Streams the output back into a local file on your machine.
* **Integrated Modules:** Supports launching helper tools like `linpeas`, `lse`, `ligolo-ng`, `pspy`, or `chisel` straight from the command interface.
* **Automatic Logging:** Logs all shell interactions and terminal sessions into local files for reporting and audit trails.

---

## Installation on Kali Linux

Penelope is available directly in the official Kali package repository and can also be run standalone or via `pipx`.

### Option 1: Native APT Package (Recommended)

```bash
sudo apt update
sudo apt install penelope

```

### Option 2: Standalone Execution

Because Penelope relies strictly on Python 3 standard libraries, it requires no external Python dependencies and can be fetched directly:

```bash
wget -q https://raw.githubusercontent.com/brightio/penelope/main/penelope.py
python3 penelope.py

```

### Option 3: Via pipx

```bash
pipx install penelope-shell-handler

```

---

## Example Usage Commands

### 1. Basic Listener

Start listening on the default port (`4444`):

```bash
penelope

```

### 2. Multi-Port Listener

Listen on multiple ports concurrently:

```bash
penelope -p 4444,5555,8080

```

### 3. Bind to Specific Network Interface

Listen on a specific interface (e.g., `eth0` or `tun0`):

```bash
penelope -i tun0 -p 4444

```

### 4. Display One-Liner Reverse Shell Payloads

Generate syntax examples tailored to your active listener IP/ports:

```bash
penelope -a

```

### 5. Quick HTTP File Server Mode

Serve a single file, directory, or multiple binaries over HTTP (default port `8000`):

```bash
# Serve current directory on port 80
penelope -s . -p 80

# Serve specific script behind a hidden URL prefix
penelope -s LinEnum.sh -prefix hidden_path

```

---

## Managing Sessions Inside Penelope

* **Detach Shell:** Press `F12` to detach from an active PTY shell and return to the main Penelope control menu without killing the session.
* **Switch Session:** `interact <session_id>` or short alias `i 1` to attach to session 1.
* **Download File:** Inside an active session, run `download /path/to/remote/file.txt` to transfer it back to your machine.
* **Upload File:** Inside an active session, run `upload /local/path/linpeas.sh` to send it to the remote system.
