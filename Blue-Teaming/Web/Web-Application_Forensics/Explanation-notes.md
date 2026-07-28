## Task 0: Identifying the Target Service (`0-service.sh`)

### Script Code

```bash
#!/bin/bash
awk '{print $5}' auth.log | cut -d'[' -f1 | sort | uniq -c | sort -nr

```

### Line-by-Line Technical Explanation

#### 1. `awk '{print $5}' auth.log`

* **What it does:** Reads the `auth.log` file line by line and isolates the **5th whitespace-separated field (column)**.
* **Why use it here:** In a standard syslog or auth.log format (e.g., `Mai 18 15:27:23 app-1 sshd[1234]: ...`), column 1 is the month, 2 is the day, 3 is the time, 4 is the hostname (`app-1`), and 5 is the process/service identifier that generated the log item (`sshd[1234]:`).
* **When to use:** Use this whenever you need to slice structured log files vertically by specific column positions.

#### 2. `cut -d'[' -f1`

* **What it does:** Modifies the output string coming from `awk` by using a left bracket `[` as a strict delimiter (`-d`) and extracting only the **first field (`-f1`)** to the left of that bracket.
* **Why use it here:** Raw service outputs frequently contain operational process IDs (PIDs) appended inside brackets (like `sshd[34806]:` or `sshd[2214]:`). To group all identical service names together regardless of their changing process identifier, `cut` strips off everything starting from the `[`, isolating the clean process string (e.g., `sshd`).
* **When to use:** Use this to trim or clean up strings containing variable suffix fields split by a predictable character delimiter.

#### 3. `sort`

* **What it does:** Rearranges the extracted service names alphabetically.
* **Why use it here:** The subsequent command, `uniq`, has a strict prerequisite: it can only identify and deduplicate records that are **directly adjacent to one another**. Alphabetizing the lines groups all instances of a service sequentially.
* **When to use:** Always use this as a direct structural prerequisite immediately prior to piping stream outputs into `uniq`.

#### 4. `uniq -c`

* **What it does:** Deduplicates the stream down to unique elements and appends an active occurrence count (`-c`) prefixing each item.
* **Why use it here:** This calculates the exact volume of log items attributed to each individual service running on the box, revealing which protocol was targeted with heavy activity (like brute-forcing).
* **When to use:** Use this to generate quick quantitative frequency tables from textual lists.

#### 5. `sort -nr`

* **What it does:** Sorts the frequency list numerically (`-n`) and in reverse order (`-r`), placing the largest number at the top.
* **Why use it here:** It instantly floats the most active service to the very top of your terminal display. In this case, `pam_unix(sshd:auth)` generated 34,806 entries, revealing that **SSH** was the primary service leveraged during the intrusion lifecycle.
* **When to use:** Use this at the terminal tail-end of profiling pipelines to establish priority views based on numeric frequency.

---

## Task 1: Interrogating Operating System Fingerprints (`1-operating.sh`)

### Script Code

```bash
#!/bin/bash
grep "Linux version" dmesg

```

### Line-by-Line Technical Explanation

#### 1. `grep "Linux version" dmesg`

* **What it does:** Searches the `dmesg` (diagnostic message/kernel ring buffer log) file specifically for any lines containing the literal, case-sensitive string pattern `"Linux version"`.
* **Why use it here:** During system initialization, the Linux kernel logs a highly specific master hardware/software declaration banner that contains the exact distribution identity, kernel release version, compiler version (`gcc`), and build date. Hunting this specific pattern extracts the operating system's technical footprint (`Linux version 2.6.24-26-server ... Ubuntu 4.2.4-1ubuntu3`) cleanly without reading thousands of irrelevant hardware initializations.
* **When to use:** Use this to isolate definitive environmental definitions or version markers from system files where the exact string structure is standardized.

---

## Task 2: Pinpointing Account Compromise (`2-accounts.sh`)

### Script Code

```bash
#!/bin/bash
tail -n 1000 auth.log | grep -E "root" | sort | uniq -c | sort -nr | head -n 1 | awk '{print $12}'

```

### Line-by-Line Technical Explanation

#### 1. `tail -n 1000 auth.log`

* **What it does:** Extracts strictly the **last 1,000 lines** of the `auth.log` file, ignoring older history.
* **Why use it here:** Intrusion lifecycles typically follow a progression: a long period of automated authentication failures (brute-forcing) followed by a successful interactive authentication and post-exploitation tasks at the very end of the file. Narrowing the analytical window to the end of the log isolates the successful breach phase.
* **When to use:** Use this to ignore large historic data footprints and focus directly on the most recent actions recorded on an asset.

#### 2. `grep -E "root"`

* **What it does:** Leverages Extended Regular Expressions (`-E`) to filter the 1,000 log lines, preserving only entries that match the word `"root"`.
* **Why use it here:** Attackers targeting Linux servers almost exclusively focus brute-force parameters or elevation sweeps on the superuser identifier (`root`) to guarantee complete control over the kernel space.
* **When to use:** Use this to isolate lines belonging to highly targeted system identities or specific diagnostic anchors.

#### 3. `sort | uniq -c | sort -nr`

* **What it does:** As explained in Task 0, this pipeline sorts the log messages, counts the exact occurrences of identical lines, and formats them from highest to lowest frequency.
* **Why use it here:** It separates repetitive high-volume actions (like brute-force password attempts or repeated sudo commands) from one-off events, showing you exactly what repetitive pattern occurred on the root account.

#### 4. `head -n 1`

* **What it does:** Intercepts the incoming sorted text stream and outputs strictly the **first line (`-n 1`)**, discarding everything beneath it.
* **Why use it here:** Because the preceding step sorted the records in descending order, the top line represents the single most frequent type of log entry matching the root user, isolating the core point of high-density activity.
* **When to use:** Use this whenever you need to isolate top-tier items from a prioritized list.

#### 5. `awk '{print $12}'`

* **What it does:** Isolates and prints strictly the 12th whitespace-delimited field of that single highest-frequency line.
* **Why use it here:** In the target lab data structure, the top log entry extracted matches an interactive command or a specific authentication status string where the compromised username sits exactly at the 12th position, outputting `root` as the verified breached entity.
* **When to use:** Use this to pluck an exact word or token out of a known, highly structured single line of text.

---

## Task 3: Enumerating Attacker IP Footprints (`3-ips.sh`)

### Script Code

```bash
#!/bin/bash
grep "Accepted password for root" auth.log | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u | wc -l

```

### Line-by-Line Technical Explanation

#### 1. `grep "Accepted password for root" auth.log`

* **What it does:** Filters `auth.log` to preserve only lines that contain the exact string `"Accepted password for root"`.
* **Why use it here:** This string is the absolute definitive cryptographic confirmation that an external connection successfully authenticated as the root operator over SSH. Failed attempts are completely ignored; this isolates the exact entries where an adversary successfully gained access.
* **When to use:** Use this to map verified security access events or confirmed breach entry points.

#### 2. `grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}'`

* **What it does:** Uses Extended Regex (`-E`) paired with the **only-matching (`-o`)** flag to extract patterns matching an IPv4 address structure (1 to 3 numbers, followed by a dot, repeated three times).
* **Why use it here:** Standard `grep` prints the entire line. Adding `-o` commands the utility to discard the log message text entirely and return *only* the raw IP address string itself. This strips away timestamps, usernames, and ports, leaving a clean column of source IPs.
* **When to use:** Use this to carve out specific regex matches (like hashes, email addresses, or IPs) from a line while discarding surrounding text.

#### 3. `sort -u`

* **What it does:** Sorts the list of IP addresses alphabetically and applies an internal deduplication pass (`-u` for unique).
* **Why use it here:** If a single malicious actor logged into the system 50 separate times from the exact same source IP, counting them 50 times would distort your attacker metrics. `sort -u` compresses the list so every individual source IP address appears exactly once.
* **When to use:** Use this as a fast combination shortcut for `sort | uniq`.

#### 4. `wc -l`

* **What it does:** Invokes the Word Count utility with the **lines flag (`-l`)** to calculate the absolute line total of the incoming text stream.
* **Why use it here:** Since each line in the stream is now a single, unique IP address that successfully broke into the system, counting the total number of lines gives you the exact count of unique attackers (in this lab, `18`).
* **When to use:** Use this at the end of any data-filtering pipeline to generate a final scalar count.

---

## Task 4: Quantifying Firewall Modifications (`4-firewall.sh`)

### Script Code

```bash
#!/bin/bash
grep -iE "iptables" auth.log | grep "A INPUT" | sort -u | wc -l

```

### Line-by-Line Technical Explanation

#### 1. `grep -iE "iptables" auth.log`

* **What it does:** Searches `auth.log` using case-insensitive (`-i`) extended regex to look for any lines referencing `"iptables"`.
* **Why use it here:** When an attacker executes administrative commands via `sudo` or an interactive shell to alter netfilter policies, the system logs the command string to security channels. This captures any firewall adjustments attempted by the intruder.
* **When to use:** Use this when you need to search for a tool name or command reference regardless of whether it was typed in uppercase or lowercase.

#### 2. `grep "A INPUT"`

* **What it does:** Secondary filter that searches the previous matches specifically for the characters `"A INPUT"`.
* **Why use it here:** In standard `iptables` syntax, `-A INPUT` represents an **Append** action targeting the inbound packet processing chain. This isolates instances where the adversary intentionally injected a new rule into the live firewall topology (such as opening communication lines or creating explicit persistent channels), ignoring rules that were deleted or listed.
* **When to use:** Use this to add a second layer of precision to an existing data filter.

#### 3. `sort -u | wc -l`

* **What it does:** Deduplicates identical command entries (`sort -u`) to ensure redundant execution commands aren't over-counted, and counts the lines (`wc -l`) to return the final count of distinct firewall rules added (yielding `6`).

---

## Task 5: Mapping Created Adversarial Accounts (`5-users.sh`)

### Script Code

```bash
#!/bin/bash
grep -E "new user" auth.log | awk '{print $8}' | sed 's/name=//' | sed 's/,$//' | sort | uniq | paste -sd ","

```

### Line-by-Line Technical Explanation

#### 1. `grep -E "new user" auth.log`

* **What it does:** Searches the authentication log for lines containing the exact pattern `"new user"`.
* **Why use it here:** When accounts are added to a Linux operating system, low-level binaries like `useradd` register a specific syslog event entry (e.g., `... useradd[...]: new user: name=Aphelios, UID=1001, GID=1001...`). This filters out everything except actual account creation events.
* **When to use:** Use this to audit account provisioning histories or locate unauthorized administrative backdoor creation.

#### 2. `awk '{print $8}'`

* **What it does:** Pulls out the 8th whitespace-separated field from the matching account creation string.
* **Why use it here:** In a standard account creation syslog message, the eighth column corresponds precisely to the name parameter block (e.g., `name=Aphelios,`).
* **When to use:** Use this to isolate structured positional data blocks out of systemic log outputs.

#### 3. `sed 's/name=//'`

* **What it does:** Invokes the Stream Editor (`sed`) to perform a string substitution (`s/`). It looks for the literal characters `name=` and replaces them with absolutely nothing, effectively deleting them.
* **Why use it here:** The raw field looks like `name=Aphelios,`. To cleanly present only the account name, you must strip away the systemic attribute labeling prefix (`name=`).
* **When to use:** Use this to strip out unwanted characters or clear static prefixes from a text stream.

#### 4. `sed 's/,$//'`

* **What it does:** A second stream edit pass that uses a regex anchor (`$`) to locate a trailing comma `,` at the absolute **end of the line** and replaces it with nothing.
* **Why use it here:** The text trailing the name field in the log entry leaves a remaining trailing comma (like `Aphelios,`). This cleanly deletes that trailing punctuation mark, leaving only the pure account name string (`Aphelios`).
* **When to use:** Use this to trim trailing formatting artifacts from lines of text.

#### 5. `sort | uniq`

* **What it does:** Sorts the cleaned user profiles alphabetically and removes any duplicate names, providing a clean list of unique accounts that were created.

#### 6. `paste -sd ","`

* **What it does:** Merges the vertical lines of text into a single horizontal row, pasting them sequentially using a comma as the explicit delimiter (`-d ","`). The `-s` flag tells the tool to process the data serially (all on one line) rather than processing multiple files in parallel.
* **Why use it here:** Standard Linux pipelines output lists vertically (one name per line). The lab requirements specify a single, flat, comma-separated row matching the exact layout of your challenge checks (e.g., `Aphelios,Debian-exim,Fido...`).
* **When to use:** Use this whenever you need to flatten a vertical stack of data items into a single, delimited string format.
