Here is your comprehensive, high-density reference sheet for web application log analysis and incident response. This is built for rapid deployment during an investigation or for writing automation tools in your repository.

---

## 🗺️ Web Access Log Architecture (Standard Combined Format)

Before parsing, you must know exactly where data sits. Most standard web servers (Nginx, Apache) log transactions using whitespace-delimited arrays.

```
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST /login HTTP/1.1" 200 1941 "-" "python-requests/2.31.0"
  [ $1 ]    $2 $3          [ $4 ]      [$5]    [ $6 ]  [ $7 ]   [ $8 ]   $9  $10  $11          [ $12 ]

```

| Field Position | Log Attribute | Security Analysis Purpose |
| --- | --- | --- |
| **`$1`** | Client Source IP | Identifies the attacker/visitor origin address. |
| **`$4` / `$5**` | Date and Time Window | Establishes timelines, attack velocity, and correlation. |
| **`$6`** | HTTP Method (Verb) | Reveals action intent (`GET` for reading, `POST` for submission). |
| **`$7`** | Requested URI/Endpoint | Pinpoints the target application pathway or exploit location. |
| **`$9`** | HTTP Status Code | Confirms success (`200`/`302`) vs. failure (`401`/`403`/`404`). |
| **`$10`** | Bytes Sent | Anomalous large values indicate potential exfiltration. |
| **`$12`** | User-Agent String | Identifies automation frameworks, scanners, or client browsers. |

---

## 🛠️ The Core Forensic Commands

### 1. Source IP Profiling

Use these to isolate high-frequency actors or verify traffic volumes during DoS/brute-force events.

* **Extract Top 10 Most Active IP Addresses:**
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -n 10

```


* **Count Total Unique IP Addresses Active in the Log:**
```bash
awk '{print $1}' access.log | sort -u | wc -l

```


* **Filter Log Entries Exclusively From a Target Attacker IP:**
```bash
grep "^54.145.34.34" access.log

```



### 2. Endpoint & Resource Auditing

Identify which application routes are being targeted or discovered via directory brute-forcing.

* **Find the Most Heavily Requested Endpoints:**
```bash
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head -n 10

```


* **Isolate High-Frequency Endpoints Targeted by a Specific IP:**
```bash
grep "^54.145.34.34" access.log | awk '{print $7}' | sort | uniq -c | sort -rn

```


* **Identify 404 Directory Scanning Activity:**
```bash
awk '$9 == 404 {print $7}' access.log | sort | uniq -c | sort -rn | head -n 10

```



### 3. User-Agent Analysis

Spot malicious automated tooling or specific programming language libraries interacting with the app.

* **List All Unique User-Agents (Cleaned of Quotes):**
```bash
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn

```


*(Note: Using `-F'"'` splits the line by double quotes, making field `$6` the full User-Agent string seamlessly).*
* **Look specifically for common attack tool footprints (sqlmap, nmap, nikto):**
```bash
grep -iE "(sqlmap|nmap|nikto|dirbuster|gobuster)" access.log | awk '{print $1}' | sort -u

```



---

## 🩺 System Authentication & Linux Logs (`auth.log` / `secure`)

When tracking lateral movement, credential stuffing, or privilege escalation inside a Linux host.

### 1. SSH Tracking

* **Count Successful SSH Logins by IP:**
```bash
grep "Accepted password for" /var/log/auth.log | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort | uniq -c | sort -rn

```


* **Track Most Frequently Targeted Accounts During Brute-Forcing:**
```bash
grep "Failed password for" /var/log/auth.log | awk '{for(i=1;i<=NF;i++) if($i=="for") print $(i+1)}' | sort | uniq -c | sort -rn

```



### 2. Sudo & Account Activity

* **List Every Executed Sudo Command Chronologically:**
```bash
grep "COMMAND=" /var/log/auth.log | awk -F'COMMAND=' '{print $2}'

```


* **Identify Newly Created System User Accounts:**
```bash
grep -E "new user" /var/log/auth.log | awk '{print $8}' | sed 's/name=//'

```



---

## 🎛️ String Manipulation & Cleaning Tricks

When crafting flexible scripts, text artifacts from logs must often be parsed out. Use these text-shaping primitives:

```
                            ┌───────────────────┐
                            │ Raw: "name=Jax,"   │
                            └─────────┬─────────┘
                                      │
                             sed 's/name=//'
                                      │
                                      ▼
                            ┌───────────────────┐
                            │    Refined: "Jax,"│
                            └─────────┬─────────┘
                                      │
                              sed 's/,$//'
                                      │
                                      ▼
                            ┌───────────────────┐
                            │    Cleaned: "Jax" │
                            └───────────────────┘

```

* **Strip Out Character Patterns Globally (`tr -d`):**
```bash
tr -d '"'   # Deletes all quotation marks from the pipeline stream
tr -d '[]'  # Deletes brackets (useful for stripping timestamp enclosures)

```


* **In-Line String Replacement with Stream Editor (`sed`):**
```bash
sed 's/TargetString/Replacement/g' # Swaps terms globally
sed 's/,$//'                       # Deletes a comma ONLY if it sits at the absolute end of a line

```


* **Flattening Vertical Rows into Comma-Separated Data:**
```bash
paste -sd ","

```


*Transforms a list like:*
```text
user1
user2

```


*Into:* `user1,user2`
