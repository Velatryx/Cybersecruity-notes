Identify the Attack Source                                                 
     
  
                  Create  a Bash script to identify the IP address responsible for the most  requests in a log file, which is likely the source of a Denial of  Service (DoS) attack.
Functionality:
• Extract IP addresses from the log file.

• Count the occurrences of each IP address.

• Identify and print the IP address with the highest number of requests.

• Log File  : logs.txt


TIP: see which Ip had the most requests
┌──(oumaima㉿hbtn-lab)-[…/web_application_security/0x0b_web_application_fast_incident_response]
└─$  ./0-attack_ip.sh
**.***.**.**


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0b_web_application_fast_incident_response
            ◇ File: 0-attack_ip.sh
        
==================================================================
#!/bin/bash

file=logs.txt
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" "$file" | sort | uniq -c | sort -rn | head -1 | awk '{print $2}'

Explanation:
# grep -o is for showing only the matching part, not the whole line
# grep -E is for extended regex
# \b is for establishing a word boundary. For instance if used without \b, grepping cat would also show cat, catnip, cats
we just want exact cat.
# [0-9] means anything 0 to 9
# {1,3} is for repeating this [0-9] 3 times (xxx instead of x)
# \. Escaping dot to separate octets
# () wrapping
# {3} to repeat this for first three octets -> xxx.xxx.xxx.
# closing with the same regex: [0-9]{1,3} to avoid a . in the end -> xxx.xxx.xxx.

# | sort | is for sorting to make duplicates grouped 
# | uniq -c | is for counting the number of repeated ips -> Output: 20 10.0.0.1; 10 20.0.0.2
# | sort -rn | -> sorting the numbers from “uniq -c” -r reverse (sort goes from lowest to highest, we make it go from highest to lowest.), -n numerically (we use it to indicate we dont want the sorting alphabetical, but rather numerical)
# head -1, grepping the highest number (most repeated IP)
# awk ‘{print $2}’ is to print only the IP address and not the number from uniq -c.

---

    
       1. Identify the Attacked Endpoint                                                 
     
  
                  Create  a Bash script to find the endpoint (URL) that received the most  requests, indicating it was likely the target of the attack.
Functionality:
• Extract the requested URLs from the log file.

• Count the occurrences of each endpoint and identify the most frequently requested one.


TIP: try to find where the most request have been sent
┌──(oumaima㉿hbtn-lab)-[…/web_application_security/0x0b_web_application_fast_incident_response]
└─$  ./1-endpoint.sh 
/


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0b_web_application_fast_incident_response
            ◇ File: 1-endpoint.sh
        
      
============================================
Sample: 
51.158.115.139 - - [14/Jun/2024:17:25:12 +0000] "GET / HTTP/1.1" 200 1887 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
51.158.115.139 - - [14/Jun/2024:17:26:04 +0000] "POST / HTTP/1.1" 200 1941 "http://75.101.231.9:4001/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"

54.145.34.34 - $1
- $2
- $3
[14/Jun/2024:17:26:35 - $4
+0000] - $5
"POST - $6
/ - $7

We need the endpoint. So choose $7
-------------------------------------------------------
Script:

#!/bin/bash

file=logs.txt

awk ‘{print $7}’ “$file” | sort | uniq -c | sort -rn | head -1 | awk ‘{print $2}’
# -n flag is for the command, not the content 

---

    
       2.  Count the Number of Requests by the Attacker                                                 
     
  
                  Create  a Bash script to determine how many requests the attacker has sent,  where the attacker is identified as the IP address with the highest  number of requests.
Requirements:
• The script should accept a log file as input.
• It should:1. Identify the IP address with the most requests (assumed to be the attacker).
2. Count the total number of requests made by that IP address.


┌──(oumaima㉿hbtn-lab)-[…/web_application_security/0x0b_web_application_fast_incident_response]
└─$  ./2-count_attack.sh
5000


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0b_web_application_fast_incident_response
            ◇ File: 2-count_attack.sh
        
===========================================
51.158.115.139 - - [14/Jun/2024:17:25:12 +0000] "GET / HTTP/1.1" 200 1887 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
51.158.115.139 - - [14/Jun/2024:17:26:04 +0000] "POST / HTTP/1.1" 200 1941 "http://75.101.231.9:4001/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"


Script:

#!/bin/bash

file=logs.txt

awk '{print $1}' $file | sort | uniq -c | sort -rn | head -1 | awk ‘{print $1}’

#We need to identify how many requests ATTACKER made, not how many requests was made in total.

---


    
       3. Identify the Library Used by the Attacker                                                 
     
  
                  Create a Bash script to find out which tool or library the attacker used by analyzing the User-Agent strings.
Functionality:
• Filter the log for requests made by the attacker.

• Extract and count the User-Agent strings to identify the tool/library used.


┌──(oumaima㉿hbtn-lab)-[…/web_application_security/0x0b_web_application_fast_incident_response]
└─$  ./3-library.sh
python-requests/2.31.0


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0b_web_application_fast_incident_response
            ◇ File: 3-library.sh
        
==================================================

51.158.115.139 - - [14/Jun/2024:17:25:12 +0000] "GET / HTTP/1.1" 200 1887 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
51.158.115.139 - - [14/Jun/2024:17:26:04 +0000] "POST / HTTP/1.1" 200 1941 "http://75.101.231.9:4001/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"
54.145.34.34 - - [14/Jun/2024:17:26:35 +0000] "POST / HTTP/1.1" 200 1941 "-" "python-requests/2.31.0" "-"

Script:

#!/bin/bash

file=logs.txt

awk '{print $12}' $file | sort | uniq -c | sort -rn | head -1 | tr -d '"' | awk '{print $2}' 

#tr -d deletes the string
#tr ‘a’ ‘b’ replaces a with b. tr ‘"’ ‘’ wont work.
