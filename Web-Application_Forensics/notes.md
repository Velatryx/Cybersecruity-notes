The objective of this project is to develop scripts that analyze logs  from web application attacks. These logs contain crucial information  that can help us understand the nature of the attacks, identify the  attackers, and uncover the vulnerabilities exploited. By scrutinizing  these logs, we can gather actionable intelligence to strengthen our web  application's security posture.
Which service did the attackers use to gain access to the system?   Write a script that scan the logs and help you  figure what service was  used 
┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./0-service.sh 
34806 pam_unix(sshd:auth):
  20339 Failed
  14478 Invalid
    214 Address
    200 pam_unix(sshd:session):
    169 reverse
    118 Accepted
     44 Did
     20 error:
     20 Server
     10 subsystem
      9 syslogin_perform_logout:
      7 Received
      5 PAM
      5 Jax
      2 Bad
      1 new
      1 changed
      1 change
      1 Kayn
      1 Exiting


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0c_web_application_foresics
            ◇ File: 0-service.sh
      
 =======================================================================
 sample:
 Mai 18 15:27:23 app-1 sudo: pam_unix(sudo:session): session closed for user root
Mai 18 15:27:42 app-1 sudo:   Jax : TTY=pts/3 ; PWD=/opt/software/web/config ; USER=root ; COMMAND=/usr/bin/vi /opt/software/base/vmscripts/app/django_checkout.sh
Mai 18 15:27:42 app-1 sudo: pam_unix(sudo:session): session opened for user root by Jax(uid=0)
Mai 18 15:27:42 app-1 sudo: pam_unix(sudo:session): session closed for user root
Mai 18 15:33:36 app-1 sudo:   Jax : TTY=pts/3 ; PWD=/opt/software/web/config ; USER=root ; COMMAND=/usr/bin/patch -d /usr/lib/python2.5/site-packages -p1

Solution:
#!/bin/bash

awk '{print $5}' auth.log | cut -d'[' -f1 | sort | uniq -c | sort -nr



###awk '{print $6}' $file | sort | uniq -c | sort -rn

---


       1. Operation System                                                  
     
  
                  What is the operating system version of the targeted system
File Concerned is dmseg 
┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./1-operating.sh 
[    0.000000] Linux version 2.6.24-26-server (buildd@crested) (gcc version 4.2.4 (Ubuntu 4.2.4-1ubuntu3)) #1 SMP Tue Dec 1 18:26:43 UTC 2009 (Ubuntu 2.6.24-26.64-server)


                  Repo:
                  • GitHub repository: holbertonschool-cyber_security
            • Directory: web_application_security/0x0c_web_application_foresics
            • File: 1-operating.sh
        
      
  
========================================================

#!/bin/bash

grep "Linux version" dmesg

---

    
       2. Account Compromised                                                  
     
  
                  What is the name of the compromised account
* Tips: 
* Analyse last 1000 line of logs 
* Check if the user had multiple unsuccessful break in and then success  this will be mostly compromised account 
* Check for Suspected Activity 
┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./2-accounts.sh 
root



==============================================
#!/bin/bash

tail -n 1000 auth.log | grep -E "root" | sort | uniq -c | sort -nr | head -n 1 | awk '{print $12}'

---

Consider each unique IP address as representing a different attacker. How many distinct attackers gained access to the system
┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./3-ips.sh 
18


                  Repo:
                  • GitHub repository: holbertonschool-cyber_security
            • Directory: web_application_security/0x0c_web_application_foresics
            • File: 3-ips.sh
        
      
  
                


================================
#!/bin/bash 
grep "Accepted password for root" auth.log | grep -Eo '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sort -u | wc -l

---


How many rules have been added to the firewall
• Check the auth.log file for entries related to adding firewall rules.

┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./4-firewall.sh
6


                  Repo:
                  ◇ GitHub repository: holbertonschool-cyber_security
            ◇ Directory: web_application_security/0x0c_web_application_foresics
            ◇ File: 4-firewall.sh
        
      
============================================

#!/bin/bash
grep -iE "iptables" auth.log | grep "A INPUT" | sort -u | wc -l

---

    
       5. Users Accounts                                                 
     
  
                  Multiple accounts were created on the target system. What are the users?
Example: Aphelios,Debian-exim,Fido....
┌──(imen㉿hbtn-lab)-[…/web_application_security/0x0c_web_application_foresics]
└─$ ./5-users.sh
Aphelios,Debian-exim,Fido,Jax,Nidalee,Senna,dhg,messagebus,mysql,packet,sshd


                  Repo:
                  • GitHub repository: holbertonschool-cyber_security
            • Directory: web_application_security/0x0c_web_application_foresics
            • File: 5-users.sh
        
      
  
====================================
#!/bin/bash
grep -E "new user" auth.log | awk '{print $8}' | sed 's/name=//' | sed 's/,$//' | sort | uniq | paste -sd ","
