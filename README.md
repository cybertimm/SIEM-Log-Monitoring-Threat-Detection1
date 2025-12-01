# SIEM-Log-Monitoring-Threat-Detection1

**Environment:** Splunk SIEM Lab

**Data Sources:**

- Linux SSH Authentication Logs (`linux_s_30DAY.log`) linux_s_30DAY
- Database Audit Logs (`db_audit_30DAY.csv`)
- Project requirements from SOC Analyst Labs Guide SOC_Analyst_Hands_on_Projects_1…

# **Executive Summary**

Between *October 26, 2025*, multiple high-volume brute-force attacks were launched against the Linux server `www1`. The attacks originated from **several external IP addresses**, repeatedly attempting to log in as privileged users such as `root`, `postgres`, `oracle`, and `backup`.

In multiple instances, attackers attempted **hundreds of password guesses** within short time periods. These attacks were unsuccessful, but valid internal users (`nsharpe`, `djohnson`, `myuan`) logged in around the same windows of time and escalated privileges using `sudo` and `su`.

**No confirmed account compromise** was observed, but due to sustained brute-force attempts and privilege escalations by internal users, the overall activity required full review.

Database audit logs were reviewed and **no suspicious database activity** was identified.

# **Incident Timeline Summary**

### **October 26, 2025 — 08:00 to 09:00 UTC**

- First wave of brute-force attempts from **208.65.153.253**, targeting:
    - `zabbix`
    - `operator`
    - `dba`
        
        *Source evidence:* Failed password events recorded in the log. 
        linux_s_30DAY
      ![Detected Brute Force](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/DetectedBruteForce2.png)

        

### **08:41–08:49 UTC**

- Large brute-force burst from **202.179.8.245**, targeting:
    - `root` (20+ attempts)
    - `nobody`
    - `db`
    - `oracle`
    - `postgres`
    - `harrypotter` (invalid user)
    - `mantis`
    - `redmine`
        
        This represents a high-intensity automated attack.
        
        *Evidence:* Multiple consecutive “Failed password for root” entries. 
        linux_s_30DAY
         ![Brute Force Threshold](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/Brute%20Force%20Threshold%201.png)

         ![Splunk Search Screenshot](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/Search%20_%20Splunk%2010.0.2%20-%20Google%20Chrome%2029_11_2025%2002_14_04.png)


### **10:49 UTC**

- Valid logins:
    - `nsharpe` from internal IP `10.2.10.163`
    - `djohnson` from internal IP `10.3.10.46`
    - `myuan` from internal IP `10.1.10.172`
        
        *Evidence:* “Accepted password” entries. 
        linux_s_30DAY
      ![Splunk Search Screenshot](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/Search%20_%20Splunk%2010.0.2%20-%20Google%20Chrome%2029_11_2025%2003_28_08.png)

        
- Privilege escalation:
    - `su` session opened for `root` by `djohnson`
        
        *Evidence:* `su: pam_unix(su:session): session opened for user root`. 
        linux_s_30DAY

        

### **10:51–11:12 UTC**

- Second attack wave from **142.162.221.28**, attempting:
    - `guest`
    - `oracle`
    - `git`
    - `gustavo`
    - `postgres`
    - `administrator`
        
        *Evidence:* Failed SSH attempts from this IP. 
        linux_s_30DAY
        ![Detected Brute Force](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/DetectedBruteForce.png)


### **11:03–12:58 UTC**

- Continuous valid login + logout activity from internal users:
    - `nsharpe`
    - `djohnson`
    - `myuan`
- Multiple privilege escalations using `sudo` and `su`.
    
    *Evidence:* `sudo:` and `su:` session logs. 
    linux_s_30DAY
    

### **12:19–13:15 UTC**

Multiple brute-force events from the following external IPs:

- **107.3.146.207**
- **192.162.19.179**
- **148.107.2.20**
- **198.35.2.120**
- **49.212.64.138**

All targeted common accounts like:

- `postgres`
- `mysql`
- `guest`
- `admin`
- `db2inst1`
- `etc.`
    
    *Evidence:* Repeated failed login attempts across the logs. 
    linux_s_30DAY
    ![Splunk Search Screenshot](https://raw.githubusercontent.com/cybertimm/SIEM-Log-Monitoring-Threat-Detection1/main/Search%20_%20Splunk%2010.0.2%20-%20Google%20Chrome%2029_11_2025%2004_35_45.png)


# **Threat Analysis**

## **Attack Type: SSH Brute-Force (Automated)**

**Severity:** High

**Description:**

Automated scripts attempted thousands of username/password combinations targeting privileged accounts such as:

- `root`
- `postgres`
- `oracle`
- `backup`
- `nobody`
- `sysadmin`
    
    *Evidence:* Repeated “Failed password for … from <IP>” sequences. 
    linux_s_30DAY
    

**Indicators of Automation:**

- Very high frequency per second
- Attempts cycling through usernames
- Multiple global IPs within hours
- Consistent behavior across attacking IPs

## **Privilege Escalation (Legitimate Users)**

**Severity:** Medium

**Description:**

Internal users performed privilege escalation using `sudo` and `su`, often shortly after login.

Example:

- `sudo: nsharpe ; USER=root ; COMMAND=/bin/su`
- `su: session opened for user root by djohnson(uid=0)`
    
    *Evidence:* `/bin/su` and `sudo` entries. 
    linux_s_30DAY
    

**Assessment:**

These actions *appear legitimate* but occurred during ongoing attacks, requiring context review.

## **Possible Lateral Movement (Internal Logins)**

Repeated internal logins occurred from IP ranges:

- `10.1.10.x`
- `10.2.10.x`
- `10.3.10.x`

This pattern is **normal for enterprise operations**, but could also indicate:

- Bastion hosts
- Admin jump servers
- Remote internal movement

No evidence of malicious lateral movement found.

Logins matched expected user accounts.

## **Database Activity Review**

The DB audit log (`db_audit_30DAY.csv`) contains login/query events.

Review checklist:

- No failed DB logins tied to attacker IPs
- No privileged schema changes
- No bulk SELECT queries against sensitive tables
- No DROP, DELETE, or permission changes

**Conclusion:** No suspicious database activity identified.

# **Indicators of Compromise (IOCs)**

### **Top Attacking IPs Identified**

| IP Address | Notes |
| --- | --- |
| 202.179.8.245 | Highest-volume brute-force activity |
| 208.65.153.253 | Early brute-force attempts |
| 142.162.221.28 | Persistent scanning |
| 87.194.216.51 | Repeated root attempts |
| 198.35.2.120 | Targeted brute-force on multiple accounts |
| 148.107.2.20 | Sustained attack for > 3 minutes |
| 60.18.93.11 | Wide username enumeration |

*All confirmed by SSH log entries.* 
linux_s_30DAY

# **MITRE ATT&CK Mapping**

| Behavior | MITRE Technique | Evidence |
| --- | --- | --- |
| SSH brute-force | **T1110 – Brute Force** | Thousands of "Failed password" entries |
| Account discovery | **T1087 – Account Discovery** | Attackers cycled through ~50+ usernames |
| Privilege escalation | **T1068 / T1078** | Use of sudo + su by internal users |
| Unauthorized access attempts | **T1078 – Valid Accounts** | Attempts to access root, postgres, oracle |

---

# **Impact Assessment**

### **No successful external compromise observed.**

All “Accepted password” logins came from **internal corporate IPs**.

No signs of:

- Data exfiltration
- Malware execution
- Unauthorized DB access
- Root compromise by external IP

However, the persistent brute-force attempts indicate:

- The system is highly targeted
- Password policies may need improvement
- No network-level blocking was detected

# **Recommendations**

### **Immediate (High Priority)**

1. **Enable fail2ban / SSH rate-limiting**
    
    Block IPs after 5–10 failed attempts.
    
2. **Disable password authentication**
    
    Move to **SSH key-based auth** where possible.
    
3. **Implement network geo-blocking**
    
    If the server shouldn’t be accessed globally.
    
4. **Enable MFA for admin accounts**
    
    Prevents brute-force even if a password leaks.
    

### **Short-Term**

1. **Rotate credentials for high-value accounts**
    - `root`
    - `postgres`
    - `oracle`
    - Any admin-level users
2. **Increase logging on DB activity**
    
    Alert on:
    
    - Bulk SELECT
    - Privilege changes
    - Failed logins
3. **Tune SIEM alerts**
    - Brute-force threshold alert
    - Successful login after failures
    - Privilege escalation monitoring

### **Long-Term**

1. **Move SSH behind a VPN or bastion host**
    
    Reduces external attack surface.
    
2. **Conduct periodic threat hunting**
    
    Using SPL/KQL queries to detect:
    
    - Anomalous logins
    - Rare commands
    - Lateral movement patterns

# **Final Conclusion**

The Linux server experienced **multiple large-scale brute-force attacks** over a 6-hour period from external IPs distributed globally. The attacks targeted privileged accounts but **none were successful**.

Internal users authenticated legitimately and performed expected administrative actions, including `sudo`/`su` operations. No suspicious database activity was found.

**Overall risk rating:** **Medium**

No compromise occurred, but the attack volume shows the server is an active target and requires improved hardening.
