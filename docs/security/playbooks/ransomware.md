# Ransomware Response Playbook

**Playbook ID:** PB-002
**Version:** 1.0
**Last Updated:** 2026-02-21
**Severity:** P1 (Critical)

---

## 1. Overview

### 1.1 Definition

Ransomware is a type of malicious software that encrypts files or systems, rendering them inaccessible until a ransom is paid. Modern ransomware often includes data exfiltration (double extortion) and threatens to publish stolen data if payment is not made.

### 1.2 Scope

This playbook covers:

- Encryption-based ransomware
- Data exfiltration ransomware (double/triple extortion)
- Ransomware-as-a-Service (RaaS) attacks
- Supply chain ransomware infections
- Cloud-focused ransomware

### 1.3 Objectives

1. Prevent ransomware spread across the network
2. Preserve systems for forensic analysis
3. Restore operations from clean backups
4. Determine if data was exfiltrated
5. Make informed decision on ransom payment (generally NOT recommended)
6. Report to law enforcement

---

## 2. Detection and Initial Response

### 2.1 Common Indicators

| Indicator               | Description                                               | Priority |
| ----------------------- | --------------------------------------------------------- | -------- |
| File encryption         | Files with changed extensions (.locked, .encrypted, etc.) | Critical |
| Ransom note             | README files with payment instructions                    | Critical |
| System slowdown         | High CPU/disk usage from encryption process               | High     |
| Failed backups          | Backup systems targeted by attackers                      | High     |
| Lateral movement        | Suspicious network connections between systems            | High     |
| Disabled security tools | Antivirus/EDR disabled or deleted                         | Critical |

### 2.2 Common Ransomware Families

| Family         | Characteristics                 | Notable Behaviors                         |
| -------------- | ------------------------------- | ----------------------------------------- |
| LockBit        | Fast encryption, self-spreading | Deletes shadow copies, disables recovery  |
| BlackCat/ALPHV | Rust-based, highly configurable | Targets ESXi, uses triple extortion       |
| Clop           | Focus on data exfiltration      | Exploits zero-days, publishes stolen data |
| Play           | Simple but effective            | Targets backups first, no data leak site  |
| Akira          | Linux and Windows variants      | Targets SMBs, double extortion            |

### 2.3 Initial Assessment Questions

1. **What systems are affected?**
   - Number of systems
   - Criticality of affected systems
   - Geographic distribution

2. **Is the attack ongoing?**
   - Active encryption in progress
   - Lateral movement detected
   - Command & Control communication

3. **Is there evidence of data exfiltration?**
   - Large outbound transfers
   - Cloud storage uploads
   - Attacker communication claiming exfiltration

4. **What is the ransom demand?**
   - Amount demanded
   - Payment deadline
   - Payment cryptocurrency address

---

## 3. Response Procedures

### Phase 1: Emergency Response (0-15 minutes)

#### 3.1.1 Immediate Actions

```
PRIORITY 1: ISOLATE AFFECTED SYSTEMS
- Disconnect from network (physically or via VLAN)
- Do NOT power off if encryption is in progress (preserves memory forensics)
- Preserve running state for forensic analysis

PRIORITY 2: ALERT RESPONSE TEAM
- Declare P1 incident
- Activate incident response team
- Notify executive leadership

PRIORITY 3: PREVENT SPREAD
- Disable VPN access
- Block external RDP/SSH access
- Implement network segmentation
```

#### 3.1.2 Network Isolation

| Action             | Command/Method        | Owner             |
| ------------------ | --------------------- | ----------------- |
| Isolate VLAN       | Network admin console | Network Team      |
| Block external RDP | Firewall rule         | Security Engineer |
| Disable VPN        | VPN admin console     | IT Team           |
| Port shutdown      | Switch CLI            | Network Team      |

#### 3.1.3 Evidence Preservation

```bash
# DO NOT power off systems yet if possible
# Capture volatile data first:

1. Memory dump (if safe to do so)
   - Use tools like Magnet RAM Capture, DumpIt
   - Store on external media

2. Running processes
   - ps aux (Linux)
   - Get-Process (Windows PowerShell)

3. Network connections
   - netstat -an (Windows/Linux)
   - lsof -i (Linux)

4. Open files
   - lsof (Linux)
   - Resource Monitor (Windows)
```

### Phase 2: Containment (15 minutes - 2 hours)

#### 3.2.1 Identify Patient Zero

**Investigation Steps:**

1. Review authentication logs for initial access
2. Check email gateways for phishing
3. Analyze VPN logs for unauthorized access
4. Review endpoint detection alerts
5. Interview users about suspicious activity

#### 3.2.2 Stop the Spread

| Action                       | Details                                                 | Priority |
| ---------------------------- | ------------------------------------------------------- | -------- |
| Disable compromised accounts | All accounts used by attackers                          | Critical |
| Block C2 domains/IPs         | Update firewall and DNS filters                         | Critical |
| Patch entry vector           | Close vulnerability used for initial access             | High     |
| Scan for persistence         | Check for scheduled tasks, registry keys, startup items | High     |
| Review admin accounts        | Check for newly created privileged accounts             | High     |

#### 3.2.3 Identify Scope

**Systems to Check:**

- [ ] Production servers
- [ ] Development environments
- [ ] Backup systems
- [ ] Domain controllers
- [ ] Cloud resources (AWS, GCP, Azure)
- [ ] Container orchestration (Kubernetes)
- [ ] Database servers
- [ ] File shares and NAS devices
- [ ] User workstations
- [ ] Network infrastructure

### Phase 3: Eradication (2-8 hours)

#### 3.3.1 Malware Removal

```
WARNING: Do not attempt to clean infected systems
RECOMMENDATION: Rebuild from scratch or restore from clean backups

If cleaning is necessary:
1. Boot from trusted media
2. Scan with multiple AV/EDR tools
3. Verify removal with secondary scan
4. Check for rootkits and bootkits
```

#### 3.3.2 Backdoor Elimination

| Location        | What to Check                              |
| --------------- | ------------------------------------------ |
| Registry        | Run keys, services, Winlogon               |
| Scheduled Tasks | All scheduled tasks for suspicious entries |
| Services        | Non-standard services, service hijacks     |
| Startup Folders | User and system startup locations          |
| WMI             | WMI persistence (event subscriptions)      |
| AD              | GPO modifications, new admin accounts      |
| Cloud           | IAM policy changes, new access keys        |

### Phase 4: Recovery (8-48 hours)

#### 3.4.1 Backup Assessment

**Before Restoring:**

1. Verify backup integrity
   - Check backup dates (ensure pre-infection)
   - Scan backups for malware
   - Test restore on isolated system

2. Assess backup availability
   - Air-gapped/offline backups
   - Cloud backups (check for deletion)
   - Immutable backups

#### 3.4.2 Restoration Priority

| Priority | Systems                                           | RTO Target |
| -------- | ------------------------------------------------- | ---------- |
| 1        | Critical infrastructure (DNS, AD, authentication) | 4 hours    |
| 2        | Core services (gateway, API, database)            | 8 hours    |
| 3        | User-facing applications                          | 24 hours   |
| 4        | Development environments                          | 48 hours   |
| 5        | Non-critical systems                              | 72 hours   |

#### 3.4.3 Recovery Verification

- [ ] All systems patched and hardened
- [ ] EDR/antivirus reinstalled and updated
- [ ] Monitoring and logging restored
- [ ] Backups reconfigured and tested
- [ ] User access restored with MFA enforced
- [ ] Security controls validated

---

## 4. Ransom Payment Decision

### 4.1 General Policy

**OpenClaw does NOT recommend paying ransoms.**

Reasons:

- Payment does not guarantee decryption
- Payment funds criminal organizations
- Payment may violate sanctions laws
- Payment marks you as a paying target for future attacks

### 4.2 Decision Framework

If payment is being considered:

| Factor                 | Consideration                                              |
| ---------------------- | ---------------------------------------------------------- |
| Legal                  | Consult legal counsel regarding sanctions (OFAC)           |
| Insurance              | Contact cyber insurance provider                           |
| Feasibility            | Can operations continue without the data?                  |
| Decryption reliability | Research the ransomware family - do they actually decrypt? |
| Cost                   | Compare ransom to recovery costs                           |

### 4.3 If Payment is Required

1. Involve law enforcement
2. Use professional ransomware negotiators
3. Verify decryption capability before full payment
4. Document all transactions
5. Report payment to authorities

---

## 5. Communication Procedures

### 5.1 Internal Communication

| Timeframe | Audience       | Message                          |
| --------- | -------------- | -------------------------------- |
| 0-15 min  | Response Team  | P1 declared, initial scope       |
| 15-30 min | All Staff      | Work stoppage, preserve evidence |
| 1 hour    | Executive Team | Business impact, recovery ETA    |
| 4 hours   | Board          | Detailed briefing                |
| Ongoing   | All Staff      | Status updates every 4 hours     |

### 5.2 External Communication

| Scenario                     | Timing          | Channel                       |
| ---------------------------- | --------------- | ----------------------------- |
| Service outage               | Immediate       | Status page, Discord          |
| Data exfiltration confirmed  | Within 72 hours | User notification, regulatory |
| Law enforcement notification | Within 24 hours | FBI IC3, local field office   |
| Transparency report          | Post-recovery   | Blog post                     |

### 5.3 Law Enforcement Contact

**United States:**

- FBI Internet Crime Complaint Center (IC3): ic3.gov
- FBI local field office
- CISA: report@cisa.gov

**International:**

- Europol: europol.europa.eu
- National cyber security centers
- Local law enforcement

---

## 6. Special Considerations

### 6.1 Cloud Ransomware

If cloud resources are affected:

1. **Immediate Actions:**
   - Revoke all potentially compromised access keys
   - Enable CloudTrail/Activity logging
   - Check for unauthorized IAM changes
   - Review S3 bucket policies for public access

2. **Assessment:**
   - Check for resource deletion (EC2, S3 objects)
   - Review CloudFormation/CDK changes
   - Audit container image integrity
   - Check for cryptocurrency mining

### 6.2 Supply Chain Ransomware

If ransomware entered via third-party:

1. Identify the compromised vendor
2. Assess scope of vendor access
3. Revoke vendor access immediately
4. Coordinate with vendor's incident response
5. Review all vendor-delivered code/updates

### 6.3 Double/Triple Extortion

If attackers threaten to publish stolen data:

1. **Assess Data Exfiltration:**
   - Review logs for large outbound transfers
   - Check cloud storage access
   - Interview users about accessed data

2. **Response Options:**
   - Pre-emptive disclosure (if appropriate)
   - Legal injunction against publication
   - Negotiate deletion (not recommended)

3. **User Notification:**
   - If PII was accessed, follow data breach procedures
   - Provide identity protection services
   - Notify regulators as required

---

## 7. Prevention Measures

### 7.1 Technical Controls

| Control              | Implementation                                  |
| -------------------- | ----------------------------------------------- |
| Air-gapped backups   | Offline, immutable, tested regularly            |
| EDR/XDR              | Endpoint detection and response on all systems  |
| Network segmentation | VLANs, micro-segmentation, zero trust           |
| Email security       | Advanced threat protection, sandboxing          |
| Patch management     | Automated patching, vulnerability management    |
| MFA                  | Enforced on all accounts, especially privileged |
| Privilege management | Least privilege, just-in-time access            |

### 7.2 Administrative Controls

- Regular backup restoration testing
- Incident response drills
- Security awareness training (phishing)
- Vendor risk assessments
- Cyber insurance review

---

## 8. Post-Incident Activities

### 8.1 Forensic Analysis

- Preserve all evidence for potential prosecution
- Analyze ransomware sample (if obtained)
- Document attack timeline
- Identify all TTPs (Tactics, Techniques, Procedures)
- Share IOCs with industry partners

### 8.2 Recovery Validation

- Penetration testing of restored environment
- Vulnerability assessment
- Security control validation
- Backup restoration testing

### 8.3 Lessons Learned

- What allowed initial access?
- Why did detection fail or succeed?
- How effective was containment?
- What can be improved?

---

## 9. Tools and Resources

### 9.1 Decryption Tools

| Resource               | URL                                   |
| ---------------------- | ------------------------------------- |
| No More Ransom         | nomoreransom.org                      |
| ID Ransomware          | id-ransomware.malwarehunterteam.com   |
| Avast Decryption Tools | avast.com/ransomware-decryption-tools |
| Kaspersky Decryptors   | kaspersky.com/ransomware-decryptors   |

### 9.2 Intelligence Resources

| Resource           | Purpose          |
| ------------------ | ---------------- |
| VirusTotal         | Malware analysis |
| Any.Run            | Sandbox analysis |
| MalwareBazaar      | Malware samples  |
| Ransomware Tracker | C2 tracking      |

---

## 10. References

- [CISA Ransomware Guide](https://www.cisa.gov/stopransomware)
- [FBI Ransomware Overview](https://www.fbi.gov/investigate/cyber/ransomware)
- [NIST Ransomware Protection Guide](https://www.nist.gov/itl/smallbusinesscyber/cybersecurity-basics/ransomware)
- [No More Ransom Project](https://www.nomoreransom.org)
- [OpenClaw Incident Response Plan](../incident-response.md)

---

**Playbook Owner:** Security Team
**Review Date:** 2026-05-21
**Next Drill:** 2026-08-21
