# Data Breach Response Playbook

**Playbook ID:** PB-001
**Version:** 1.0
**Last Updated:** 2026-02-21
**Severity:** P1 (Critical) - P2 (High)

---

## 1. Overview

### 1.1 Definition

A data breach is a security incident in which sensitive, protected, or confidential data is accessed, disclosed, or exfiltrated by an unauthorized individual.

### 1.2 Scope

This playbook covers breaches involving:

- User credentials (passwords, API keys, tokens)
- Personal Identifiable Information (PII)
- Financial information
- Proprietary source code
- System configurations and secrets

### 1.3 Objectives

1. Quickly contain the breach to prevent further data loss
2. Determine the scope and nature of compromised data
3. Meet regulatory notification requirements
4. Restore user trust through transparent communication
5. Implement measures to prevent recurrence

---

## 2. Detection and Initial Response

### 2.1 Common Indicators

| Indicator                | Description                                       | Data Source               |
| ------------------------ | ------------------------------------------------- | ------------------------- |
| Unusual database queries | Large volume SELECTs, off-hours access            | Database audit logs       |
| Abnormal data transfers  | Large outbound transfers, unusual destinations    | Network monitoring        |
| Unauthorized API access  | Unexpected API key usage patterns                 | API gateway logs          |
| User reports             | Users noticing suspicious account activity        | Support tickets           |
| Dark web monitoring      | Credentials for sale on dark web                  | Threat intelligence feeds |
| Anomalous file access    | Bulk file downloads, unusual file access patterns | File system audit logs    |

### 2.2 Initial Assessment Questions

1. **When did the breach occur?**
   - First evidence of unauthorized access
   - Duration of compromise

2. **What data was accessed?**
   - Data types involved
   - Volume of records
   - Sensitivity classification

3. **How was the data accessed?**
   - Attack vector
   - Compromised credentials/systems
   - Vulnerability exploited

4. **Who was affected?**
   - Number of users
   - Geographic distribution
   - Special categories (minors, EU residents)

---

## 3. Response Procedures

### Phase 1: Immediate Response (0-30 minutes)

#### 3.1.1 Declare Incident

```
ACTION: Incident Commander declares P1/P2 incident
NOTIFY: Response team via Slack #security-incidents
CREATE: GitHub Issue with label:security-incident, label:data-breach
```

#### 3.1.2 Initial Containment

| Priority | Action                         | Owner             | Details                                                     |
| -------- | ------------------------------ | ----------------- | ----------------------------------------------------------- |
| 1        | Isolate compromised systems    | Technical Lead    | Disconnect from network, preserve running state if possible |
| 2        | Revoke compromised credentials | Security Engineer | Rotate all potentially exposed keys/passwords               |
| 3        | Block attacker's access        | Security Engineer | Firewall rules, WAF blocks, account lockouts                |
| 4        | Enable enhanced logging        | Security Engineer | Increase log verbosity, enable packet capture               |

#### 3.1.3 Evidence Preservation

```bash
# Critical evidence to preserve immediately
1. Database audit logs (last 30 days minimum)
2. Application access logs
3. Network flow logs
4. Authentication logs
5. System snapshots/images
6. Running process lists
7. Network connection tables
```

### Phase 2: Investigation (30 minutes - 4 hours)

#### 3.2.1 Scope Determination

**Investigation Checklist:**

- [ ] Identify entry point
- [ ] Map attacker movement (lateral traversal)
- [ ] Determine data access timestamps
- [ ] Identify specific records accessed
- [ ] Check for data exfiltration evidence
- [ ] Review privileged account usage
- [ ] Analyze backup access

#### 3.2.2 Forensic Analysis

| Analysis Type      | Tools              | Purpose                     |
| ------------------ | ------------------ | --------------------------- |
| Log Analysis       | ELK Stack, Splunk  | Timeline reconstruction     |
| Network Forensics  | Wireshark, Zeek    | Data exfiltration detection |
| Memory Analysis    | Volatility         | Malware detection           |
| Disk Forensics     | Autopsy, FTK       | File access evidence        |
| Database Forensics | Native audit tools | Query analysis              |

#### 3.2.3 Data Classification

Classify compromised data by sensitivity:

| Classification | Examples                                        | Risk Level |
| -------------- | ----------------------------------------------- | ---------- |
| Critical       | User passwords, private keys, financial data    | Critical   |
| High           | Email addresses, phone numbers, API keys        | High       |
| Medium         | Usage data, preferences, non-sensitive metadata | Medium     |
| Low            | Public profile information                      | Low        |

### Phase 3: Containment and Eradication (4-24 hours)

#### 3.3.1 Full Containment

```
1. Complete isolation of affected systems
2. Disable compromised user accounts
3. Revoke and rotate ALL potentially exposed credentials
4. Patch exploited vulnerabilities
5. Implement additional monitoring
```

#### 3.3.2 Backdoor Removal

- Scan for persistence mechanisms
- Check for new user accounts
- Review scheduled tasks/cron jobs
- Verify integrity of critical binaries
- Review firewall rules for unauthorized changes

### Phase 4: Recovery (24-72 hours)

#### 3.4.1 System Restoration

| Step | Action                       | Verification            |
| ---- | ---------------------------- | ----------------------- |
| 1    | Restore from clean backups   | Hash verification       |
| 2    | Apply all security patches   | Vulnerability scan      |
| 3    | Re-enable services gradually | Functional testing      |
| 4    | Monitor for anomalies        | 24-48 hour watch period |

#### 3.4.2 User Protection Measures

- Force password resets for affected accounts
- Invalidate all active sessions
- Enable MFA requirement
- Provide identity protection services (if warranted)
- Issue new API keys

---

## 4. Communication Procedures

### 4.1 Internal Communication Timeline

| Time      | Audience               | Message                             |
| --------- | ---------------------- | ----------------------------------- |
| 0-15 min  | Response Team          | Incident declared, initial briefing |
| 15-30 min | Engineering Leadership | Scope and impact summary            |
| 1 hour    | Executive Team         | Business impact assessment          |
| 4 hours   | All Staff              | General awareness (if appropriate)  |
| 24 hours  | Board                  | Detailed briefing for P1 incidents  |

### 4.2 External Communication Timeline

| Timeframe       | Action                              | Owner               |
| --------------- | ----------------------------------- | ------------------- |
| Within 24 hours | Prepare holding statement           | Communications Lead |
| Within 72 hours | User notification (if required)     | Communications Lead |
| Within 72 hours | Regulatory notification (GDPR/CCPA) | Legal Counsel       |
| Within 72 hours | Blog post/transparency report       | Communications Lead |
| Ongoing         | Status page updates                 | Technical Lead      |

### 4.3 Regulatory Notification Requirements

| Regulation      | Trigger              | Timeline                   | Authority               |
| --------------- | -------------------- | -------------------------- | ----------------------- |
| GDPR            | Personal data breach | 72 hours                   | Supervisory Authority   |
| CCPA            | Unauthorized access  | Without unreasonable delay | California AG           |
| State Laws      | Varies by state      | Varies                     | State Attorneys General |
| Sector-Specific | If applicable        | Per regulation             | Relevant regulator      |

---

## 5. Special Considerations

### 5.1 Credential Breach

If user credentials were compromised:

1. **Immediate Actions:**
   - Force password reset for all affected accounts
   - Invalidate all active sessions
   - Check for credential stuffing attacks

2. **User Guidance:**
   - Advise users to change passwords on other services
   - Recommend password manager usage
   - Enable MFA instructions

3. **Monitoring:**
   - Watch for unusual login patterns
   - Monitor for account takeovers
   - Check for privilege escalation attempts

### 5.2 API Key Exposure

If API keys were exposed:

1. **Immediate:**
   - Revoke all exposed keys
   - Generate new keys for legitimate users
   - Block requests with old keys

2. **Analysis:**
   - Review API access logs for abuse
   - Check for unauthorized data access
   - Assess cost impact (if cloud resources abused)

### 5.3 Source Code Exposure

If proprietary code was accessed:

1. **Assessment:**
   - Identify exposed repositories
   - Check for embedded secrets in code
   - Review commit history for unauthorized changes

2. **Remediation:**
   - Rotate all secrets in code
   - Review access controls
   - Audit recent deployments

---

## 6. Post-Incident Activities

### 6.1 Immediate Review (24-48 hours)

- Document timeline of events
- Catalog all evidence collected
- Verify all containment measures effective
- Confirm no ongoing unauthorized access

### 6.2 Full Retrospective (1 week)

**Required Analysis:**

1. **Technical Root Cause**
   - Vulnerability exploited
   - Control failures
   - Detection gaps

2. **Response Effectiveness**
   - Time to detection
   - Time to containment
   - Communication effectiveness

3. **Impact Assessment**
   - Number of users affected
   - Data types compromised
   - Business impact

### 6.3 Improvement Actions

Common post-breach improvements:

- [ ] Enhanced monitoring and alerting
- [ ] Improved access controls
- [ ] Additional security training
- [ ] Updated incident response procedures
- [ ] Third-party security assessment
- [ ] Implementation of new security tools

---

## 7. Tools and Resources

### 7.1 Investigation Tools

| Category            | Tools                           |
| ------------------- | ------------------------------- |
| Log Analysis        | ELK Stack, Splunk, Graylog      |
| Database Audit      | Native audit features, pgaudit  |
| Network Monitoring  | Zeek, Suricata, Wireshark       |
| Forensics           | Volatility, Autopsy, FTK Imager |
| Threat Intelligence | MISP, VirusTotal, AlienVault    |

### 7.2 Communication Templates

See [communication-templates.md](../communication-templates.md):

- Initial breach notification
- User notification email
- Regulatory notification
- Public blog post template
- Status page updates

---

## 8. Escalation Criteria

Escalate to Executive Team if:

- > 10,000 users affected
- Financial data compromised
- Media attention likely
- Regulatory investigation initiated
- Law enforcement involvement
- Potential for class-action litigation

---

## 9. References

- [NIST SP 800-61: Computer Security Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [GDPR Breach Notification Requirements](https://gdpr.eu/article-33-breach-notification/)
- [CCPA Security Breach Notification](https://oag.ca.gov/privacy/ccpa)
- [OpenClaw Incident Response Plan](../incident-response.md)
- [OpenClaw Threat Model](../THREAT-MODEL-ATLAS.md)

---

**Playbook Owner:** Security Team
**Review Date:** 2026-05-21
**Next Drill:** 2026-08-21
