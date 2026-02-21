# Insider Threat Response Playbook

**Playbook ID:** PB-003
**Version:** 1.0
**Last Updated:** 2026-02-21
**Severity:** P1 (Critical) - P2 (High)

---

## 1. Overview

### 1.1 Definition

An insider threat is a security risk that originates from within the organization, involving current or former employees, contractors, or business associates who have inside information concerning the organization's security practices, data, and computer systems.

### 1.2 Types of Insider Threats

| Type              | Description                          | Example                                |
| ----------------- | ------------------------------------ | -------------------------------------- |
| **Malicious**     | Intentional harm for personal gain   | Stealing IP for competitor, sabotage   |
| **Negligent**     | Careless actions causing harm        | Falling for phishing, misconfiguration |
| **Compromised**   | Account taken over by external actor | Credential theft, social engineering   |
| **Unintentional** | Accidental data exposure             | Sending email to wrong recipient       |

### 1.3 Objectives

1. Detect insider threat activity early
2. Investigate discreetly to avoid alerting the subject
3. Gather evidence while preserving legal admissibility
4. Minimize damage to organization
5. Coordinate with HR and Legal for appropriate action

---

## 2. Detection and Initial Response

### 2.1 Behavioral Indicators

| Indicator               | Description                                        | Priority |
| ----------------------- | -------------------------------------------------- | -------- |
| Unusual access patterns | Accessing systems outside normal hours or role     | High     |
| Data exfiltration       | Large downloads, USB usage, cloud uploads          | Critical |
| Privilege escalation    | Attempting to gain unauthorized access             | Critical |
| Policy violations       | Bypassing security controls, disabling protections | High     |
| Financial stress        | Sudden lifestyle changes, gambling debts           | Medium   |
| Disgruntled behavior    | Negative comments, performance issues              | Medium   |
| Job change activity     | Updating LinkedIn, interviews with competitors     | Medium   |

### 2.2 Technical Indicators

| Indicator                  | Detection Method                            |
| -------------------------- | ------------------------------------------- |
| Bulk file access           | DLP alerts, file server audit logs          |
| Email anomalies            | Large attachments to personal accounts      |
| Database queries           | Unusual SELECT statements, off-hours access |
| USB device usage           | Endpoint detection alerts                   |
| Cloud storage uploads      | CASB alerts, proxy logs                     |
| Print volume spikes        | Print server logs                           |
| VPN from unusual locations | Geo-impossible logins                       |

### 2.3 Initial Assessment Questions

1. **Who is the subject?**
   - Role and access level
   - Employment history
   - Recent performance/behavior changes

2. **What is the suspected activity?**
   - Specific actions observed
   - Systems/data involved
   - Duration of activity

3. **What is the potential impact?**
   - Sensitivity of accessed data
   - Potential for ongoing damage
   - External involvement

4. **Is there immediate risk?**
   - Active data exfiltration in progress
   - System sabotage capability
   - Violence or safety concerns

---

## 3. Response Procedures

### Phase 1: Discreet Investigation (0-24 hours)

#### 3.1.1 Confidentiality Protocol

```
CRITICAL: Maintain strict need-to-know
- Limit investigation team to essential personnel
- Do NOT alert the subject
- Use secure communication channels
- Document all actions with timestamps
```

**Authorized Personnel:**

- Security Lead
- Legal Counsel
- HR Representative
- Forensics Specialist (if needed)

#### 3.1.2 Initial Evidence Collection

| Evidence Type        | Collection Method            | Preservation       |
| -------------------- | ---------------------------- | ------------------ |
| System logs          | SIEM export, log aggregation | Write-once storage |
| File access records  | DLP system, file server logs | Hash verification  |
| Email records        | Email archive, journaling    | Legal hold         |
| Network traffic      | NetFlow, packet capture      | Encrypted storage  |
| Endpoint forensics   | EDR data, disk images        | Chain of custody   |
| Physical access logs | Badge records, CCTV          | Secure storage     |

#### 3.1.3 Subject Profiling

**Review:**

- [ ] Current role and responsibilities
- [ ] System access permissions
- [ ] Recent access requests/changes
- [ ] Projects and data access history
- [ ] Termination risk (if applicable)
- [ ] Personal circumstances (if known)

### Phase 2: Formal Investigation (24-72 hours)

#### 3.2.1 Evidence Analysis

**Analysis Priorities:**

1. **Scope of access**
   - What systems were accessed?
   - What data was viewed/downloaded?
   - When did access occur?

2. **Data exfiltration**
   - Volume of data transferred
   - Destination (email, cloud, USB, etc.)
   - Whether data left the organization

3. **Collaboration**
   - Communication with external parties
   - Coordination with other insiders
   - External actor involvement

#### 3.2.2 Legal and HR Coordination

| Action                       | Responsible Party | Timing               |
| ---------------------------- | ----------------- | -------------------- |
| Legal review of evidence     | Legal Counsel     | Before any action    |
| HR notification              | Security Lead     | Within 24 hours      |
| Employment law consultation  | Legal + HR        | Before termination   |
| Law enforcement coordination | Legal Counsel     | If criminal activity |

### Phase 3: Containment (Ongoing)

#### 3.3.1 Access Restriction Options

| Method           | Use Case               | Considerations            |
| ---------------- | ---------------------- | ------------------------- |
| Monitor only     | Investigation phase    | No subject awareness      |
| Restrict access  | Prevent further damage | May alert subject         |
| Disable accounts | Imminent threat        | Immediate action required |
| Physical removal | Safety concern         | Coordinate with security  |

#### 3.3.2 Containment Actions

```
IF ongoing data theft detected:
1. Implement silent monitoring
2. Restrict access to sensitive systems
3. Enable enhanced logging
4. Prepare for account suspension

IF sabotage risk identified:
1. Isolate critical systems
2. Revoke privileged access
3. Enable change approval workflows
4. Consider immediate suspension
```

### Phase 4: Resolution (72+ hours)

#### 3.4.1 Decision Points

| Scenario                   | Recommended Action           | Approval Required |
| -------------------------- | ---------------------------- | ----------------- |
| Negligent, minor impact    | Training, policy reminder    | Manager + HR      |
| Negligent, major impact    | Disciplinary action          | HR + Legal        |
| Malicious, no exfiltration | Termination, legal review    | Legal + Executive |
| Malicious, data stolen     | Termination, law enforcement | Executive         |
| Criminal activity          | Law enforcement, prosecution | Executive + Legal |

#### 3.4.2 Termination Procedures

**If termination is necessary:**

1. **Pre-termination:**
   - Disable all access (network, VPN, email, applications)
   - Preserve all evidence
   - Prepare final documentation
   - Coordinate with HR and Legal

2. **During termination:**
   - Collect company equipment
   - Escort from premises (if required)
   - Document return of assets
   - Obtain acknowledgment of policies

3. **Post-termination:**
   - Monitor for revenge attempts
   - Review access by former colleagues
   - Update access controls
   - Conduct lessons learned

---

## 4. Evidence Handling

### 4.1 Chain of Custody

```
Requirements:
- Document who collected evidence
- Timestamp all collection activities
- Track all access to evidence
- Maintain integrity (hashes)
- Secure storage with access controls
```

### 4.2 Legal Admissibility

| Requirement   | Implementation                     |
| ------------- | ---------------------------------- |
| Authenticity  | Verify source and integrity        |
| Best evidence | Original logs preferred            |
| Completeness  | Preserve context, not just content |
| Legality      | Ensure lawful collection           |

### 4.3 Documentation Standards

- All actions timestamped
- Investigator identity recorded
- Tools and methods documented
- Findings clearly stated
- Subject rights respected

---

## 5. Communication Protocols

### 5.1 Internal Communication

| Audience                 | Information Shared       | Channel         |
| ------------------------ | ------------------------ | --------------- |
| Investigation Team       | Full details             | Secure meeting  |
| Legal Counsel            | Evidence and findings    | Encrypted email |
| HR                       | Employment actions       | Secure meeting  |
| Executive Team           | Summary and decisions    | Briefing        |
| Manager (if not subject) | Limited operational info | Need-to-know    |

### 5.2 External Communication

**Generally NOT shared externally:**

- Subject identity
- Investigation details
- Evidence specifics

**May be shared with:**

- Law enforcement (if criminal)
- Legal counsel (privileged)
- External forensics (under NDA)

### 5.3 Subject Communication

**Principles:**

- Legal counsel approval required
- HR typically leads communication
- Document all interactions
- Maintain professional tone

---

## 6. Special Scenarios

### 6.1 Executive Insider Threat

**Additional Considerations:**

- Board notification
- External investigator (independence)
- Media management plan
- Regulatory implications
- Succession planning

### 6.2 Contractor/Third-Party Threat

**Actions:**

- Contract review (termination clauses)
- Vendor notification
- Access revocation across all systems
- Forensic analysis of vendor access

### 6.3 Compromised Insider

**If account is compromised rather than malicious:**

- Credential reset
- Malware scan
- Incident response for compromise
- User education
- May not require disciplinary action

---

## 7. Prevention and Detection

### 7.1 Preventive Controls

| Control              | Implementation                               |
| -------------------- | -------------------------------------------- |
| Background checks    | Pre-employment, periodic for sensitive roles |
| Least privilege      | Role-based access, regular reviews           |
| Separation of duties | Critical actions require multiple people     |
| Mandatory vacation   | Detects fraud requiring continuous presence  |
| Exit procedures      | Immediate access revocation, exit interviews |
| Security training    | Insider threat awareness                     |

### 7.2 Detective Controls

| Control             | Implementation                                |
| ------------------- | --------------------------------------------- |
| UEBA                | User and Entity Behavior Analytics            |
| DLP                 | Data Loss Prevention on endpoints and network |
| SIEM correlation    | Detect anomalous patterns                     |
| CASB                | Cloud Access Security Broker                  |
| Database monitoring | Query analysis, sensitive data access         |

---

## 8. Post-Incident Activities

### 8.1 Lessons Learned

- How was the threat detected?
- What controls failed or succeeded?
- How can detection be improved?
- What policy changes are needed?

### 8.2 Control Improvements

- Update access controls
- Enhance monitoring
- Revise policies
- Additional training

---

## 9. Legal and Ethical Considerations

### 9.1 Privacy Rights

- Employee monitoring policies must be documented
- Investigation scope should be proportional
- Personal data protection requirements apply
- Union agreements may apply

### 9.2 Labor Laws

- Wrongful termination risks
- Due process requirements
- Documentation requirements
- Union notification (if applicable)

### 9.3 Criminal Referral

**Criteria for law enforcement referral:**

- Clear criminal intent
- Significant financial impact
- Data theft with external transfer
- Sabotage or malware deployment

---

## 10. References

- [CISA Insider Threat Mitigation Guide](https://www.cisa.gov/insider-threat-mitigation)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/publications/detail/sp/800-207/final)
- [SEI Insider Threat Center](https://www.sei.cmu.edu/our-work/insider-threat-center/)
- [OpenClaw Incident Response Plan](../incident-response.md)

---

**Playbook Owner:** Security Team
**Review Date:** 2026-05-21
**Next Drill:** 2026-08-21
