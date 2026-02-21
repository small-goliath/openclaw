# Security Incident Communication Templates

**Version:** 1.0
**Last Updated:** 2026-02-21
**Owner:** Security & Communications Team

---

## 1. Internal Communication Templates

### 1.1 Initial Incident Notification

**Channel:** Slack #security-incidents
**Timing:** Immediately upon incident declaration

```
:rotating_light: SECURITY INCIDENT DECLARED :rotating_light:

Incident ID: INC-YYYY-MM-DD-###
Severity: [P1/P2/P3/P4]
Type: [Data Breach/Ransomware/DDoS/Insider Threat/Other]
Detected: [Timestamp]

SUMMARY:
[Brief description of the incident]

IMMEDIATE ACTIONS:
- [Action 1]
- [Action 2]

INCIDENT COMMANDER: @username
RESPONSE TEAM: @user1 @user2 @user3

STATUS PAGE: [Link if external impact]
NEXT UPDATE: [Time]

---
DO NOT discuss externally. Direct questions to #security-incidents.
```

### 1.2 Status Update Template

**Channel:** Slack #security-incidents
**Timing:** Per severity schedule (P1: 30min, P2: 1hr, P3: 4hr)

```
:arrow_right: INCIDENT UPDATE - INC-YYYY-MM-DD-###

Time Elapsed: [X hours Y minutes]
Current Severity: [P1/P2/P3/P4]

PROGRESS SINCE LAST UPDATE:
- [Update 1]
- [Update 2]

CURRENT STATUS:
[Detailed current state]

NEXT ACTIONS:
- [Action 1] - Owner: @username
- [Action 2] - Owner: @username

ETA NEXT UPDATE: [Time]
```

### 1.3 All-Company Notification

**Channel:** Slack #general or Email
**Timing:** When incident has company-wide impact

```
Subject: Security Incident - Awareness Notice

Team,

We are currently responding to a security incident that may affect our operations.

WHAT HAPPENED:
[Brief, non-technical description]

CURRENT IMPACT:
[What employees may experience]

WHAT YOU SHOULD DO:
- Do not discuss this incident publicly or on social media
- Direct any external inquiries to security@openclaw.ai
- Report any suspicious activity to #security
- [Additional instructions specific to incident]

We will provide updates as the situation develops.

Incident Commander: [Name]
Security Team: security@openclaw.ai
```

### 1.4 Incident Resolution Notice

**Channel:** Slack #security-incidents
**Timing:** Upon incident closure

```
:white_check_mark: INCIDENT RESOLVED - INC-YYYY-MM-DD-###

Duration: [X hours Y minutes]
Final Severity: [P1/P2/P3/P4]

RESOLUTION SUMMARY:
[How the incident was resolved]

IMPACT SUMMARY:
[Final impact assessment]

FOLLOW-UP ACTIONS:
- [Action 1] - Owner: @username - Due: [Date]
- [Action 2] - Owner: @username - Due: [Date]

POST-INCIDENT REVIEW:
Scheduled: [Date/Time]
Attendees: [List]

Thank you to everyone who assisted with the response.
```

---

## 2. External Communication Templates

### 2.1 Status Page - Service Disruption

**Timing:** Immediate upon external impact

```
**Investigating - [Service Name]**

We are currently investigating reports of [issue description].

**Affected Services:**
- [Service 1]
- [Service 2]

**Impact:**
[Description of user impact]

**Started:** [Timestamp]

We will provide updates as more information becomes available.
```

### 2.2 Status Page - Update

**Timing:** Per update schedule

```
**Update - [Service Name]**

We have identified the cause of [issue] and are implementing a fix.

**Current Status:**
[Description of current state]

**Next Steps:**
[What we're doing next]

**ETA:** [Estimated resolution time or "No ETA yet"]

**Last Updated:** [Timestamp]
```

### 2.3 Status Page - Resolved

**Timing:** Upon full resolution

```
**Resolved - [Service Name]**

The issue affecting [service] has been resolved.

**Duration:** [X minutes/hours]
**Resolution:** [Brief description of fix]

All services are now operating normally. We apologize for any inconvenience.

A full incident report will be published within [timeframe].
```

### 2.4 User Email - Security Incident

**Timing:** Within 72 hours if user data potentially affected

```
Subject: Important Security Notice - OpenClaw Account

Dear [User Name],

We are writing to inform you of a security incident that may have affected your OpenClaw account.

**WHAT HAPPENED:**
On [Date], we discovered unauthorized access to [system description]. We immediately took action to secure the affected systems and launched a comprehensive investigation.

**WHAT INFORMATION WAS INVOLVED:**
The unauthorized party may have accessed:
- [Data type 1]
- [Data type 2]
- [Data type 3]

**WHAT WE ARE DOING:**
- We have secured the vulnerability that allowed this access
- We have engaged leading cybersecurity experts to assist our investigation
- We have notified law enforcement and relevant authorities
- We are implementing additional security measures

**WHAT YOU SHOULD DO:**
1. Change your OpenClaw password immediately
2. Enable two-factor authentication if you haven't already
3. Review your account for any suspicious activity
4. Be cautious of phishing emails claiming to be from OpenClaw

We sincerely apologize for this incident and any inconvenience it may cause. Protecting your data is our top priority.

If you have questions, please contact us at security@openclaw.ai or visit our security page at https://trust.openclaw.ai.

Sincerely,
[Name]
Security Team Lead
OpenClaw
```

---

## 3. Regulatory Notification Templates

### 3.1 GDPR Supervisory Authority Notification

**Timing:** Within 72 hours of becoming aware of breach

```
DATA BREACH NOTIFICATION
Article 33 GDPR

1. Nature of the personal data breach:
   [Description of breach type and circumstances]

2. Categories and approximate number of data subjects concerned:
   - Categories: [e.g., users, customers, employees]
   - Approximate number: [Number]

3. Categories and approximate number of personal data records concerned:
   - Categories: [e.g., names, emails, passwords]
   - Approximate number: [Number]

4. Likely consequences of the personal data breach:
   [Description of potential harm to data subjects]

5. Measures taken or proposed to be taken:
   - Containment measures: [Actions taken]
   - Mitigation measures: [Actions to protect data subjects]
   - Preventive measures: [Actions to prevent recurrence]

6. Contact details for further information:
   [DPO or responsible contact]

7. Cross-border nature:
   [Indicate if data subjects in multiple EU countries affected]
```

### 3.2 CCPA Notification to California AG

**Timing:** Without unreasonable delay

```
SECURITY BREACH NOTIFICATION
California Civil Code Section 1798.82

Reporting Entity: OpenClaw, Inc.
Date of Discovery: [Date]
Date of Breach: [Date or Date Range]

1. Breach Description:
   [Detailed description of incident]

2. Personal Information Involved:
   [List of CPII categories involved]

3. Number of California Residents Affected:
   [Number or "Unknown at this time"]

4. Notification Status:
   - Date individual notifications sent: [Date]
   - Method of notification: [Email/Mail/Substitute]

5. Law Enforcement Notification:
   [Indicate if law enforcement notified]

6. Contact Information:
   [Name, Title, Phone, Email]
```

---

## 4. Media and Public Communication

### 4.1 Media Holding Statement

**Use:** When media inquiries received before full statement ready

```
"We recently experienced a security incident and immediately took action to secure our systems and investigate. We are working with leading cybersecurity experts and have notified law enforcement. We are committed to transparency and will share more information as our investigation continues. The security of our users is our top priority."

For media inquiries: press@openclaw.ai
```

### 4.2 Blog Post - Security Incident Transparency

**Timing:** Post-resolution or per legal guidance

```
# Security Incident Report: [Date]

**Posted:** [Date]
**Category:** Security

We are sharing details about a security incident that affected OpenClaw on [Date]. Transparency is important to us, and we want to share what happened, what we did, and what we're doing to prevent similar incidents.

## What Happened

On [Date] at [Time], our security team detected [brief description of detection]. Upon investigation, we discovered that [description of incident].

## Impact Assessment

The incident affected approximately [number] users. The unauthorized party may have accessed:

- [Data type 1]
- [Data type 2]

We have no evidence that [data types NOT accessed].

## Our Response

Upon detection, we immediately:

1. Secured the vulnerability
2. Revoked affected credentials
3. Engaged forensic experts
4. Notified law enforcement
5. [Additional actions]

## What We're Doing

To prevent similar incidents, we are:

- [Improvement 1]
- [Improvement 2]
- [Improvement 3]

## What You Should Do

We recommend users:

1. [Action 1]
2. [Action 2]
3. [Action 3]

## Questions?

If you have questions or concerns, please contact us at security@openclaw.ai or visit our Trust Center at https://trust.openclaw.ai.

We apologize for this incident and appreciate your trust in OpenClaw.

[Name]
[Title]
```

### 4.3 Social Media Response

**Twitter/X Thread:**

```
Tweet 1/5:
We're aware of a security incident affecting OpenClaw. We take this seriously and want to share what we know. Thread 👇

Tweet 2/5:
On [Date], we detected unauthorized access to [system]. We immediately secured the affected systems and launched an investigation.

Tweet 3/5:
Approximately [number] users may be affected. We've notified affected users directly via email with specific guidance.

Tweet 4/5:
We've reported this to law enforcement and relevant authorities. Our investigation is ongoing with leading cybersecurity experts.

Tweet 5/5:
Full details: [link to blog post]
Questions: security@openclaw.ai
We'll share updates as our investigation continues.
```

---

## 5. Stakeholder-Specific Templates

### 5.1 Partner/Integration Notification

```
Subject: Security Incident - Partner Notification

Dear [Partner] Team,

We are notifying you of a security incident that may affect our integration.

INCIDENT SUMMARY:
[Description]

IMPACT ON INTEGRATION:
[Specific impact on partner systems/connection]

ACTIONS REQUIRED:
[If any partner action needed]

We will keep you updated as our investigation progresses.

Contact: security@openclaw.ai
```

### 5.2 Investor/Board Notification

```
Subject: Security Incident - Executive Summary

EXECUTIVE SUMMARY

Incident ID: INC-YYYY-MM-DD-###
Detection Date: [Date]
Current Status: [Active/Contained/Resolved]

BUSINESS IMPACT:
- Users affected: [Number]
- Services impacted: [List]
- Financial impact: [Estimate or TBD]
- Regulatory implications: [Summary]

RESPONSE ACTIONS:
- [Key action 1]
- [Key action 2]
- [Key action 3]

COMMUNICATION STATUS:
- Users notified: [Yes/No/Timeline]
- Regulators notified: [Yes/No/Timeline]
- Media: [Status]

NEXT STEPS:
[Key milestones and timeline]

Contact: [Incident Commander]
```

### 5.3 Law Enforcement Coordination

```
To: [Law Enforcement Agency]
From: OpenClaw Security Team
Date: [Date]
Re: Cybersecurity Incident Report

We are reporting a cybersecurity incident affecting OpenClaw systems.

INCIDENT SUMMARY:
- Detection Date: [Date]
- Incident Type: [Type]
- Affected Systems: [Description]

ATTACK DETAILS:
- Initial Vector: [If known]
- Attacker TTPs: [If known]
- Evidence of Attribution: [If any]

EVIDENCE PRESERVED:
- [List of preserved evidence]
- Chain of custody maintained: [Yes/No]

We request coordination on this investigation.

Primary Contact: [Name, Title, Phone, Email]
```

---

## 6. Communication Approval Matrix

| Communication Type      | Severity | Approver            | Legal Review       |
| ----------------------- | -------- | ------------------- | ------------------ |
| Internal Slack updates  | All      | Incident Commander  | No                 |
| All-company email       | P1/P2    | Incident Commander  | If external impact |
| Status page updates     | All      | Technical Lead      | No                 |
| User notification email | P2+      | Communications Lead | Yes                |
| Regulatory notification | All      | Legal Counsel       | Yes                |
| Media statement         | All      | Communications Lead | Yes                |
| Blog post               | All      | Communications Lead | Yes                |
| Social media            | All      | Communications Lead | Yes                |

---

## 7. Communication Best Practices

### 7.1 General Principles

1. **Be Transparent:** Share what you know when you can
2. **Be Accurate:** Verify facts before communicating
3. **Be Timely:** Communicate promptly, even with limited information
4. **Be Empathetic:** Acknowledge impact on users
5. **Be Actionable:** Provide clear next steps

### 7.2 What to Include

- What happened (facts only)
- When it happened
- What was affected
- What you're doing
- What users should do
- How to get more information

### 7.3 What to Avoid

- Speculation or unverified information
- Technical jargon (for external comms)
- Blame or excuses
- Over-promising on timelines
- Legal admissions without counsel review

### 7.4 Review Checklist

Before sending any external communication:

- [ ] Facts verified with technical team
- [ ] Legal counsel review (if required)
- [ ] Tone appropriate for audience
- [ ] Action items clear
- [ ] Contact information included
- [ ] No speculative statements
- [ ] Consistent with other communications

---

## 8. Template Customization Guide

### 8.1 Variables to Replace

| Variable       | Description          | Example                      |
| -------------- | -------------------- | ---------------------------- |
| [Date]         | Incident date        | 2026-02-21                   |
| [Time]         | Incident time        | 14:30 UTC                    |
| [Service Name] | Affected service     | OpenClaw Gateway             |
| [Number]       | Quantifiable impact  | 1,250                        |
| [P1/P2/P3/P4]  | Severity level       | P2                           |
| [Description]  | Incident description | Unauthorized database access |

### 8.2 Tone Adjustments

| Audience               | Tone                   | Language                 |
| ---------------------- | ---------------------- | ------------------------ |
| Internal technical     | Direct, detailed       | Technical terms OK       |
| Internal non-technical | Clear, concise         | Minimal jargon           |
| External users         | Empathetic, reassuring | Plain language           |
| Regulators             | Formal, precise        | Legal/technical accuracy |
| Media                  | Professional, factual  | Quote-ready statements   |

---

## 9. References

- [OpenClaw Incident Response Plan](./incident-response.md)
- [GDPR Article 33](https://gdpr.eu/article-33-breach-notification/)
- [CCPA Section 1798.82](https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?sectionNum=1798.82&lawCode=CIV)
- [NIST SP 800-61: Incident Communications](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)

---

**Document Owner:** Security & Communications Team
**Review Date:** 2026-05-21
**Questions:** security@openclaw.ai
