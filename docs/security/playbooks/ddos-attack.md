# DDoS Attack Response Playbook

**Playbook ID:** PB-004
**Version:** 1.0
**Last Updated:** 2026-02-21
**Severity:** P1 (Critical) - P2 (High)

---

## 1. Overview

### 1.1 Definition

A Distributed Denial of Service (DDoS) attack is a malicious attempt to disrupt the normal traffic of a targeted server, service, or network by overwhelming the target or its surrounding infrastructure with a flood of Internet traffic.

### 1.2 Attack Types

| Type                  | Description                  | Common Vectors                             |
| --------------------- | ---------------------------- | ------------------------------------------ |
| **Volumetric**        | Consume bandwidth            | UDP floods, ICMP floods, DNS amplification |
| **Protocol**          | Consume server resources     | SYN floods, Ping of Death, Smurf attack    |
| **Application Layer** | Target specific applications | HTTP floods, Slowloris, RUDY               |
| **Multi-vector**      | Combination of above         | Mixed attacks targeting multiple layers    |

### 1.3 Objectives

1. Maintain service availability during attack
2. Quickly identify and mitigate attack traffic
3. Minimize impact on legitimate users
4. Gather intelligence for attribution
5. Coordinate with upstream providers

---

## 2. Detection and Initial Response

### 2.1 Detection Indicators

| Indicator             | Description                  | Detection Method                |
| --------------------- | ---------------------------- | ------------------------------- |
| Sudden traffic spike  | Unusual volume increase      | NetFlow, SNMP monitoring        |
| Service degradation   | Slow response times          | APM tools, synthetic monitoring |
| Resource exhaustion   | High CPU/memory/network      | System monitoring               |
| Connection saturation | Maxed out connection tables  | Network device monitoring       |
| Geographic anomalies  | Traffic from unusual regions | GeoIP analysis                  |
| Pattern anomalies     | Repetitive requests          | WAF logs, application logs      |

### 2.2 Attack Classification

| Attack Vector        | Target Layer     | Mitigation Approach                       |
| -------------------- | ---------------- | ----------------------------------------- |
| UDP Flood (DNS, NTP) | Network (L3)     | Rate limiting, filtering                  |
| SYN Flood            | Transport (L4)   | SYN cookies, connection limits            |
| HTTP Flood           | Application (L7) | WAF rules, CAPTCHA, rate limiting         |
| Slowloris            | Application (L7) | Connection timeouts, request limits       |
| DNS Amplification    | Network (L3)     | Source validation, response rate limiting |

### 2.3 Initial Assessment Questions

1. **What is the attack target?**
   - Specific service or entire infrastructure
   - Public-facing or internal systems
   - Single IP or distributed

2. **What is the attack vector?**
   - Volumetric, protocol, or application layer
   - Single or multi-vector
   - Known attack type or novel

3. **What is the attack scale?**
   - Bandwidth volume (Gbps)
   - Packet rate (Mpps)
   - Connection rate

4. **Is there a ransom demand?**
   - Extortion email received
   - Ransom amount and deadline
   - Payment instructions

---

## 3. Response Procedures

### Phase 1: Immediate Response (0-15 minutes)

#### 3.1.1 Attack Confirmation

```
VERIFY: Not a legitimate traffic spike
- Check marketing campaigns
- Review product launches
- Confirm not viral content

IF confirmed attack:
  DECLARE: P1/P2 incident
  ACTIVATE: DDoS response team
  NOTIFY: Upstream providers
```

#### 3.1.2 Initial Triage

| Action                 | Owner             | Tool/Method                      |
| ---------------------- | ----------------- | -------------------------------- |
| Identify attack vector | Security Engineer | Traffic analysis, packet capture |
| Determine target       | Network Engineer  | NetFlow, load balancer logs      |
| Assess impact          | Technical Lead    | Service health dashboards        |
| Estimate scale         | Network Engineer  | Bandwidth monitoring             |

#### 3.1.3 Emergency Mitigation

```
IMMEDIATE ACTIONS:
1. Enable DDoS protection (Cloudflare, AWS Shield, etc.)
2. Activate rate limiting on edge devices
3. Scale up affected services (auto-scaling)
4. Enable aggressive caching
5. Block obvious attack sources (if identifiable)
```

### Phase 2: Active Mitigation (15 minutes - 2 hours)

#### 3.2.1 Traffic Analysis

**Analysis Steps:**

1. **Capture attack characteristics:**

   ```bash
   # Packet capture (sample)
   tcpdump -i eth0 -w attack_capture.pcap -c 10000

   # NetFlow analysis
   nfdump -R /var/log/nfdump 'src ip <attack_source>'
   ```

2. **Identify patterns:**
   - Source IP ranges
   - User-Agent strings
   - Request patterns
   - Payload signatures
   - Geographic distribution

3. **Distinguish legitimate traffic:**
   - Known good IP ranges
   - Authenticated users
   - API key patterns
   - Behavioral analysis

#### 3.2.2 Mitigation Techniques

| Layer       | Technique         | Implementation                 |
| ----------- | ----------------- | ------------------------------ |
| Network     | Blackhole routing | Null route attack traffic      |
| Network     | ACLs              | Filter by source IP/protocol   |
| Transport   | Rate limiting     | Connection/packet rate limits  |
| Application | WAF rules         | Block attack patterns          |
| Application | Challenge         | CAPTCHA, JavaScript challenges |
| Application | Geo-blocking      | Block high-risk countries      |
| CDN         | Caching           | Aggressive edge caching        |
| CDN         | DDoS protection   | Cloudflare/AWS Shield/etc.     |

#### 3.2.3 Provider Coordination

**Contact List:**

| Provider            | Contact    | Escalation        |
| ------------------- | ---------- | ----------------- |
| ISP/Upstream        | [REDACTED] | Account manager   |
| CDN/DDoS Protection | [REDACTED] | Emergency line    |
| Hosting Provider    | [REDACTED] | Support ticket    |
| DNS Provider        | [REDACTED] | Emergency contact |

**Information to Provide:**

- Attack start time
- Target IP/hostname
- Attack vector(s)
- Current bandwidth/packet rate
- Sample logs/pcaps

### Phase 3: Sustained Defense (2-24 hours)

#### 3.3.1 Adaptive Mitigation

```
CONTINUOUS MONITORING:
- Watch for vector changes
- Monitor legitimate user impact
- Adjust mitigation rules
- Track attack evolution
```

**Response to Attack Evolution:**

| Change                     | Response                            |
| -------------------------- | ----------------------------------- |
| New attack vector          | Deploy additional rules             |
| Increased volume           | Engage additional scrubbing centers |
| Target switch              | Protect new targets                 |
| Legitimate traffic blocked | Refine filters                      |

#### 3.3.2 Service Maintenance

**During Attack:**

- [ ] Monitor service health
- [ ] Communicate with users
- [ ] Scale resources as needed
- [ ] Maintain backup systems
- [ ] Document all actions

### Phase 4: Recovery and Analysis (24+ hours)

#### 3.4.1 Attack Cessation

**Verification:**

- Monitor for 2+ hours post-attack
- Gradually remove mitigation rules
- Verify service performance
- Check for follow-up attacks

#### 3.4.2 Forensic Analysis

**Data Collection:**

| Data Type       | Retention | Analysis          |
| --------------- | --------- | ----------------- |
| Packet captures | 30 days   | Attack signatures |
| NetFlow         | 90 days   | Source analysis   |
| WAF logs        | 90 days   | Attack patterns   |
| System logs     | 90 days   | Impact assessment |

---

## 4. Ransom DDoS (RDDoS)

### 4.1 Ransom Demand Response

**If ransom demand received:**

1. **DO NOT PAY** - Payment encourages continued attacks
2. Document the demand (screenshots, emails)
3. Report to law enforcement
4. Prepare for potential attack
5. Notify upstream providers proactively

### 4.2 Common RDDoS Groups

| Group             | Characteristics     | Typical Demand |
| ----------------- | ------------------- | -------------- |
| Fancy Bear        | State-affiliated    | Varies         |
| DD4BC             | Bitcoin extortion   | 1-50 BTC       |
| Armada Collective | High-volume threats | 10-50k USD     |
| Copycat groups    | Fake threats        | Varies         |

---

## 5. Communication Procedures

### 5.1 Internal Communication

| Timeframe | Audience      | Message                                       |
| --------- | ------------- | --------------------------------------------- |
| 0-15 min  | Response Team | Attack confirmed, initial mitigation          |
| 15-30 min | Engineering   | Service impact, resource scaling              |
| 30 min    | Executive     | Business impact summary                       |
| 1 hour    | All Staff     | Awareness, no customer comms without approval |
| Ongoing   | Response Team | Status every 30 minutes                       |

### 5.2 External Communication

| Channel         | Timing        | Content                         |
| --------------- | ------------- | ------------------------------- |
| Status Page     | Immediate     | Service degradation notice      |
| Twitter/Discord | Within 1 hour | Acknowledgment, no ETA yet      |
| User Email      | If >1 hour    | Detailed status and workarounds |
| Blog Post       | Post-incident | Transparency report             |

### 5.3 Communication Templates

See [communication-templates.md](../communication-templates.md) for:

- Initial status update
- Service degradation notice
- All-clear notification
- Post-incident summary

---

## 6. Prevention and Hardening

### 6.1 Architectural Defenses

| Defense         | Implementation                                |
| --------------- | --------------------------------------------- |
| CDN             | Cloudflare, Fastly, AWS CloudFront            |
| DDoS Protection | AWS Shield Advanced, Cloudflare Magic Transit |
| Load Balancing  | Multi-region, auto-scaling                    |
| Anycast         | Geographic distribution                       |
| Redundancy      | Multi-cloud, failover systems                 |

### 6.2 Configuration Hardening

```
NETWORK LEVEL:
- Enable SYN cookies
- Implement connection rate limiting
- Configure proper timeouts
- Disable unused services
- Filter RFC 1918 and bogon addresses

APPLICATION LEVEL:
- Implement request rate limiting
- Enable caching layers
- Optimize database queries
- Configure auto-scaling policies
- Implement circuit breakers
```

### 6.3 Monitoring and Alerting

| Metric           | Threshold      | Alert |
| ---------------- | -------------- | ----- |
| Bandwidth        | >150% baseline | P1    |
| PPS              | >150% baseline | P1    |
| Connection count | >100% capacity | P1    |
| Error rate       | >5%            | P2    |
| Response time    | >2x baseline   | P2    |

---

## 7. Post-Incident Activities

### 7.1 Attack Analysis

**Questions to Answer:**

1. What was the attack vector?
2. What was the peak volume?
3. How long did the attack last?
4. What was the impact on users?
5. How effective were mitigations?
6. What could be improved?

### 7.2 Improvement Actions

- [ ] Update WAF rules with new signatures
- [ ] Adjust rate limiting thresholds
- [ ] Enhance monitoring coverage
- [ ] Update runbook with lessons learned
- [ ] Conduct tabletop exercise
- [ ] Review and update DDoS protection service

---

## 8. Tools and Resources

### 8.1 DDoS Protection Services

| Service        | Type       | Use Case                |
| -------------- | ---------- | ----------------------- |
| Cloudflare     | CDN + DDoS | Web applications        |
| AWS Shield     | Network    | AWS-hosted services     |
| Akamai         | CDN + DDoS | Enterprise applications |
| Fastly         | CDN + WAF  | Edge delivery           |
| Arbor Networks | On-premise | Data center protection  |

### 8.2 Analysis Tools

| Tool      | Purpose              |
| --------- | -------------------- |
| Wireshark | Packet analysis      |
| tcpdump   | Command-line capture |
| nfdump    | NetFlow analysis     |
| DDoS Mon  | Attack monitoring    |
| BGPStream | Routing monitoring   |

### 8.3 Intelligence Sources

| Source    | Information         |
| --------- | ------------------- |
| CERTs     | Attack advisories   |
| ISACs     | Industry sharing    |
| Twitter/X | Real-time reports   |
| Radware   | Threat intelligence |

---

## 9. References

- [CISA DDoS Quick Guide](https://www.cisa.gov/ddos)
- [Cloudflare DDoS Threat Report](https://radar.cloudflare.com/)
- [AWS DDoS Response Guide](https://docs.aws.amazon.com/whitepapers/latest/aws-best-practices-ddos-resiliency/welcome.html)
- [NIST SP 800-189: Resilient Interdomain Traffic Exchange](https://csrc.nist.gov/publications/detail/sp/800-189/final)
- [OpenClaw Incident Response Plan](../incident-response.md)

---

**Playbook Owner:** Security Team
**Review Date:** 2026-05-21
**Next Drill:** 2026-08-21
