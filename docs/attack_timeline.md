
---

## 4. ATTACK TIMELINE (optional but recommended)

Create `docs/attack_timeline.md`:

```markdown
# Attack Timeline — Investigation Sequence

| Time | NIST Phase | Action Taken |
|------|------------|--------------|
| 01:38 | Preparation | Co-occurring brute force alert fires (Incident #653762) |
| 01:55 | Preparation | OSINT toolkit assembled (6 tools loaded) |
| 02:00 | Identification | Primary SIEM alert triggered (Incident #653999) |
| 02:03 | Identification | VirusTotal — 16/94 vendors flagged |
| 02:06 | Identification | Shodan — ports 80, 10034, 10134 identified |
| 02:09 | Identification | IPinfo — ASN60729, Tor exit organization |
| 02:11 | Identification | ViewDNS — PTR: tor-exit-34.for-privacy.net |
| 02:13 | Identification | SecurityTrails — sdfguh.casacam.net |
| 02:16 | Identification | SecurityTrails — first seen: 2025-07-09 |
| 02:20 | Analysis | Censys — PROXY_SERVER label, unidentifiable ports |
| 02:24 | Analysis | SIEM correlation — WKSTN-047, 33 min window, 2.3MB outbound |
| 02:28 | Analysis | MITRE ATT&CK mapping — 7 techniques |
| 02:32 | Containment | Firewall block — 185.220.101.0/24 |
| 02:34 | Containment | Host isolated from network |
| 02:36 | Containment | Tier 2 escalation with threat intelligence package |
| 02:40 | Eradication | Full memory image acquired |
| 02:44 | Eradication | Subnet sweep in SIEM — blast radius confirmed |
| 02:48 | Eradication | Credential reset for all active accounts |
| 03:00 | Recovery | Persistence check complete — no findings |
| 03:15 | Recovery | Host reimaged from clean baseline |
| 03:30 | Lessons Learned | KQL rule SOC-TOR-EXFIL-001 written |
| 03:40 | Lessons Learned | /24 subnet added to permanent blocklist |
| 03:45 | Lessons Learned | Detection rule deployed to Sentinel |
| 03:50 | Lessons Learned | Investigation closed — full lifecycle complete |

**Total Response Time:** 1 hour 45 minutes (02:00 → 03:45)