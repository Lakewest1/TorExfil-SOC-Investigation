# TorExfil-SOC-Investigation
SOC investigation of Tor exit node 185.220.101.34 | NIST SP 800-61 full lifecycle | Microsoft Sentinel KQL detection rules | OSINT: VirusTotal, Shodan, IPinfo, ViewDNS, SecurityTrails, Censys | MITRE ATT&amp;CK mapping (T1048, T1090, T1572) | Detection pipeline architecture | 1h45m response time
# Tor Exit Node Exfiltration Investigation

## SOC Detection Engineering Portfolio Project

**Target IP:** 185.220.101.34 — Known Malicious Tor Exit Node  
**Author:** Musa Olalekan | Cloud Security Analyst & Detection Engineer  
**Framework:** NIST SP 800-61 — All 7 Phases  
**SIEM:** Microsoft Sentinel (Azure Lab Environment)  
**OSINT Tools:** VirusTotal · Shodan · IPinfo · ViewDNS · SecurityTrails · Censys  

---

## Overview

This project demonstrates a complete SOC investigation workflow from initial alert through detection rule deployment. The investigation follows NIST SP 800-61 incident response methodology across all seven phases, with every action documented and timestamped.

### What's Real vs Simulated

| Component | Status | Detail |
|-----------|--------|--------|
| Target IP | **REAL** | 185.220.101.34 — documented malicious Tor exit node |
| All 8 OSINT Screenshots | **REAL** | Captured live during investigation |
| Attack Timeline | **REAL** | Actual investigation sequence with timestamps |
| KQL Detection Queries | **REAL** | Production-ready, tested in Sentinel lab |
| MITRE ATT&CK Mapping | **REAL** | Mapped to observed behaviors |
| WKSTN-047 Scenario | **Simulated** | Internal host scenario for IR demonstration |

---

## Investigation Summary

**Response Time:** 1 hour 45 minutes (02:00 AM alert → 03:45 AM rule deployed)

**NIST SP 800-61 Lifecycle:**
- ✅ Preparation — OSINT toolkit assembled
- ✅ Identification — 6-tool threat profile built
- ✅ Analysis — Deep service fingerprinting, evasion confirmed
- ✅ Containment — /24 subnet block, host isolation
- ✅ Eradication — Memory image, credential reset, persistence sweep
- ✅ Recovery — Clean reimage, traffic audit
- ✅ Lessons Learned — 4 gaps → 4 fixes → KQL rule deployed

---

## Key Findings

| Attribute | Finding |
|-----------|--------|
| IP Address | 185.220.101.34 |
| Subnet | 185.220.101.0/24 — entire range is Tor exit infrastructure |
| Hostname | tor-exit-34.for-privacy.net |
| ASN | AS60729 — Stiftung Erneuerbare Freiheit |
| Location | Berlin, Germany |
| Reputation | 16/94 vendors flagged · Community score -25 · 41 reports |
| Open Ports | 80/Tor-httpd · 10034/UNKNOWN · 10134/UNKNOWN |
| Infrastructure Age | Active since 2025-07-09 — 8+ months |
| Verdict | **CONFIRMED MALICIOUS** — Multi-tool consensus |

---

## Detection Rules (KQL)

### SOC-TOR-EXFIL-001 — Outbound Tor with Volume Threshold

```kql
let TorExitNodes = externaldata(IPAddress:string)
    [@"https://check.torproject.org/torbulkexitlist"]
    with(format='txt', ignoreFirstRecord=true);
let DataThresholdBytes = 1048576;

CommonSecurityLog
| where TimeGenerated > ago(24h)
| where DestinationIP in (TorExitNodes)
| extend Hour = datetime_part('hour', TimeGenerated)
| extend BusinessHoursFlag = iif(Hour between (8 .. 18),
    'BUSINESS HOURS', 'AFTER HOURS')
| extend DataTransferBytes = SentBytes + ReceivedBytes
| extend DataTransferMB = round(todouble(DataTransferBytes) / 1048576, 2)
| extend Severity = case(
    DataTransferBytes > DataThresholdBytes * 10
        and BusinessHoursFlag == 'AFTER HOURS', 'CRITICAL',
    DataTransferBytes > DataThresholdBytes
        and BusinessHoursFlag == 'AFTER HOURS', 'HIGH',
    DataTransferBytes > DataThresholdBytes, 'MEDIUM',
    'LOW')
| where DataTransferMB > 1
| project TimeGenerated, SourceHost=DeviceName, SourceIP,
    DestinationIP, DestinationPort, DataTransferMB,
    BusinessHoursFlag, Severity
| order by DataTransferMB desc, TimeGenerated desc
