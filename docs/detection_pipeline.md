DATA SOURCES
├── Firewall Logs (egress traffic)
├── Endpoint Events (Windows Event 5156)
├── Proxy Logs (HTTP/S traffic)
├── Threat Intel Feed (Tor exit node list)
└── DNS Logs (query telemetry)

        ▼

Microsoft Sentinel (SIEM)
Log Analytics Workspace

        ▼

KQL Rules Execute
├── Rule 1: Outbound Tor > 1MB
├── Rule 2: Subnet /24 Sweep
└── Rule 3: Event 5156 Endpoint

        ▼

SOC Alert Triggered
Incident #653999 | Severity: HIGH

        ▼

Analyst Response
Triage → OSINT → Contain → Eradicate & Recover