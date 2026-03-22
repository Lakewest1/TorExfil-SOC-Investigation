# MITRE ATT&CK Mapping — Tor Exit Node Investigation

| ID | Technique | Tactic | Evidence |
|----|-----------|--------|----------|
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration | Tor used as non-standard exfiltration channel — Shodan/Censys confirmed |
| T1048.003 | Obfuscated Non-C2 Protocol | Exfiltration | HTTPS over Tor — payload encrypted, content hidden |
| T1090 | Proxy | Command & Control | IPinfo Privacy: TRUE — confirmed anonymization service |
| T1090.003 | Multi-hop Proxy | Command & Control | Tor multi-node routing — Censys PROXY_SERVER label |
| T1572 | Protocol Tunneling | Command & Control | Traffic via encrypted Tor circuits — port 80 banner confirmed |
| T1041 | Exfiltration Over C2 Channel | Exfiltration | Outbound > inbound ratio — exfiltration pattern |
| T1030 | Data Transfer Size Limits | Exfiltration | 1MB threshold breach triggers High/Critical severity |

## Detection Coverage

| Technique | Detection Rule |
|-----------|----------------|
| T1048, T1048.003 | SOC-TOR-EXFIL-001 — volume threshold |
| T1090, T1090.003 | SOC-TOR-EXFIL-002 — subnet sweep |
| T1572, T1041, T1030 | SOC-TOR-EXFIL-003 — endpoint events |