# Summary: 05-01 Pi-hole & Zeek Log Parsers & 7-Day Simulator

## Deliverables
- `core/log_parsers.py`:
  - `DNSQueryEvent` dataclass standardizing query telemetry across log sources.
  - `DNSLogParser.parse_pihole_log()`: Parses standard `dnsmasq`/`pihole.log` lines, correlating queries with `NXDOMAIN` / IP replies.
  - `DNSLogParser.parse_pihole_sqlite()`: Ingests `pihole-FTL.db` SQLite database query records.
  - `DNSLogParser.parse_zeek_dns_log()`: Dual-mode Zeek parser supporting both `#fields` TSV files and JSON lines.
  - `generate_home_network_logs()`: Deterministic 7-day home network simulator generating 140,000 DNS queries across 5 devices.
- Generated telemetry:
  - `data/home_dns_7days.jsonl` (140,000 JSON lines):
    - `192.168.1.10` (Primary Laptop): 40,000 queries
    - `192.168.1.24` (Smart TV): 35,000 queries (high CDN noise, CloudFront/Spotify NOERROR)
    - `192.168.1.38` (Android Phone): 30,000 queries
    - `192.168.1.55` (Compromised IoT Camera): 17,500 queries with active Necurs/Conficker DGA beacons (90% NXDOMAIN)
    - `192.168.1.99` (Compromised Lab VM): 17,500 queries with Cryptolocker, Qakbot, Suppobox, and DNS tunneling beacons (88% NXDOMAIN)

## Verification Evidence
- Verified exact 140,000 query count in `data/home_dns_7days.jsonl`.
- Verified device query quotas and response code distribution (135,862 NOERROR, 4,138 NXDOMAIN).
- Verified unit parsing for both Pi-hole dnsmasq and Zeek TSV formats.
