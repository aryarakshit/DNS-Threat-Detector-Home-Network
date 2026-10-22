"""Unified DNS Log Parsers and 7-Day Home Network Traffic Simulator.

Supports:
- Pi-hole dnsmasq text logs (`pihole.log`)
- Pi-hole SQLite FTL database (`pihole-FTL.db`)
- Zeek network monitor DNS logs (`dns.log` TSV and JSON lines)
- Deterministic 7-day home network simulator generating 140,000 queries
"""

from __future__ import annotations
import datetime
import json
import random
import re
import sqlite3
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, Generator, Iterable, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from config import load_config
from core.dga_generators import generate_dga_domains


@dataclass
class DNSQueryEvent:
    """Normalized schema for all DNS log sources."""
    timestamp: str          # ISO-8601 or formatted UTC timestamp
    client_ip: str          # Source device IPv4 address
    device_name: str        # Device hostname or role
    query: str              # Requested domain name
    qtype: str              # DNS query type (A, AAAA, TXT, PTR, CNAME)
    rcode: str              # DNS response code (NOERROR, NXDOMAIN, SERVFAIL)
    answers: List[str]      # Resolved IPs or CNAMEs

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


class DNSLogParser:
    """Parser for Pi-hole and Zeek DNS log telemetry."""

    @staticmethod
    def parse_pihole_log(filepath: str | Path) -> List[DNSQueryEvent]:
        """Parse standard dnsmasq/pihole.log text lines."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Pi-hole log not found at: {path}")

        events: List[DNSQueryEvent] = []
        # Sample lines:
        # Oct 18 14:22:01 dnsmasq[1234]: query[A] example.com from 192.168.1.55
        # Oct 18 14:22:01 dnsmasq[1234]: reply example.com is 93.184.216.34
        # Oct 18 14:22:01 dnsmasq[1234]: reply example.com is NXDOMAIN
        query_pattern = re.compile(
            r"^([A-Za-z]{3}\s+\d+\s+[\d:]+)\s+dnsmasq\[\d+\]:\s+query\[([A-Z0-9]+)\]\s+(\S+)\s+from\s+(\S+)"
        )
        reply_pattern = re.compile(
            r"^([A-Za-z]{3}\s+\d+\s+[\d:]+)\s+dnsmasq\[\d+\]:\s+reply\s+(\S+)\s+is\s+(\S+)"
        )

        pending_queries: Dict[str, DNSQueryEvent] = {}

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                qm = query_pattern.search(line)
                if qm:
                    ts_str, qtype, domain, client_ip = qm.groups()
                    clean_domain = domain.rstrip(".")
                    event = DNSQueryEvent(
                        timestamp=ts_str,
                        client_ip=client_ip,
                        device_name="pihole-client",
                        query=clean_domain,
                        qtype=qtype,
                        rcode="NOERROR",  # default until reply
                        answers=[]
                    )
                    pending_queries[clean_domain] = event
                    events.append(event)
                    continue

                rm = reply_pattern.search(line)
                if rm:
                    _, domain, answer = rm.groups()
                    clean_domain = domain.rstrip(".")
                    if clean_domain in pending_queries:
                        ev = pending_queries[clean_domain]
                        if answer.upper() == "NXDOMAIN":
                            ev.rcode = "NXDOMAIN"
                        else:
                            ev.rcode = "NOERROR"
                            ev.answers.append(answer)

        return events

    @staticmethod
    def parse_pihole_sqlite(db_path: str | Path, limit: Optional[int] = None) -> List[DNSQueryEvent]:
        """Parse Pi-hole FTL SQLite database (pihole-FTL.db)."""
        path = Path(db_path)
        if not path.is_file():
            raise FileNotFoundError(f"Pi-hole SQLite DB not found at: {path}")

        conn = sqlite3.connect(path)
        cursor = conn.cursor()

        # Query the queries table
        query_sql = """
            SELECT timestamp, type, status, domain, client
            FROM queries
            ORDER BY timestamp ASC
        """
        if limit:
            query_sql += f" LIMIT {int(limit)}"

        cursor.execute(query_sql)
        rows = cursor.fetchall()
        conn.close()

        type_map = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA"}
        events: List[DNSQueryEvent] = []

        for ts, qtype_int, status, domain, client in rows:
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
            qtype = type_map.get(qtype_int, "A")
            # Status: 0=unknown, 1=blocked, 2=forwarded, 3=cached, etc.
            rcode = "NXDOMAIN" if status in (0, 4, 5) else "NOERROR"
            events.append(DNSQueryEvent(
                timestamp=dt,
                client_ip=client or "127.0.0.1",
                device_name="pihole-host",
                query=domain.rstrip("."),
                qtype=qtype,
                rcode=rcode,
                answers=[]
            ))

        return events

    @staticmethod
    def parse_zeek_dns_log(filepath: str | Path) -> List[DNSQueryEvent]:
        """Parse Zeek dns.log in either TSV or JSON format."""
        path = Path(filepath)
        if not path.is_file():
            raise FileNotFoundError(f"Zeek DNS log not found at: {path}")

        events: List[DNSQueryEvent] = []

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            first_char = f.read(1)
            f.seek(0)

            # Check if JSON lines
            if first_char == "{":
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    ts = str(obj.get("ts", ""))
                    client_ip = obj.get("id.orig_h") or obj.get("client_ip", "0.0.0.0")
                    query = obj.get("query", "").rstrip(".")
                    qtype = obj.get("qtype_name") or obj.get("qtype", "A")
                    rcode = obj.get("rcode_name") or obj.get("rcode", "NOERROR")
                    answers_raw = obj.get("answers", [])
                    answers = answers_raw if isinstance(answers_raw, list) else [str(answers_raw)]

                    events.append(DNSQueryEvent(
                        timestamp=ts,
                        client_ip=client_ip,
                        device_name="zeek-client",
                        query=query,
                        qtype=qtype,
                        rcode=rcode.upper(),
                        answers=answers
                    ))
                return events

            # Otherwise, Zeek TSV format
            fields = []
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if line.startswith("#fields"):
                    fields = line.split()[1:]
                    continue
                if line.startswith("#"):
                    continue

                parts = line.split("\t")
                if len(parts) != len(fields):
                    continue

                row = dict(zip(fields, parts))
                ts = row.get("ts", "")
                client_ip = row.get("id.orig_h", "0.0.0.0")
                query = row.get("query", "").rstrip(".")
                qtype = row.get("qtype_name", "A")
                rcode = row.get("rcode_name", "NOERROR")
                answers_val = row.get("answers", "-")
                answers = answers_val.split(",") if answers_val != "-" else []

                events.append(DNSQueryEvent(
                    timestamp=ts,
                    client_ip=client_ip,
                    device_name="zeek-client",
                    query=query,
                    qtype=qtype,
                    rcode=rcode.upper(),
                    answers=answers
                ))

        return events


def generate_home_network_logs(
    output_path: Optional[str | Path] = None,
    total_queries: int = 140000,
    days: int = 7,
    seed: int = 42
) -> Path:
    """Deterministic 7-day Home Network DNS Traffic Simulator.

    Simulates 140,000 queries across 5 devices defined in detector_config.yaml:
    - Normal everyday browsing (Google, Netflix, WhatsApp, SBI, GitHub)
    - Realistic high-entropy benign anomalies (CloudFront hashes, Spotify session hosts, DKIM)
    - Active DGA / C2 bursts from 192.168.1.55 (IoT camera) and 192.168.1.99 (Lab VM) with >85% NXDOMAIN
    """
    config = load_config()
    sim_cfg = config.get("home_network_simulation", {})
    devices = sim_cfg.get("devices", [
        {"ip": "192.168.1.10", "hostname": "aditya-workstation", "role": "Primary Laptop"},
        {"ip": "192.168.1.24", "hostname": "livingroom-bravia-tv", "role": "Smart TV (High CDN Noise)"},
        {"ip": "192.168.1.38", "hostname": "pixel-8-pro", "role": "Android Smartphone"},
        {"ip": "192.168.1.55", "hostname": "iot-cam-garage", "role": "Compromised IoT Camera (Simulated DGA C2)"},
        {"ip": "192.168.1.99", "hostname": "win11-lab-vm", "role": "Lab VM (Simulated Qakbot/Cryptolocker Beacon)"},
    ])

    out_file = Path(output_path) if output_path else PROJECT_ROOT / "data" / "home_dns_7days.jsonl"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    rng = random.Random(seed)
    base_time = datetime.datetime(2026, 10, 16, 0, 0, 0, tzinfo=datetime.timezone.utc)
    total_seconds = days * 86400

    # Common Benign Domains
    tech_domains = [
        "github.com", "api.github.com", "stackoverflow.com", "google.com", "www.google.com",
        "docs.python.org", "pypi.org", "slack.com", "zoom.us", "medium.com", "aws.amazon.com",
        "cloudflare.com", "linkedin.com", "chatgpt.com", "anthropic.com", "reddit.com"
    ]
    tv_domains = [
        "netflix.com", "api-global.netflix.com", "nflxvideo.net", "youtube.com",
        "googlevideo.com", "disneyplus.com", "hotstar.com", "sonyliv.com", "primevideo.com",
        "bravia.sony.tv", "connectivitycheck.gstatic.com"
    ]
    phone_domains = [
        "whatsapp.net", "chat.whatsapp.net", "instagram.com", "sbi.co.in", "onlinesbi.sbi",
        "hdfcbank.com", "netbanking.hdfcbank.com", "flipkart.com", "zomato.com", "swiggy.com",
        "play.googleapis.com", "apple.com", "icloud.com"
    ]
    iot_normal_domains = [
        "cam-cloud.ezviz.com", "time.nist.gov", "pool.ntp.org", "api.tplinkra.com", "p2p.dahuasecurity.com"
    ]
    lab_normal_domains = [
        "update.microsoft.com", "msftconnecttest.com", "windowsupdate.com", "office.com"
    ]

    # Benign High-Entropy Anomaly Domains (trip naive entropy models, but resolve with NOERROR!)
    cdn_high_entropy_domains = [
        "d3g9k8x2p1q4.cloudfront.net",
        "d1m7b9v4k2q8.cloudfront.net",
        "a8f9d2c1b4e5.spotify.com",
        "s202610._domainkey.razorpay.com",
        "k1._domainkey.github.com",
        "telemetry-x9k12m7p.apple.com",
        "prod-e8d9c2b1.akamaized.net",
        "session-b7c4d1e2.fastly.net",
        "edge-v9x2m4p7.cloudflare-dns.com",
        "telemetry-hash-9f8e7d6c.microsoft.com"
    ]

    # Pre-generate authentic DGA domains for infected hosts
    iot_necurs = generate_dga_domains("necurs", count=250, seed=101)
    iot_conficker = generate_dga_domains("conficker", count=250, seed=102)
    vm_crypto = generate_dga_domains("cryptolocker", count=250, seed=201)
    vm_qakbot = generate_dga_domains("qakbot", count=250, seed=202)
    vm_suppobox = generate_dga_domains("suppobox_matsnu", count=250, seed=203)
    vm_tunneling = [f"c2-data-{hex(rng.getrandbits(48))[2:]}.tunnel-exfil.org" for _ in range(100)]

    events: List[DNSQueryEvent] = []

    # Distribution of queries across devices:
    # 1. aditya-workstation: 40,000 queries
    # 2. livingroom-bravia-tv: 35,000 queries
    # 3. pixel-8-pro: 30,000 queries
    # 4. iot-cam-garage (compromised): 17,500 queries
    # 5. win11-lab-vm (compromised): 17,500 queries
    dev_target_counts = {
        "192.168.1.10": 40000,
        "192.168.1.24": 35000,
        "192.168.1.38": 30000,
        "192.168.1.55": 17500,
        "192.168.1.99": 17500,
    }

    # Generate queries device by device with realistic timestamps
    for dev in devices:
        ip = dev["ip"]
        hostname = dev["hostname"]
        count = dev_target_counts.get(ip, 28000)

        # Generate timestamps across 7 days with diurnal rhythm
        t_offsets = sorted([rng.uniform(0, total_seconds) for _ in range(count)])

        for idx, offset in enumerate(t_offsets):
            event_time = base_time + datetime.timedelta(seconds=offset)
            ts_str = event_time.strftime("%Y-%m-%d %H:%M:%S")

            qtype = "A"
            answers = ["104.26.10.55"]
            rcode = "NOERROR"

            if ip == "192.168.1.10":
                # Primary Laptop
                if rng.random() < 0.05:
                    qname = rng.choice(cdn_high_entropy_domains)
                    answers = ["13.224.14.88"]
                else:
                    qname = rng.choice(tech_domains)
                    answers = ["140.82.121.4"]
                rcode = "NOERROR" if rng.random() > 0.02 else "NXDOMAIN"

            elif ip == "192.168.1.24":
                # Smart TV - heavy CDN noise
                if rng.random() < 0.25:
                    qname = rng.choice(cdn_high_entropy_domains)
                    answers = ["18.65.178.44"]
                else:
                    qname = rng.choice(tv_domains)
                    answers = ["198.38.118.140"]
                rcode = "NOERROR" if rng.random() > 0.005 else "NXDOMAIN"

            elif ip == "192.168.1.38":
                # Smartphone
                if rng.random() < 0.08:
                    qname = rng.choice(cdn_high_entropy_domains)
                    answers = ["52.84.162.12"]
                else:
                    qname = rng.choice(phone_domains)
                    answers = ["157.240.22.53"]
                rcode = "NOERROR" if rng.random() > 0.03 else "NXDOMAIN"

            elif ip == "192.168.1.55":
                # Compromised IoT Camera: bursts of Necurs & Conficker
                # 6% of its traffic is malicious DGA beacons
                is_dga = (rng.random() < 0.06)
                if is_dga:
                    qname = rng.choice(iot_necurs if rng.random() > 0.5 else iot_conficker)
                    # Malware C2 generation: 90% NXDOMAIN
                    if rng.random() < 0.90:
                        rcode = "NXDOMAIN"
                        answers = []
                    else:
                        rcode = "NOERROR"
                        answers = ["194.58.112.17"]
                else:
                    qname = rng.choice(iot_normal_domains)
                    rcode = "NOERROR"
                    answers = ["139.162.45.10"]

            elif ip == "192.168.1.99":
                # Lab VM: Cryptolocker, Qakbot, Suppobox, and DNS tunneling
                # 7% of traffic is malicious
                roll = rng.random()
                if roll < 0.025:
                    qname = rng.choice(vm_crypto)
                    rcode = "NXDOMAIN" if rng.random() < 0.88 else "NOERROR"
                    answers = [] if rcode == "NXDOMAIN" else ["185.120.77.10"]
                elif roll < 0.050:
                    qname = rng.choice(vm_qakbot)
                    rcode = "NXDOMAIN" if rng.random() < 0.88 else "NOERROR"
                    answers = [] if rcode == "NXDOMAIN" else ["195.201.88.22"]
                elif roll < 0.065:
                    qname = rng.choice(vm_suppobox)
                    rcode = "NXDOMAIN" if rng.random() < 0.85 else "NOERROR"
                    answers = [] if rcode == "NXDOMAIN" else ["45.154.255.80"]
                elif roll < 0.070:
                    # DNS Tunneling exfiltration
                    qname = rng.choice(vm_tunneling)
                    qtype = "TXT"
                    rcode = "NOERROR"
                    answers = ["\"c2-ack-chunk\""]
                else:
                    qname = rng.choice(lab_normal_domains)
                    rcode = "NOERROR" if rng.random() > 0.02 else "NXDOMAIN"
                    answers = ["20.190.159.23"]

            events.append(DNSQueryEvent(
                timestamp=ts_str,
                client_ip=ip,
                device_name=hostname,
                query=qname,
                qtype=qtype,
                rcode=rcode,
                answers=answers
            ))

    # Sort all events chronologically across devices
    events.sort(key=lambda x: x.timestamp)

    print(f"Writing {len(events)} events to {out_file}...")
    with open(out_file, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(ev.to_json() + "\n")

    print(f"Successfully generated 7-day home DNS log ({len(events)} queries) -> {out_file}")
    return out_file


if __name__ == "__main__":
    generate_home_network_logs(total_queries=140000, days=7)
