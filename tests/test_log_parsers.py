"""Unit tests for Pi-hole and Zeek DNS log parsers and 7-day simulator."""

import json
import tempfile
from pathlib import Path
import pytest
from core.log_parsers import DNSLogParser, DNSQueryEvent

PROJECT_ROOT = Path(__file__).resolve().parent.parent


class TestLogParsers:
    """Verifies Pi-hole and Zeek format parsing and event schema conformity."""

    def test_pihole_log_parser(self):
        sample_log = (
            "Oct 18 14:22:01 dnsmasq[1234]: query[A] benign-site.com from 192.168.1.10\n"
            "Oct 18 14:22:01 dnsmasq[1234]: reply benign-site.com is 93.184.216.34\n"
            "Oct 18 14:22:05 dnsmasq[1234]: query[A] xk9m2v7p.biz from 192.168.1.55\n"
            "Oct 18 14:22:05 dnsmasq[1234]: reply xk9m2v7p.biz is NXDOMAIN\n"
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write(sample_log)
            tmp_path = f.name

        try:
            events = DNSLogParser.parse_pihole_log(tmp_path)
            assert len(events) == 2

            ev0 = events[0]
            assert ev0.query == "benign-site.com"
            assert ev0.client_ip == "192.168.1.10"
            assert ev0.rcode == "NOERROR"
            assert "93.184.216.34" in ev0.answers

            ev1 = events[1]
            assert ev1.query == "xk9m2v7p.biz"
            assert ev1.client_ip == "192.168.1.55"
            assert ev1.rcode == "NXDOMAIN"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_zeek_tsv_parser(self):
        sample_tsv = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tquery\tqtype_name\trcode_name\tanswers\n"
            "1697638921.12\t192.168.1.99\tqakbot-beacon.net\tA\tNXDOMAIN\t-\n"
            "1697638925.45\t192.168.1.24\td3g9k8x2p1q4.cloudfront.net\tA\tNOERROR\t54.230.1.1\n"
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write(sample_tsv)
            tmp_path = f.name

        try:
            events = DNSLogParser.parse_zeek_dns_log(tmp_path)
            assert len(events) == 2

            ev0 = events[0]
            assert ev0.client_ip == "192.168.1.99"
            assert ev0.query == "qakbot-beacon.net"
            assert ev0.rcode == "NXDOMAIN"

            ev1 = events[1]
            assert ev1.client_ip == "192.168.1.24"
            assert ev1.query == "d3g9k8x2p1q4.cloudfront.net"
            assert ev1.rcode == "NOERROR"
            assert "54.230.1.1" in ev1.answers
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_zeek_json_parser(self):
        sample_json = (
            '{"ts": "2026-10-18T14:22:01Z", "id.orig_h": "192.168.1.38", "query": "whatsapp.net", "qtype_name": "A", "rcode_name": "NOERROR", "answers": ["157.240.22.53"]}\n'
            '{"ts": "2026-10-18T14:22:05Z", "id.orig_h": "192.168.1.99", "query": "crypto123.biz", "qtype_name": "A", "rcode_name": "NXDOMAIN", "answers": []}\n'
        )
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write(sample_json)
            tmp_path = f.name

        try:
            events = DNSLogParser.parse_zeek_dns_log(tmp_path)
            assert len(events) == 2
            assert events[0].client_ip == "192.168.1.38"
            assert events[0].rcode == "NOERROR"
            assert events[1].client_ip == "192.168.1.99"
            assert events[1].rcode == "NXDOMAIN"
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    def test_7day_log_file_integrity(self):
        log_file = PROJECT_ROOT / "data" / "home_dns_7days.jsonl"
        assert log_file.is_file(), "Simulated 7-day log missing. Run log_parsers.py first."

        line_count = 0
        devices_seen = set()
        with open(log_file, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                line_count += 1
                if idx < 50:
                    obj = json.loads(line)
                    devices_seen.add(obj["client_ip"])
                    assert "query" in obj
                    assert "rcode" in obj
                    assert "timestamp" in obj

        assert line_count == 140000, f"Expected 140,000 queries, found {line_count}"
