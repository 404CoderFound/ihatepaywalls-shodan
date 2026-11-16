"""Indexed host precedence and passive-only fallbacks on public search."""
import sqlite3
import unittest

from app.passive import prefer_indexed_hosts


class SearchDedupTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.db.execute("CREATE TABLE hosts (ip TEXT PRIMARY KEY)")
        self.db.executemany(
            "INSERT INTO hosts (ip) VALUES (?)",
            [("185.220.213.43",), ("2001:db8::2",)],
        )

    def tearDown(self):
        self.db.close()

    def test_indexed_ip_suppressed_even_when_not_on_current_host_page(self):
        rows = [
            {"ip": "185.220.213.43", "record_type": "rdap", "source": "a"},
            {"ip": "185.220.213.44", "record_type": "internetdb-host", "source": "b"},
            {"ip": "185.220.213.43", "record_type": "internetdb-host", "source": "b"},
        ]
        self.assertEqual([r["ip"] for r in prefer_indexed_hosts(self.db, rows)],
                         ["185.220.213.44"])

    def test_multiple_passive_rows_for_one_ip_show_once_newest_first(self):
        rows = [
            {"ip": "203.0.113.20", "record_type": "internetdb-host", "source": "recent"},
            {"ip": "203.0.113.20", "record_type": "rdap", "source": "older"},
            {"ip": "203.0.113.21", "record_type": "rdap", "source": "other"},
        ]
        self.assertEqual([r["source"] for r in prefer_indexed_hosts(self.db, rows)],
                         ["recent", "other"])

    def test_asn_network_facts_remain_but_duplicates_collapse(self):
        rows = [
            {"ip": "", "subject": "AS30925", "record_type": "asn-overview", "network": "", "domain": ""},
            {"ip": "", "subject": "AS30925", "record_type": "asn-overview", "network": "", "domain": ""},
            {"ip": "", "subject": "AS30925", "record_type": "announced-prefix", "network": "192.0.2.0/24", "domain": ""},
            {"ip": "", "subject": "AS30925", "record_type": "announced-prefix", "network": "198.51.100.0/24", "domain": ""},
        ]
        result = prefer_indexed_hosts(self.db, rows)
        self.assertEqual(len(result), 3)

    def test_ipv6_indexed_host_preferred(self):
        rows = [{"ip": "2001:db8::2", "record_type": "rdap"},
                {"ip": "2001:db8::3", "record_type": "rdap"}]
        self.assertEqual([r["ip"] for r in prefer_indexed_hosts(self.db, rows)],
                         ["2001:db8::3"])


if __name__ == "__main__":
    unittest.main()
