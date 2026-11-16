"""Offline regression checks. Never contact a public target or remote feed."""
import gzip
import json
from pathlib import Path
import tempfile
import unittest

import ingest


class FakeClient:
    def __init__(self, fail_once=False):
        self.calls = []
        self.fail_once = fail_once

    def upload(self, ident, source, data):
        if self.fail_once:
            self.fail_once = False
            raise RuntimeError("temporary API failure")
        self.calls.append((ident, source, [json.loads(x) for x in data.splitlines()]))


class FeedTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state = Path(self.tmp.name)
        self.db = ingest.database(self.state)
        self.feed = self.state / "inbox" / "data.jsonl"
        self.source = {
            "id": "example", "path": str(self.feed), "format": "jsonl",
            "compression": "identity", "rights_confirmed": True,
        }
        self.config = {
            "_state": self.state, "batch_records": 2,
            "batch_bytes": 16384, "max_source_bytes": 100000,
            "max_batches_per_run": 10,
        }

    def tearDown(self):
        self.db.close()
        self.tmp.cleanup()

    def write(self, rows):
        self.feed.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_per_batch_upload_and_idempotent_unchanged(self):
        self.write([
            {"ip": "192.0.2.1", "port": 443, "banner": "example-A"},
            {"ip": "192.0.2.2", "port": 22, "banner": "example-B"},
            {"ip": "192.0.2.3", "ports": [80, 443]},
        ])
        client = FakeClient()
        r = ingest.process_source(self.config, self.db, self.source, client)
        self.assertEqual(r["status"], "completed")
        self.assertEqual(len(client.calls), 2)
        self.assertEqual(client.calls[0][2][0]["banner"], "example-A")
        self.assertEqual(ingest.process_source(self.config, self.db, self.source, client)["status"], "unchanged")
        self.assertEqual(len(client.calls), 2)

    def test_restart_resumes_after_acknowledged_batch(self):
        self.write([
            {"ip": "192.0.2.1"}, {"ip": "192.0.2.2"},
            {"ip": "192.0.2.3"}, {"ip": "192.0.2.4"},
            {"ip": "192.0.2.5"}
        ])
        client = FakeClient()
        self.config["max_batches_per_run"] = 1
        self.assertEqual(ingest.process_source(self.config, self.db, self.source, client)["status"], "partial")
        self.assertEqual(ingest.get_progress(self.db, "example")["cursor"], 1)
        self.config["max_batches_per_run"] = 10
        self.assertEqual(ingest.process_source(self.config, self.db, self.source, client)["status"], "completed")
        self.assertEqual([call[0].split("-")[-1] for call in client.calls],
                         ["00000000", "00000001", "00000002"])
        self.assertEqual(len({call[0] for call in client.calls}), 3)

    def test_api_failure_does_not_advance_cursor(self):
        self.write([{"ip": "192.0.2.1", "port": 443}])
        bad = FakeClient(fail_once=True)
        with self.assertRaisesRegex(RuntimeError, "temporary API failure"):
            ingest.process_source(self.config, self.db, self.source, bad)
        self.assertEqual(ingest.get_progress(self.db, "example")["cursor"], 0)
        good = FakeClient()
        self.assertEqual(ingest.process_source(self.config, self.db, self.source, good)["status"], "completed")
        self.assertEqual(len(good.calls), 1)

    def test_only_changes_imported_on_new_snapshot(self):
        self.write([{"ip": "192.0.2.1", "port": 443}])
        c = FakeClient()
        ingest.process_source(self.config, self.db, self.source, c)
        self.write([{"ip": "192.0.2.1", "port": 443}, {"ip": "192.0.2.2", "port": 80}])
        ingest.process_source(self.config, self.db, self.source, c)
        self.assertEqual(len(c.calls), 2)
        self.assertNotEqual(c.calls[0][0], c.calls[1][0])

    def test_nested_nul_sanitization(self):
        self.write([{"ip": "192.0.2.3", "port": 443, "banner": "abc\u0000",
                     "tls": {"cert": {"subject": "hello\u0000world"}}}])
        c = FakeClient()
        ingest.process_source(self.config, self.db, self.source, c)
        item = c.calls[0][2][0]
        self.assertEqual(item["banner"], "abc\ufffd")
        self.assertEqual(item["tls"]["cert"]["subject"], "hello\ufffdworld")

    def test_gzip_supported(self):
        source = dict(self.source, compression="gzip")
        source["path"] = str(self.feed) + ".gz"
        with gzip.open(source["path"], "wt") as out:
            out.write(json.dumps({"ip": "192.0.2.1", "port": 22}) + "\n")
        c = FakeClient()
        self.assertEqual(ingest.process_source(self.config, self.db, source, c)["status"], "completed")
        self.assertEqual(c.calls[0][2][0]["port"], 22)

    def test_does_not_invent_ports_or_banners(self):
        self.write([{"ip": "192.0.2.1", "org": "documented only"}])
        c = FakeClient()
        ingest.process_source(self.config, self.db, self.source, c)
        item = c.calls[0][2][0]
        self.assertNotIn("port", item)
        self.assertNotIn("banner", item)

    def test_reject_bad_feed_record(self):
        self.write([{"ip": "not-an-ip", "port": 443}])
        with self.assertRaises(ValueError):
            list(ingest.batches(self.feed, self.source, 250, 16384))


if __name__ == "__main__":
    unittest.main()
