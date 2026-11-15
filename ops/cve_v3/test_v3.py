import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import unittest
from datetime import datetime, timezone, timedelta

import fingerprint
import merge_report
import vendor_oval
import verify_ingestion
import publish

APACHE={"cve":"CVE-2024-38472","ip":"185.220.213.51",
        "status":"potential","evidence":"remote"}

def meta(*ids):
    return {cve:{"cve":cve,"description":"test","severity":"HIGH",
                 "cvss":7.5,"known_exploited":False} for cve in ids}

def vendor(ip="185.220.213.51",statuses=None):
    return {"schema_version":1,"ip":ip,"os_family":"ubuntu",
            "source":"canonical_ubuntu_usn_oval_local_openscap",
            "generated_at":datetime.now(timezone.utc).isoformat(),
            "cve_status":statuses or {}}

class CVEV3Tests(unittest.TestCase):
    def test_oval_xml_true_false(self):
        with tempfile.TemporaryDirectory() as folder:
            defs=Path(folder)/"defs.xml"
            results=Path(folder)/"results.xml"
            defs.write_text("""<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>
              <definition id="oval:ubuntu:def:1"><metadata>
                <reference source="CVE" ref_id="CVE-2024-38472"/>
              </metadata></definition>
              <definition id="oval:ubuntu:def:2"><metadata>
                <reference source="CVE" ref_id="CVE-2024-12345"/>
              </metadata></definition>
            </definitions></oval_definitions>""")
            results.write_text("""<oval_results xmlns="http://oval.mitre.org/XMLSchema/oval-results-5">
              <results><system><definitions>
                <definition definition_id="oval:ubuntu:def:1" result="false"/>
                <definition definition_id="oval:ubuntu:def:2" result="true"/>
              </definitions></system></results></oval_results>""")
            merged=vendor_oval.aggregate(
                vendor_oval.refs_by_definition(defs),
                vendor_oval.oval_results(results))
            self.assertEqual(merged["CVE-2024-38472"],"vendor_not_affected")
            self.assertEqual(merged["CVE-2024-12345"],"vendor_affected")

    def test_remote_nvd_matches_remain_research_only(self):
        result=merge_report.combine(
            {"generated_at":"2026-11-15T20:00:00+00:00",
             "fingerprinted_services":1,"findings":[APACHE]},
            {},meta("CVE-2024-38472"))
        self.assertEqual(result["counts"]["research_candidate"],1)
        self.assertNotIn("potential",result["counts"])
        self.assertEqual(result["findings"][0]["status"],"research_candidate")
        self.assertIn("NOT evidence",result["findings"][0]["note"])
        self.assertNotIn("vendor_affected",result["counts"])

    def test_ubuntu_false_suppresses_unverified_remote(self):
        host=vendor(statuses={"CVE-2024-38472":"vendor_not_affected"})
        report={"generated_at":"2026-11-15T20:00:00+00:00",
                "fingerprinted_services":3,"findings":[APACHE]}
        merged=merge_report.combine(report,{host["ip"]:host},
                                    meta("CVE-2024-38472"))
        self.assertEqual(merged["findings"],[])
        self.assertEqual(merged["vendor_suppressed_remote_signals"],1)

    def test_vendor_true_adds_affected_without_remote_fingerprint(self):
        host=vendor(statuses={"CVE-2024-12345":"vendor_affected"})
        report={"generated_at":"2026-11-15T20:00:00+00:00",
                "fingerprinted_services":0,"findings":[]}
        merged=merge_report.combine(report,{host["ip"]:host},
                                    meta("CVE-2024-12345"))
        self.assertEqual(merged["findings"][0]["status"],"vendor_affected")

    def test_expired_vendor_evidence_not_accepted(self):
        item=vendor()
        item["generated_at"]=(datetime.now(timezone.utc)-timedelta(days=5)).isoformat()
        self.assertFalse(merge_report.valid_oval_file(item))

    def test_ssh_identification(self):
        row={"banner":"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20","cpe":""}
        self.assertEqual(fingerprint.fingerprint(row),
                         "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")

    def test_apache_http_server_header(self):
        row={"banner":"", "http_json":json.dumps({"headers":{"Server":"Apache/2.4.58 (Ubuntu)"}}),
             "cpe":""}
        self.assertEqual(fingerprint.fingerprint(row),
                         "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*")

    def test_unknown_banner_not_guessed(self):
        self.assertIsNone(fingerprint.fingerprint({
            "banner":"HTTP/1.1 200 OK","product":"Apache","port":80,"cpe":""
        }))
    def test_conflicting_versions_not_guessed(self):
        self.assertIsNone(fingerprint.fingerprint({
            "banner":"Apache/2.4.58\nnginx/1.24.0","cpe":""
        }))
    def test_v3_frontend_escaper_and_syntax(self):
        js = Path(__file__).with_name("cve-v3.js")
        source = js.read_text()
        self.assertIn("c => ({", source)
        self.assertNotIn(':"&quot;":"&#39;"', source)
        if shutil.which("node"):
            subprocess.run(["node", "--check", str(js)], check=True)

    def test_read_only_overlay_contains_complete_static_mount(self):
        yaml = publish.overlay_yaml("/srv/app/static")
        self.assertIn("read_only: true", yaml)
        self.assertIn("source: /var/lib/scanlattice-cve/site-v3-static", yaml)
        self.assertIn("target: /srv/app/static", yaml)

    def test_patched_index_is_idempotent(self):
        html = """<!doctype html><html><body>
          <section id="host-content"></section>
          <section id="insight-content"></section>
          <script src="/static/app.js" defer></script>
          <script src="/static/insights.js" defer></script>
          </body></html>"""
        first = publish.patched_index(html)
        self.assertEqual(first.count(publish.SCRIPT_TAG), 1)
        self.assertEqual(first, publish.patched_index(first))
        self.assertIn('<script src="/static/cve-v3.js" defer></script>', first)

    def test_publisher_checks_actual_dom_not_nav_text(self):
        html = """<!doctype html><html><body>
          <section id="host-content"></section>
          <section id='insight-content'></section>
          <script src="/static/app.js"></script>
          <script src="/static/insights.js"></script></body></html>"""
        result = publish.validate_ui(html)
        self.assertIs(result, True)
        self.assertTrue(all(publish.ui_features(html).values()))
        self.assertNotIn('data-page="vulnerabilities"', html)

    def test_publisher_fails_closed_on_unsupported_dom(self):
        with self.assertRaisesRegex(RuntimeError, "insight-content"):
            publish.validate_ui(
                '<html><body><div id="host-content"></div>'
                '<script src="/static/app.js"></script>'
                '<script src="/static/insights.js"></script></body></html>'
            )

    def test_recent_completed_job_is_visible_on_website(self):
        recent=(datetime.now(timezone.utc)-timedelta(hours=1)).isoformat()
        job={"status":"completed","created_at":recent,
             "request":{"target_type":"ip","target":"185.220.213.51"}}
        count,fail=verify_ingestion.audit(
            [job],lambda ip:{"host":{"last_scan_at":datetime.now(timezone.utc).isoformat()}})
        self.assertEqual(count,1)
        self.assertEqual(fail,[])
        count,fail=verify_ingestion.audit([job],lambda ip:{"host":{"last_scan_at":""}})
        self.assertEqual(len(fail),1)

    def test_existing_cpe_not_overwritten(self):
        self.assertIsNone(fingerprint.fingerprint({
            "banner":"nginx/1.25.0","cpe":"cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
        }))

if __name__=="__main__":
    unittest.main()
