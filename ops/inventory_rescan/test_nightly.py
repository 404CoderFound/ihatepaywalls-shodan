import ipaddress
from datetime import datetime, timedelta, timezone
import unittest
import nightly

NOW = datetime(2026,11,15,2,30,tzinfo=timezone.utc)

def config():
    return {
        "_website":"https://scanlattice.plezi.eu",
        "_allowed":[ipaddress.ip_network("185.220.213.0/24")],
        "_excluded":[],
        "ports":"extended",
        "max_inventory_hosts":1000,
        "max_jobs_per_tick":2,
        "max_pending_jobs":2,
        "max_jobs_per_night":20,
        "max_checks_per_night":1000,
        "cooldown_hours":24,
        "night_start_utc":0,"night_end_utc":5
    }

def fetch_factory(*ips, total_override=None):
    def fetch(url):
        import urllib.parse
        values=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
        page=int(values["page"][0])
        return {"total":len(ips) if total_override is None else total_override,
                "page":page,"has_next":False,
                "hosts":[{"ip":v} for v in ips]}
    return fetch

class NightlyTests(unittest.TestCase):
    def test_preview_is_read_only(self):
        calls=[]
        def go(args,binary):
            calls.append(args)
            if args==["jobs"]: return {"jobs":[]}
            raise AssertionError("preview called scan!")
        cfg=config()
        submitted=nightly.run(cfg,False,fetch_factory("185.220.213.51"),go,NOW)
        self.assertEqual(submitted,0)
        self.assertEqual(calls,[["jobs"]])

    def test_all_indexed_authorized_hosts_queued(self):
        cfg=config()
        go_calls=[]
        def go(args,binary):
            go_calls.append(args)
            if args==["jobs"]: return {"jobs":[]}
            if args[0]=="plan": return {"host_count":1,"check_count":91}
            if args[0]=="scan": return {"status":"queued","id":"test"}
            raise AssertionError(args)
        n=nightly.run(
            cfg,True,fetch_factory("185.220.213.51","185.220.213.52",
                                   "203.0.113.1"),go,NOW)
        self.assertEqual(n,2)
        self.assertEqual(sum(x[0]=="scan" for x in go_calls),2)

    def test_inventory_is_not_authorization(self):
        cfg=config()
        self.assertFalse(nightly.permitted("1.1.1.1",cfg))
        self.assertFalse(nightly.permitted("192.168.0.9",cfg))
        self.assertTrue(nightly.permitted("185.220.213.51",cfg))
        cfg["_excluded"].append(ipaddress.ip_network("185.220.213.0/24"))
        self.assertFalse(nightly.permitted("185.220.213.51",cfg))

    def test_skip_existing_running_job(self):
        cfg=config()
        job={"status":"running","created_at":NOW.isoformat(),
             "request":{"target_type":"ip","target":"185.220.213.51",
                        "ports":"extended"},"plan":{"check_count":91}}
        def go(args,binary):
            if args==["jobs"]: return {"jobs":[job]}
            raise AssertionError("job must be skipped")
        n=nightly.run(cfg,True,fetch_factory("185.220.213.51"),go,NOW)
        self.assertEqual(n,0)

    def test_cooldown(self):
        cfg=config()
        recent=NOW-timedelta(hours=2)
        job={"status":"completed","finished_at":recent.isoformat(),
             "created_at":recent.isoformat(),
             "request":{"target_type":"ip","target":"185.220.213.51",
                        "ports":"extended"},"plan":{"check_count":91}}
        def go(args,binary):
            if args==["jobs"]: return {"jobs":[job]}
            raise AssertionError("cooldown must skip scan")
        self.assertEqual(nightly.run(cfg,True,fetch_factory("185.220.213.51"),go,NOW),0)

    def test_inventory_pagination_drift_aborts(self):
        cfg=config()
        with self.assertRaises(RuntimeError):
            nightly.inventory(cfg,fetch_factory("185.220.213.51",total_override=2))

    def test_outside_window(self):
        cfg=config()
        def go(args,binary):
            if args==["jobs"]: return {"jobs":[]}
            raise AssertionError("not allowed to queue outside night")
        self.assertEqual(nightly.run(cfg,True,fetch_factory("185.220.213.51"),
                                     go,NOW.replace(hour=9)),0)

    def test_nightly_check_budget(self):
        cfg=config()
        cfg["max_checks_per_night"]=100
        calls=[]
        def go(args,binary):
            calls.append(args)
            if args==["jobs"]: return {"jobs":[]}
            if args[0]=="plan": return {"host_count":1,"check_count":91}
            if args[0]=="scan": return {"status":"queued","id":"abc"}
        n=nightly.run(cfg,True,fetch_factory("185.220.213.51",
                                             "185.220.213.52"),go,NOW)
        self.assertEqual(n,1)

if __name__=="__main__":
    unittest.main()
