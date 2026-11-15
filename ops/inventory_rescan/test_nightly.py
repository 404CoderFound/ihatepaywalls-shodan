import ipaddress
from datetime import datetime, timedelta, timezone
import unittest
import nightly

NOW = datetime(2026,11,15,2,30,tzinfo=timezone.utc)

def config():
    return {
        "_website":"https://scanlattice.plezi.eu",
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

    def test_all_indexed_public_hosts_queued(self):
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

    def test_public_indexed_targets_respect_exclusions(self):
        cfg=config()
        self.assertTrue(nightly.permitted("1.1.1.1",cfg))
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

    def test_pagination_fetches_every_host(self):
        cfg=config()
        ips=["185.220.213."+str(i) for i in range(1,103)]
        def fetch(url):
            import urllib.parse
            values=urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
            page=int(values["page"][0])
            chunk=ips[(page-1)*100:page*100]
            return {"page":page,"total":len(ips),"hosts":[{"ip":v} for v in chunk],
                    "has_next":page*100<len(ips)}
        self.assertEqual(set(nightly.inventory(cfg,fetch)),set(ips))

    def test_passive_only_ip_also_in_inventory(self):
        cfg=config()
        def fetch(url):
            return {"page":1,"total":1,"hosts":[{"ip":"185.220.213.51"}],
                    "has_next":False,"passive_total":2,
                    "passive_intelligence":[
                        {"ip":"185.220.213.52","record_type":"rdap"},
                        {"ip":"","network":"185.220.212.0/22"}]}
        got=nightly.inventory(cfg,fetch)
        self.assertEqual(set(got),{"185.220.213.51","185.220.213.52"})

    def test_config_requires_no_cidr_list(self):
        import tempfile, json, pathlib
        with tempfile.TemporaryDirectory() as folder:
            root=pathlib.Path(folder)
            scanner=root/"scanner.json"
            scanner.write_text(json.dumps({"excluded_cidrs":[]}))
            cfg=root/"inventory.json"
            cfg.write_text(json.dumps({
                "website_url":"https://scanlattice.plezi.eu",
                "scanner_config":str(scanner),
                "ports":"extended","max_inventory_hosts":100,
                "max_jobs_per_tick":1,"max_pending_jobs":1,
                "max_jobs_per_night":1,"max_checks_per_night":100,
                "cooldown_hours":24,"night_start_utc":0,"night_end_utc":5
            }))
            loaded=nightly.load_config(cfg)
            self.assertTrue(nightly.permitted("1.1.1.1",loaded))
            self.assertFalse(nightly.permitted("192.168.0.9",loaded))

    def test_atomic_go_job_files_are_read(self):
        import tempfile, json, pathlib
        with tempfile.TemporaryDirectory() as folder:
            jobs=pathlib.Path(folder)/"jobs"
            jobs.mkdir()
            (jobs/"abc.json").write_text(json.dumps({
                "status":"queued","request":{"target_type":"ip",
                "target":"185.220.213.51","ports":"extended"}}))
            cfg=config()
            cfg["_scanner_state_dir"]=folder
            self.assertEqual(len(nightly.read_jobs(cfg,None)),1)

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
