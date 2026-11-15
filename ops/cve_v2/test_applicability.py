import unittest
from applicability import Truth, criterion, assess, split_cpe, key

APACHE = "cpe:2.3:a:apache:http_server:2.4.58:*:*:*:*:*:*:*"
SSH = "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"
WINDOWS = "cpe:2.3:o:microsoft:windows_11:23h2:*:*:*:*:*:*:*"

def cpe(value, vulnerable=True, **kwargs):
    return {"criteria":value,"vulnerable":vulnerable,**kwargs}

def configuration(nodes):
    return [{"nodes":nodes}]

class MatchingTests(unittest.TestCase):
    def test_cpe_parts(self):
        self.assertEqual(len(split_cpe(SSH)),11)
        self.assertEqual(key(SSH),"a:openbsd:openssh")
    def test_old_ssh_range_rejected(self):
        rule=cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*",
                 versionStartIncluding="8.9",versionEndExcluding="9.3")
        self.assertEqual(criterion(rule,[SSH]),Truth.FALSE)
        self.assertIsNone(assess(configuration([{"cpeMatch":[rule]}]),[SSH]))
    def test_not_applicable_version_not_wildcard(self):
        rule=cpe("cpe:2.3:a:openbsd:openssh:-:*:*:*:*:*:*:*")
        self.assertIsNone(assess(configuration([{"cpeMatch":[rule]}]),[SSH]))
    def test_windows_condition_unknown_on_apache(self):
        apache=cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                   versionStartIncluding="2.4.57",versionEndExcluding="2.4.59")
        windows=cpe("cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
                    vulnerable=False)
        config=configuration([{"operator":"AND","cpeMatch":[apache,windows]}])
        self.assertEqual(assess(config,[APACHE]),"needs_evidence")
        self.assertEqual(assess(config,[APACHE,WINDOWS]),"potential")
    def test_os_does_not_infer_backports(self):
        rule=cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 versionStartIncluding="2.4.57",versionEndExcluding="2.4.59")
        # This is only a potential version signal, NEVER confirmed exposure.
        self.assertEqual(assess(configuration([{"cpeMatch":[rule]}]),[APACHE]),
                         "potential")
    def test_nested_boolean_conditions(self):
        vuln=cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*")
        windows=cpe("cpe:2.3:o:microsoft:windows_11:*:*:*:*:*:*:*:*",
                    vulnerable=False)
        other=cpe("cpe:2.3:a:other:product:*:*:*:*:*:*:*:*")
        config=configuration([{"operator":"OR","children":[
            {"operator":"AND","cpeMatch":[vuln,windows]},
            {"cpeMatch":[other]}]}])
        self.assertEqual(assess(config,[APACHE]),"needs_evidence")
        self.assertEqual(assess(config,[APACHE,WINDOWS]),"potential")
    def test_unknown_version_is_not_positive(self):
        hidden="cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
        rule=cpe("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
                 versionEndExcluding="2.4.59")
        self.assertEqual(criterion(rule,[hidden]),Truth.UNKNOWN)
        self.assertIsNone(assess(configuration([{"cpeMatch":[rule]}]),[hidden]))
    def test_unknown_conditional_release(self):
        rule=cpe("cpe:2.3:a:vendor:thing:*:*:*:*:*:*:*:*",
                 versionEndExcluding="1.0rc1")
        self.assertEqual(criterion(rule,["cpe:2.3:a:vendor:thing:0.9:*:*:*:*:*:*:*"]),
                         Truth.UNKNOWN)
if __name__=="__main__":
    unittest.main()
