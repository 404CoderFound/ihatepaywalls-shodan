#!/usr/bin/env python3
"""Opt-in ScanLattice v3.2 source patch: exhaustive TCP 1..65535 on ONE allowlisted IP.

No changes to binaries/config/services are made by this script.
"""
import argparse
from pathlib import Path
import shutil

p=argparse.ArgumentParser()
p.add_argument("--source",required=True,help="Existing local aws-v3.2 Go source directory")
args=p.parse_args()
root=Path(args.source).resolve()
policy=root/"internal/scan/policy.go"
targets=root/"internal/scan/targets.go"
cli=root/"cmd/scanlattice/main.go"
for f in (policy,targets,cli):
    if not f.is_file(): raise SystemExit("Expected v3.2 Go source missing: "+str(f))

def patch(f,old,new):
    s=f.read_text()
    if new in s:
        print("Already patched:",f)
        return
    if s.count(old)!=1:
        raise SystemExit("Unexpected source version; refusing to modify "+str(f))
    shutil.copy2(f,str(f)+".before-full-tcp")
    f.write_text(s.replace(old,new,1))
    print("PATCHED",f)

patch(policy,
      'if c.MaxPorts < 1 || c.MaxPorts > 1024 {',
      'if c.MaxPorts < 1 || c.MaxPorts > 65535 {')
patch(policy,
      'func Ports(s string, max int) ([]int, error) {\n',
      '''func Ports(s string, max int) ([]int, error) {
    if strings.ToLower(s) == "all-tcp" {
        if max < 65535 { return nil, errors.New("all-tcp requires max_ports=65535") }
        out := make([]int, 65535)
        for i := range out { out[i] = i+1 }
        return out,nil
    }
''')
patch(targets,
      '''\tports, e := Ports(r.Ports, c.MaxPorts)
''',
      '''\t// Exhaustive TCP is deliberately restricted to one explicitly allowlisted host.
    if r.Ports == "all-tcp" {
        if r.TargetType != "ip" {
            return Plan{}, errors.New("all-tcp requires --ip, never subnet/asn/public sampling")
        }
        address, err := netip.ParseAddr(r.Target)
        if err != nil { return Plan{}, errors.New("invalid all-tcp address") }
        permitted := false
        for _, raw := range c.AllowedCIDRs {
            subnet, err := netip.ParsePrefix(raw)
            if err == nil && subnet.Contains(address) { permitted = true; break }
        }
        if !permitted {
            return Plan{}, errors.New("all-tcp requires IP in explicit allowed_cidrs, even with public mode")
        }
    }
\tports, e := Ports(r.Ports, c.MaxPorts)
''')
patch(cli,
      'Port sets: quick, standard, extended, or 22,80,443,... (TCP only)',
      'Port sets: quick, standard, extended, all-tcp (allowlisted single IP only), or 22,80,443,... (TCP only)')

print("PATCH COMPLETE: run Go tests, build and back up the installed binary before upgrading.")
print("This source-only patch has not changed running scans or config.")
