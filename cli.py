"""Dependency-free ScanLattice CLI. Set SCANLATTICE_URL and optionally SCANLATTICE_API_KEY."""
import argparse, json, os, sys
import uuid
from sdk.client import ScanLatticeClient

def main():
    parser=argparse.ArgumentParser(prog="scanlattice",description="Search ScanLattice indexed intelligence")
    parser.add_argument("--url",default=os.getenv("SCANLATTICE_URL","https://scanlattice.plezi.eu"))
    sub=parser.add_subparsers(dest="command",required=True)
    q=sub.add_parser("search");q.add_argument("query");q.add_argument("--page",type=int,default=1)
    h=sub.add_parser("host");h.add_argument("ip")
    hist=sub.add_parser("history");hist.add_argument("ip");hist.add_argument("--page",type=int,default=1)
    sub.add_parser("stats")
    v=sub.add_parser("vulnerabilities");v.add_argument("query",nargs="?",default="")
    imp=sub.add_parser("import-dataset",help="Upload a large CSV/JSON/JSONL dataset with resumable chunks")
    imp.add_argument("file");imp.add_argument("--source",required=True);imp.add_argument("--import-id",default="");imp.add_argument("--chunk-size",type=int,default=1024*1024)
    args=parser.parse_args();client=ScanLatticeClient(args.url,os.getenv("SCANLATTICE_API_KEY"),admin_token=os.getenv("SCANLATTICE_ADMIN_TOKEN"))
    try:
        if args.command=="search":data=client.search(args.query,args.page)
        elif args.command=="host":data=client.host(args.ip)
        elif args.command=="history":data=client.history(args.ip,args.page)
        elif args.command=="stats":data=client.analytics()
        elif args.command=="import-dataset":data=client.upload_dataset(args.file,args.source,args.import_id or None,args.chunk_size)
        else:data=client.vulnerabilities(args.query)
        print(json.dumps(data,indent=2,ensure_ascii=False))
    except (RuntimeError,ValueError) as exc:
        print(str(exc),file=sys.stderr);return 1
    return 0
if __name__=="__main__":raise SystemExit(main())
