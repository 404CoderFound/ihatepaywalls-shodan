from __future__ import annotations

import concurrent.futures, ipaddress, json, os, socket, ssl, sys, threading, time, urllib.error, urllib.request, uuid
from pathlib import Path
from worker.scanners import scan_endpoint

CONTROL=os.getenv("CONTROL_URL","").rstrip("/");ENROLL=os.getenv("ENROLLMENT_TOKEN","");NAME=os.getenv("WORKER_NAME",socket.gethostname())
STATE=Path(os.getenv("WORKER_STATE_FILE","/data/registration.json"));INTERVAL=int(os.getenv("HEARTBEAT_SECONDS","10"));MAX_CONCURRENT=int(os.getenv("WORKER_MAX_CONCURRENT","1"));VERSION="0.5.0"
CAPABILITIES=["tcp-connect","http-headers","tls-metadata","ssh-identification","service-fingerprints","redis-ping","postgresql-sslrequest"]

def call(path,payload=None,headers=None):
    data=json.dumps(payload).encode() if payload is not None else None
    req=urllib.request.Request(CONTROL+path,data=data,headers={"Content-Type":"application/json",**(headers or {})},method="POST" if data is not None else "GET")
    with urllib.request.urlopen(req,timeout=30,context=ssl.create_default_context()) as response:return json.load(response)
def cpu():
    try:return round(min(100,os.getloadavg()[0]/(os.cpu_count() or 1)*100),1)
    except OSError:return 0
def memory():
    try:
        values={line.split(":")[0]:int(line.split()[1]) for line in Path("/proc/meminfo").read_text().splitlines() if line.startswith(("MemTotal:","MemAvailable:"))}
        return round(100*(1-values["MemAvailable"]/values["MemTotal"]),1)
    except (OSError,KeyError):return 0
def credentials():
    if STATE.exists():
        data=json.loads(STATE.read_text())
        if data.get("worker_token"):return data
    if not ENROLL:raise RuntimeError("ENROLLMENT_TOKEN is required for initial registration")
    data=call("/api/worker/register",{"name":NAME,"capabilities":CAPABILITIES,"version":VERSION,"max_concurrent":MAX_CONCURRENT},{"X-Enrollment-Token":ENROLL})
    STATE.parent.mkdir(parents=True,exist_ok=True);STATE.write_text(json.dumps(data));STATE.chmod(0o600);return data
def execute(job,headers):
    target=ipaddress.ip_network(job["target"],strict=False);allowed=ipaddress.ip_network(job["authorization_cidr"],strict=False)
    if not target.subnet_of(allowed):raise RuntimeError("Control server supplied a target outside its authorization")
    if target.num_addresses>4096 or len(job["ports"])>100:raise RuntimeError("Job exceeds worker safety limits")
    call(f"/api/worker/jobs/{job['id']}/start",{"lease_token":job["lease_token"]},headers)
    tasks=[(str(ip),port) for ip in target for port in job["ports"]];results=[];done=0;last_report=time.monotonic()
    concurrency=min(int(job["max_concurrency"]),50)
    rate=max(.1,float(job.get("rate_per_second",20)));rate_lock=threading.Lock();next_start=[time.monotonic()]
    def rate_limited_scan(ip,port):
        with rate_lock:
            delay=next_start[0]-time.monotonic()
            if delay>0:time.sleep(delay)
            next_start[0]=max(next_start[0],time.monotonic())+1/rate
        return scan_endpoint(ip,port,float(job["connect_timeout"]),float(job["banner_timeout"]))
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=concurrency)
    futures=[pool.submit(rate_limited_scan,ip,port) for ip,port in tasks]
    try:
        for future in concurrent.futures.as_completed(futures):
            result=future.result();done+=1
            if result:results.append(result)
            if done%25==0 or time.monotonic()-last_report>=10:
                call(f"/api/worker/jobs/{job['id']}/progress",{"lease_token":job["lease_token"],"progress_done":done},headers);last_report=time.monotonic()
    except Exception:
        for future in futures:future.cancel()
        pool.shutdown(wait=False,cancel_futures=True)
        raise
    else:pool.shutdown(wait=True)
    return call(f"/api/worker/jobs/{job['id']}/results",{"lease_token":job["lease_token"],"idempotency_key":f"{job['id']}:{uuid.uuid4()}","completed_checks":done,"observations":results},headers)
def main():
    if not CONTROL.startswith("https://") and not (os.getenv("ALLOW_INSECURE_LOCALHOST")=="true" and CONTROL.startswith("http://127.0.0.1")):raise RuntimeError("CONTROL_URL must use HTTPS")
    backoff=5
    while True:
        try:
            creds=credentials();headers={"X-Worker-Token":creds["worker_token"]};call("/api/worker/heartbeat",{"cpu_pct":cpu(),"memory_pct":memory(),"active_jobs":0,"version":VERSION,"capabilities":CAPABILITIES,"max_concurrent":MAX_CONCURRENT},headers)
            for job in call("/api/worker/jobs/claim",{},headers)["jobs"]:
                try:execute(job,headers)
                except Exception as exc:
                    try:call(f"/api/worker/jobs/{job['id']}/fail",{"lease_token":job["lease_token"],"error":str(exc)[:1000]},headers)
                    except Exception:pass
            backoff=5;time.sleep(INTERVAL)
        except KeyboardInterrupt:return
        except Exception as exc:print(f"Worker disconnected: {exc}",file=sys.stderr,flush=True);time.sleep(backoff);backoff=min(backoff*2,120)
if __name__=="__main__":main()
