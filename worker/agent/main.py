from __future__ import annotations

import concurrent.futures, ipaddress, json, os, socket, ssl, sys, threading, time, urllib.error, urllib.request, uuid
from pathlib import Path
from worker.scanners import scan_endpoint
from worker.agent.batches import run_batched_job

CONTROL=os.getenv("CONTROL_URL","").rstrip("/");ENROLL=os.getenv("ENROLLMENT_TOKEN","");NAME=os.getenv("WORKER_NAME",socket.gethostname())
STATE=Path(os.getenv("WORKER_STATE_FILE","/data/registration.json"));INTERVAL=int(os.getenv("HEARTBEAT_SECONDS","10"));MAX_CONCURRENT=int(os.getenv("WORKER_MAX_CONCURRENT","1"));VERSION="0.6.0"
CAPABILITIES=["tcp-connect","http-headers","tls-metadata","ssh-identification","durable-batched-results"]

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
    return run_batched_job(job,headers,call,scan_endpoint,STATE.parent/"batch-spool")

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
