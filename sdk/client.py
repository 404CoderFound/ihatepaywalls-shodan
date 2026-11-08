"""Small dependency-free ScanLattice API client for Python 3.10+."""
from __future__ import annotations
import json
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

class ScanLatticeClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 15, admin_token: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.admin_token = admin_token

    def get(self, path: str, **params):
        query = urlencode({k: v for k, v in params.items() if v is not None})
        url = self.base_url + path + ("?" + query if query else "")
        headers = {"Accept": "application/json"}
        if self.api_key: headers["Authorization"] = "Bearer " + self.api_key
        if self.admin_token: headers["X-Admin-Token"] = self.admin_token
        request = Request(url, headers=headers)
        try:
            with urlopen(request, timeout=self.timeout) as response:
                content = response.read()
                return json.loads(content) if "json" in response.headers.get("Content-Type", "") else content
        except HTTPError as exc:
            try: message = json.loads(exc.read()).get("detail", str(exc))
            except Exception: message = str(exc)
            raise RuntimeError(f"ScanLattice API {exc.code}: {message}") from exc
        except URLError as exc:
            raise RuntimeError(f"ScanLattice API unavailable: {exc.reason}") from exc

    def search(self, query: str, page: int = 1): return self.get("/api/search", q=query, page=page)
    def host(self, ip: str): return self.get("/api/hosts/" + ip)
    def history(self, ip: str, page: int = 1): return self.get("/api/hosts/" + ip + "/observations", page=page)
    def vulnerabilities(self, query: str = "", page: int = 1): return self.get("/api/vulnerabilities", q=query, page=page)
    def analytics(self): return self.get("/api/analytics/summary")

    def upload_dataset(self, path: str, source: str, import_id: str | None = None, chunk_size: int = 1024 * 1024):
        """Upload CSV/JSON/JSONL or .gz files in resumable raw chunks using an admin token."""
        if not self.admin_token: raise ValueError("Dataset imports require admin_token")
        path=Path(path);suffixes=path.suffixes;encoding="gzip" if suffixes and suffixes[-1]==".gz" else "identity"
        stem=path.name[:-3] if encoding=="gzip" else path.name
        fmt=Path(stem).suffix.lower().lstrip(".")
        if fmt not in {"csv","json","jsonl"}:raise ValueError("Dataset file must be CSV, JSON, JSONL, or one of those formats with .gz")
        if not 1<=chunk_size<=8*1024*1024:raise ValueError("chunk_size must be between 1 byte and 8 MiB")
        import_id=import_id or str(uuid.uuid4());total=path.stat().st_size
        existing=next((r for r in self.get("/api/admin/datasets/imports")["imports"] if r["id"]==import_id),None)
        offset=existing["uploaded_bytes"] if existing else 0
        if existing and (existing["source"]!=source or existing["format"]!=fmt or existing["encoding"]!=encoding):raise ValueError("Import id already belongs to different file metadata")
        if existing and existing["status"]=="completed":return existing
        if existing and offset==total and existing["status"]=="partial":
            request=Request(self.base_url+f"/api/admin/datasets/imports/{import_id}/resume",data=b"",headers={"X-Admin-Token":self.admin_token},method="POST")
            with urlopen(request,timeout=self.timeout) as response:return json.loads(response.read())
        with path.open("rb") as file:
            file.seek(offset)
            while offset<total:
                chunk=file.read(min(chunk_size,total-offset));end=offset+len(chunk)-1
                headers={"X-Admin-Token":self.admin_token,"X-Import-Id":import_id,"X-Import-Source":source,"X-Import-Format":fmt,"X-Import-Encoding":encoding,"Content-Range":f"bytes {offset}-{end}/{total}","Content-Type":"application/octet-stream"}
                request=Request(self.base_url+"/api/admin/datasets/imports",data=chunk,headers=headers,method="POST")
                try:
                    with urlopen(request,timeout=self.timeout) as response:data=json.loads(response.read())
                except HTTPError as exc:
                    try:detail=json.loads(exc.read()).get("detail",str(exc))
                    except Exception:detail=str(exc)
                    raise RuntimeError(f"Dataset import {import_id} stopped at byte {offset}: {detail}") from exc
                offset=data.get("resume_offset",data.get("uploaded_bytes",offset+len(chunk)))
                if data.get("status")=="completed":return data
        return self.get("/api/admin/datasets/imports")
