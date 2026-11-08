"""Small dependency-free ScanLattice API client for Python 3.10+."""
from __future__ import annotations
import json
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

class ScanLatticeClient:
    def __init__(self, base_url: str, api_key: str | None = None, timeout: float = 15):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def get(self, path: str, **params):
        query = urlencode({k: v for k, v in params.items() if v is not None})
        url = self.base_url + path + ("?" + query if query else "")
        headers = {"Accept": "application/json"}
        if self.api_key: headers["Authorization"] = "Bearer " + self.api_key
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
