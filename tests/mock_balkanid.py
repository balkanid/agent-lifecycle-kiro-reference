"""In-process mock of the BalkanID Public API GraphQL endpoint for tests."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockBalkanID:
    def __init__(self) -> None:
        self.requests: dict[str, dict] = {}
        self.created: list[dict] = []
        self.identities: dict[str, dict] = {}
        self.step_up_required = False
        self.next_status = "approved"
        self._counter = 0
        self.calls = 0
        mock = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):  # silence
                pass

            def do_POST(self):  # noqa: N802
                mock.calls += 1
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length) or b"{}")
                if self.headers.get("X-Api-Key-Id") != "test-key":
                    self.send_response(401)
                    self.end_headers()
                    self.wfile.write(b'{"errors":[{"message":"unauthorized"}]}')
                    return
                data = mock.handle(body.get("query", ""), body.get("variables") or {})
                out = json.dumps({"data": data}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api/public"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()

    def set_status(self, request_id: str, status: str) -> None:
        self.requests[request_id]["status"] = status

    def handle(self, query: str, variables: dict) -> dict:
        if "createRequest" in query:
            inp = variables["input"]
            self.created.append(inp)
            if self.step_up_required:
                return {"createRequest": {"id": None, "success": False, "eventIds": [], "stepUpRequired": True}}
            self._counter += 1
            rid = f"req-{self._counter}"
            self.requests[rid] = {"id": rid, "status": self.next_status, "requestType": inp["requestType"]}
            return {"createRequest": {"id": rid, "success": True, "eventIds": [], "stepUpRequired": False}}
        if "requests(" in query:
            rid = variables["filter"]["id"]["_eq"]
            node = self.requests.get(rid)
            if not node:
                return {"requests": {"edges": []}}
            return {
                "requests": {
                    "edges": [
                        {
                            "node": {
                                "id": rid,
                                "status": node["status"],
                                "requestApprovalStatus": node["status"],
                                "requestProvisioningStatus": None,
                                "requestType": node["requestType"],
                                "metadata": {},
                            }
                        }
                    ]
                }
            }
        if "identities(" in query:
            handle = variables["filter"]["handle"]["_eq"]
            ident = self.identities.get(handle)
            return {"identities": {"edges": [{"node": ident}] if ident else []}}
        if "syncIntegration" in query:
            return {"syncIntegration": {"success": True, "correlationId": "corr-1"}}
        raise AssertionError(f"unexpected query: {query[:80]}")
