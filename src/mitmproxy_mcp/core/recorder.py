import json
import shlex
import sqlite3
import sys
from collections import deque  # added
from typing import Any, Dict, List, Optional

from mitmproxy import http

from .scope import ScopeManager
from .utils import get_safe_text


class SimpleRequest:
    def __init__(self, method: str, url: str, headers: Dict[str, str], body: Optional[str]):
        self.method = method
        self.url = url
        self.headers = headers
        self.body = body


class SimpleResponse:
    def __init__(
        self,
        status_code: Optional[int],
        headers: Optional[Dict[str, str]],
        body: Optional[str],
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body


class TrafficDB:
    """Implements SQLite persistence for traffic logs."""

    def __init__(self, db_path: str = "mitm_mcp_traffic.db"):
        self.db_path = db_path
        self._init_db()

    def _get_conn(self):
        return sqlite3.connect(self.db_path, check_same_thread=False)

    def _init_db(self):
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS flows (
                    id TEXT PRIMARY KEY,
                    url TEXT,
                    method TEXT,
                    status_code INTEGER,
                    request_headers TEXT,
                    request_body TEXT,
                    response_headers TEXT,
                    response_body TEXT,
                    timestamp REAL,
                    size INTEGER
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON flows(timestamp)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON flows(url)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_method ON flows(method)")

    def save_flow(self, flow: http.HTTPFlow):
        """Upserts a flow into the database."""
        req_body = get_safe_text(flow.request)
        resp_body = get_safe_text(flow.response) if flow.response else None

        status_code = flow.response.status_code if flow.response else None
        size = len(flow.response.content) if flow.response and flow.response.content else 0

        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO flows (
                    id, url, method, status_code,
                    request_headers, request_body,
                    response_headers, response_body,
                    timestamp, size
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    url=excluded.url,
                    method=excluded.method,
                    status_code=excluded.status_code,
                    request_headers=excluded.request_headers,
                    request_body=excluded.request_body,
                    response_headers=excluded.response_headers,
                    response_body=excluded.response_body,
                    size=excluded.size
            """,
                (
                    flow.id,
                    flow.request.url,
                    flow.request.method,
                    status_code,
                    json.dumps(dict(flow.request.headers)),
                    req_body,
                    json.dumps(dict(flow.response.headers)) if flow.response else None,
                    resp_body,
                    flow.request.timestamp_start,
                    size,
                ),
            )

    def get_summary(
        self,
        limit: int = 20,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                """
                SELECT id, url, method, status_code,
                       response_headers, timestamp, size
                FROM flows
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            """,
                (limit, offset),
            )

            rows = cursor.fetchall()
            result = []
            for row in rows:
                content_type = "unknown"
                if row["response_headers"]:
                    headers = json.loads(row["response_headers"])
                    content_type = headers.get(
                        "content-type",
                        headers.get("Content-Type", "unknown"),
                    )

                result.append({
                    "id": row["id"],
                    "url": row["url"],
                    "method": row["method"],
                    "status_code": row["status_code"],
                    "content_type": content_type,
                    "size": row["size"],
                    "timestamp": row["timestamp"],
                })
            return result

    def get_detail(self, flow_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
            row = cursor.fetchone()

            if not row:
                return None

            req_headers = json.loads(row["request_headers"])
            resp_headers = json.loads(row["response_headers"]) if row["response_headers"] else None

            simple_request = SimpleRequest(
                method=row["method"],
                url=row["url"],
                headers=req_headers,
                body=row["request_body"],
            )
            simple_response = (
                SimpleResponse(
                    status_code=row["status_code"],
                    headers=resp_headers,
                    body=row["response_body"],
                )
                if row["status_code"] is not None
                else None
            )

            return {
                "id": row["id"],
                "request": {
                    "method": simple_request.method,
                    "url": simple_request.url,
                    "headers": simple_request.headers,
                    "body_preview": (
                        simple_request.body[:2000] if simple_request.body else None
                    ),
                },
                "response": {
                    "status_code": simple_response.status_code,
                    "headers": simple_response.headers,
                    "body_preview": (simple_response.body[:2000] if simple_response.body else None),
                }
                if simple_response
                else None,
                "curl_command": self._generate_curl(simple_request),
            }

    def search(
        self, query: str = None, domain: str = None, method: str = None, limit: int = 50
    ) -> List[Dict[str, Any]]:
        sql = "SELECT id, url, method, status_code, timestamp FROM flows WHERE 1=1"
        params = []

        if domain:
            sql += " AND url LIKE ?"
            params.append(f"%{domain}%")

        if method:
            sql += " AND method = ?"
            params.append(method.upper())

        if query:
            sql += " AND (url LIKE ? OR request_body LIKE ? OR response_body LIKE ?)"
            wildcard = f"%{query}%"
            params.extend([wildcard, wildcard, wildcard])

        sql += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql, params)
            return [dict(row) for row in cursor.fetchall()]

    def clear(self):
        with self._get_conn() as conn:
            conn.execute("DELETE FROM flows")

    def get_all_for_analysis(self, limit: int = 1000) -> List[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM flows ORDER BY timestamp DESC LIMIT ?", (limit,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append({
                    "id": row["id"],
                    "request": {
                        "url": row["url"],
                        "method": row["method"],
                        "headers": json.loads(row["request_headers"]),
                        "body": row["request_body"],
                    },
                    "response": {
                        "status_code": row["status_code"],
                        "headers": json.loads(row["response_headers"]) if row["response_headers"] else {},
                        "body": row["response_body"],
                    }
                    if row["status_code"]
                    else None,
                })
            return results

    def _generate_curl(self, request: SimpleRequest) -> str:
        try:
            cmd = ["curl", "-X", request.method]
            cmd.append(shlex.quote(request.url))

            for key, value in request.headers.items():
                cmd.append("-H")
                cmd.append(shlex.quote(f"{key}: {value}"))

            if request.body:
                cmd.append("-d")
                cmd.append(shlex.quote(request.body))

            return " ".join(cmd)
        except Exception:
            return "Error generating curl command"

    # Helper to reconstruct a minimal request for replay
    def get_flow_object(self, flow_id: str) -> Optional[SimpleRequest]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT method, url, request_headers, request_body FROM flows WHERE id = ?",
                (flow_id,),
            )
            row = cursor.fetchone()

            if not row:
                return None

            headers = json.loads(row["request_headers"])
            return SimpleRequest(
                method=row["method"],
                url=row["url"],
                headers=headers,
                body=row["request_body"],
            )


class TrafficRecorder:
    """Captures flows into SQLite for inspection."""

    def __init__(self, scope: ScopeManager):
        self.scope = scope
        self.db = TrafficDB()
        # Keep a small in-memory deque of objects for legacy usage (like replay)
        # Note: This buffer is non-persistent, SQLite is the main storage.
        self.flows = deque(maxlen=500)

    def request(self, flow: http.HTTPFlow):
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                print(
                    f"DEBUG: Request saved for {flow.request.url}",
                    file=sys.stderr,
                )
            except Exception as e:
                print(f"Failed to save request flow: {e}", file=sys.stderr)

    def response(self, flow: http.HTTPFlow):
        print(
            f"DEBUG: Response hook called for {flow.request.url}",
            file=sys.stderr,
        )
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
                print(f"DEBUG: Saved flow {flow.id}", file=sys.stderr)
            except Exception as e:
                print(f"Failed to save flow: {e}", file=sys.stderr)

    def error(self, flow: http.HTTPFlow):
        if self.scope.is_allowed(flow):
            try:
                self.db.save_flow(flow)
                self.flows.append(flow)
            except Exception as e:
                print(f"Failed to save flow error: {e}", file=sys.stderr)

    def get_flow_summary(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self.db.get_summary(limit=limit)

    def get_flow_detail(self, flow_id: str) -> Optional[Dict[str, Any]]:
        return self.db.get_detail(flow_id)

    def search(self, query: str, domain: str, method: str, limit: int):
        return self.db.search(query, domain, method, limit)

    def clear(self):
        self.db.clear()

    def get_all_for_analysis(self, limit: int = 1000) -> List[Dict[str, Any]]:
        return self.db.get_all_for_analysis(limit)
