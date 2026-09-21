import json
import os
import shlex
import sqlite3
import sys
from collections import deque
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from mitmproxy import http
from mitmproxy.io import FlowReader

from .scope import ScopeManager, host_in_scope
from .utils import get_safe_text

# Headers whose values may carry live credentials. They are redacted before any
# flow detail is handed back to a caller (and therefore to the model context).
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
}
REDACTED = "<REDACTED>"

ALLOWED_IMPORT_EXTENSIONS = (".har", ".mitm", ".flow")


def _parse_headers(raw: str) -> Dict[str, str]:
    """Parse stored headers into a dict for backward compat.

    Headers are stored as either:
    - list of [key, value] pairs (new format, preserves order)
    - dict (legacy format)
    Returns a dict in both cases. Duplicate keys are collapsed (last wins).
    """
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return {k: v for k, v in parsed}
    return parsed


def _parse_headers_ordered(raw: str) -> List[List[str]]:
    """Parse stored headers into an ordered list of [key, value] pairs.

    Preserves header ordering and duplicate keys. Used by codegen tools
    where header order matters (e.g. HTTP fingerprinting).
    """
    parsed = json.loads(raw)
    if isinstance(parsed, list):
        return parsed
    return [[k, v] for k, v in parsed.items()]


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


def _redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Replace credential-bearing header values with a placeholder."""
    return {
        k: (REDACTED if k.lower() in SENSITIVE_HEADERS else v)
        for k, v in headers.items()
    }


def _redact_headers_ordered(headers: List[List[str]]) -> List[List[str]]:
    """Replace credential-bearing values in an ordered [key, value] list."""
    return [
        [k, (REDACTED if k.lower() in SENSITIVE_HEADERS else v)]
        for k, v in headers
    ]


class TrafficDB:
    """Implements SQLite persistence for traffic logs."""

    def __init__(self, db_path: str = "mitm_mcp_traffic.db"):
        self.db_path = db_path
        self._init_db()

    @contextmanager
    def _get_conn(self):
        """Open a connection that is always closed, with WAL and a busy timeout."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=30)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            with conn:
                yield conn
        finally:
            conn.close()

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
                    json.dumps(
                        [
                            [k.decode("latin-1"), v.decode("latin-1")]
                            for k, v in flow.request.headers.fields
                        ],
                    ),
                    req_body,
                    json.dumps(
                        [
                            [k.decode("latin-1"), v.decode("latin-1")]
                            for k, v in flow.response.headers.fields
                        ],
                    )
                    if flow.response
                    else None,
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
                    headers = _parse_headers(row["response_headers"])
                    content_type = headers.get(
                        "content-type",
                        headers.get("Content-Type", "unknown"),
                    )

                result.append(
                    {
                        "id": row["id"],
                        "url": row["url"],
                        "method": row["method"],
                        "status_code": row["status_code"],
                        "content_type": content_type,
                        "size": row["size"],
                        "timestamp": row["timestamp"],
                    }
                )
            return result

    def get_detail(self, flow_id: str) -> Optional[Dict[str, Any]]:
        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM flows WHERE id = ?", (flow_id,))
            row = cursor.fetchone()

            if not row:
                return None

            req_headers = _redact_headers(_parse_headers(row["request_headers"]))
            resp_headers = (
                _redact_headers(_parse_headers(row["response_headers"]))
                if row["response_headers"]
                else None
            )

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
                    "body_preview": (simple_request.body[:2000] if simple_request.body else None),
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

    def get_all_for_analysis(
        self,
        limit: Optional[int] = None,
        lightweight: bool = False,
        redact: bool = True,
    ) -> List[Dict[str, Any]]:
        """Fetch flows for analysis.

        Args:
            limit: Max flows to return. None = all flows.
            lightweight: If True, only select columns needed for clustering
                (no bodies). Reduces memory usage for large captures.
            redact: Replace credential-bearing header values. Set False only
                for in-process analysis that inspects the value but never
                returns it (e.g. auth-scheme detection).
        """
        if lightweight:
            cols = "id, url, method, status_code, request_headers, response_headers"
        else:
            cols = "*"

        # cols is a fixed literal ("*" or a constant column list); values are
        # always passed as bound parameters.
        sql = "SELECT {} FROM flows ORDER BY timestamp DESC".format(cols)  # nosec B608
        params: list = []
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(sql, params)
            rows = cursor.fetchall()
            results = []
            for row in rows:
                results.append(
                    {
                        "id": row["id"],
                        "request": {
                            "url": row["url"],
                            "method": row["method"],
                            "headers": (
                                _redact_headers(_parse_headers(row["request_headers"]))
                                if redact
                                else _parse_headers(row["request_headers"])
                            ),
                            **(
                                {"body": row["request_body"]}
                                if not lightweight
                                else {}
                            ),
                        },
                        "response": {
                            "status_code": row["status_code"],
                            "headers": (
                                _redact_headers(_parse_headers(row["response_headers"]))
                                if redact
                                else _parse_headers(row["response_headers"])
                            )
                            if row["response_headers"]
                            else {},
                            **(
                                {"body": row["response_body"]}
                                if not lightweight
                                else {}
                            ),
                        }
                        if row["status_code"]
                        else None,
                    }
                )
            return results

    def get_by_ids(
        self,
        flow_ids: List[str],
        columns: Optional[List[str]] = None,
        ordered_headers: bool = False,
    ) -> List[Dict[str, Any]]:
        """Fetch flows by IDs.

        Args:
            flow_ids: List of flow IDs to fetch.
            columns: SQL columns to select. None = all columns.
                Reduces memory when response bodies aren't needed.
            ordered_headers: If True, return headers as ordered [key, value]
                pairs instead of dict. Used by codegen for header ordering.
        """
        if not flow_ids:
            return []

        if columns:
            allowed_cols = {
                "id", "url", "method", "status_code", "request_headers", 
                "request_body", "response_headers", "response_body", "timestamp", "size"
            }
            invalid_cols = [c for c in columns if c not in allowed_cols]
            if invalid_cols:
                raise ValueError(f"Invalid columns requested: {invalid_cols}")
            cols = ", ".join(columns)
        else:
            cols = "*"

        placeholders = ",".join(["?"] * len(flow_ids))
        header_fn = _parse_headers_ordered if ordered_headers else _parse_headers
        redact_fn = _redact_headers_ordered if ordered_headers else _redact_headers

        with self._get_conn() as conn:
            conn.row_factory = sqlite3.Row
            # cols was validated against an allowlist above; ids are bound.
            query = "SELECT {} FROM flows WHERE id IN ({})".format(cols, placeholders)  # nosec B608
            cursor = conn.execute(query, flow_ids)
            rows = cursor.fetchall()
            row_keys = set(rows[0].keys()) if rows else set()
            results = []
            for row in rows:
                entry: Dict[str, Any] = {"id": row["id"]}

                req: Dict[str, Any] = {}
                if "url" in row_keys:
                    req["url"] = row["url"]
                if "method" in row_keys:
                    req["method"] = row["method"]
                if "request_headers" in row_keys and row["request_headers"]:
                    req["headers"] = redact_fn(header_fn(row["request_headers"]))
                if "request_body" in row_keys:
                    req["body"] = row["request_body"]
                if req:
                    entry["request"] = req

                if "status_code" in row_keys and row["status_code"] is not None:
                    resp: Dict[str, Any] = {"status_code": row["status_code"]}
                    if "response_headers" in row_keys and row["response_headers"]:
                        resp["headers"] = redact_fn(header_fn(row["response_headers"]))
                    if "response_body" in row_keys:
                        resp["body"] = row["response_body"]
                    entry["response"] = resp

                results.append(entry)
            return results

    IMPORT_PATH_ENV = "MITMPROXY_MCP_IMPORT_ROOT"
    MAX_IMPORT_BYTES = 256 * 1024 * 1024

    @staticmethod
    def resolve_import_path(file_path: str) -> Path:
        """Resolve and validate an import path.

        Containment uses path-component semantics (never a string prefix), the
        base directory is an explicit configured root (defaulting to the
        project root, not the process CWD), the extension is checked up front,
        and the file is opened with O_NOFOLLOW so a symlink cannot swap the
        target between validation and read.
        """
        base = Path(
            os.environ.get(
                TrafficDB.IMPORT_PATH_ENV,
                Path(__file__).resolve().parents[3],
            )
        ).resolve()
        candidate = Path(file_path).resolve()
        try:
            candidate.relative_to(base)
        except ValueError as err:
            raise PermissionError(
                f"path must be within the import root ({base})"
            ) from err
        if candidate.is_symlink():
            raise PermissionError("symlinked import paths are not allowed")
        if not candidate.exists():
            raise FileNotFoundError(f"file not found: {file_path}")
        if not candidate.is_file():
            raise ValueError(f"path is not a file: {file_path}")
        if candidate.suffix.lower() not in ALLOWED_IMPORT_EXTENSIONS:
            raise ValueError(
                f"unsupported file extension: {candidate.suffix or '(none)'}"
            )
        size = candidate.stat().st_size
        if size > TrafficDB.MAX_IMPORT_BYTES:
            raise ValueError(
                f"file exceeds the {TrafficDB.MAX_IMPORT_BYTES} byte import limit"
            )
        return candidate

    def import_from_file(
        self,
        file_path: str,
        append: bool = False,
        scope: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Import flows from a HAR or mitmproxy flow file.

        The whole file is parsed into memory first. Nothing is cleared until
        parsing succeeds, so a corrupt or truncated file can never destroy
        existing traffic.
        """
        resolved = self.resolve_import_path(file_path)

        stats = {"imported": 0, "skipped": 0, "errors": 0}

        # Open with O_NOFOLLOW and parse fully before touching the database.
        fd = os.open(resolved, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            reader = FlowReader(f)
            staged: List[http.HTTPFlow] = []
            for flow in reader.stream():
                try:
                    if not isinstance(flow, http.HTTPFlow):
                        stats["skipped"] += 1
                        continue
                    staged.append(flow)
                except Exception as e:
                    stats["errors"] += 1
                    print(f"Skipped flow during import: {e}", file=sys.stderr)

        # Parse succeeded: only now is it safe to replace existing traffic.
        if not append:
            self.clear()

        for flow in staged:
            try:
                if scope:
                    host = urlparse(flow.request.url).hostname or ""
                    if not host_in_scope(host, scope):
                        stats["skipped"] += 1
                        continue
                self.save_flow(flow)
                stats["imported"] += 1
            except Exception as e:
                stats["errors"] += 1
                print(f"Failed to store imported flow: {e}", file=sys.stderr)

        return stats

    def _generate_curl(self, request: SimpleRequest) -> str:
        try:
            cmd = ["curl", "-X", request.method]
            cmd.append(shlex.quote(request.url))

            for key, value in request.headers.items():
                if key.lower() in SENSITIVE_HEADERS:
                    value = REDACTED
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

            headers = _parse_headers(row["request_headers"])
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

    def get_live_flow(self, flow_id: str) -> Optional[http.HTTPFlow]:
        """Return a richer in-memory HTTPFlow when it is still buffered."""
        for flow in reversed(self.flows):
            if flow.id == flow_id:
                return flow
        return None

    def search(self, query: str, domain: str, method: str, limit: int):
        return self.db.search(query, domain, method, limit)

    def clear(self):
        self.db.clear()

    def get_all_for_analysis(
        self, limit: Optional[int] = None, lightweight: bool = False
    ) -> List[Dict[str, Any]]:
        return self.db.get_all_for_analysis(limit, lightweight=lightweight)

    def get_by_ids(
        self,
        flow_ids: List[str],
        columns: Optional[List[str]] = None,
        ordered_headers: bool = False,
    ) -> List[Dict[str, Any]]:
        return self.db.get_by_ids(flow_ids, columns=columns, ordered_headers=ordered_headers)
