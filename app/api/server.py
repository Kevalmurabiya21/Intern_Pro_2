"""
Phase 6: REST API.

Endpoints (all return JSON):
  GET  /health     - liveness check
  GET  /status     - current threat score/band + monitor stats
  GET  /alerts     - recent alerts
  GET  /events     - recent file events
  GET  /reports    - list of generated report files
  POST /scan       - trigger an on-demand process snapshot
  POST /settings   - view current settings (read-only in this build)

Implementation note: built on Python's stdlib `http.server` rather than
FastAPI, since this sandbox has no internet access to install it. The route
table, handlers, and JSON responses are structured the same way a FastAPI
app would be, so porting to FastAPI later is mostly moving each handler
into an `@app.get(...)` / `@app.post(...)` decorator - see README.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from app.core.config import Settings
from app.core.logging_setup import get_logger
from app.database import db
from app.detectors.process_monitor import snapshot_processes

_log = get_logger("system")

# Populated by main.py at startup so handlers can reach live objects.
_shared_state = {
    "engine": None,       # DetectionEngine instance
    "monitor": None,      # FileMonitor instance
    "settings": None,     # Settings instance
    "start_time": None,
}


def configure(engine, monitor, settings: Settings) -> None:
    _shared_state["engine"] = engine
    _shared_state["monitor"] = monitor
    _shared_state["settings"] = settings
    _shared_state["start_time"] = datetime.now(timezone.utc)


def _json_default(o):
    if isinstance(o, datetime):
        return o.isoformat()
    return str(o)


class _Handler(BaseHTTPRequestHandler):
    server_version = "RDRS/1.0"

    def log_message(self, fmt, *args):
        _log.info("API " + (fmt % args))

    def _send_json(self, payload, status: int = 200):
        body = json.dumps(payload, default=_json_default, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    # -- routing ------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)

        if path == "/health":
            self._send_json({"status": "ok"})
        elif path == "/status":
            self._handle_status()
        elif path == "/alerts":
            limit = int(query.get("limit", [50])[0])
            self._send_json({"alerts": db.recent_alerts(limit)})
        elif path == "/events":
            limit = int(query.get("limit", [50])[0])
            self._send_json({"events": db.recent_events(limit)})
        elif path == "/incidents":
            limit = int(query.get("limit", [50])[0])
            self._send_json({"incidents": db.recent_incidents(limit)})
        elif path == "/reports":
            self._handle_reports_list()
        elif path in ("/dashboard", "/dashboard/"):
            self._serve_dashboard()
        elif path == "/":
            self._send_json({
                "service": "RDRS API",
                "endpoints": ["/health", "/status", "/alerts", "/events",
                              "/incidents", "/reports", "POST /scan", "POST /settings"],
            })
        else:
            self._send_json({"error": "not found", "path": path}, status=404)

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/scan":
            self._handle_scan()
        elif path == "/settings":
            self._handle_settings_post()
        else:
            self._send_json({"error": "not found", "path": path}, status=404)

    # -- handlers -------------------------------------------------------
    def _handle_status(self):
        engine = _shared_state["engine"]
        monitor = _shared_state["monitor"]
        start_time = _shared_state["start_time"]

        score = engine.last_score if engine else None
        state = engine.last_state if engine else None

        payload = {
            "uptime_seconds": (datetime.now(timezone.utc) - start_time).total_seconds() if start_time else None,
            "threat_score": score.score if score else 0,
            "threat_band": score.band if score else "Normal",
            "fired_signals": score.fired_signals if score else [],
            "event_count": monitor.event_count if monitor else 0,
            "db_counts": db.counts(),
            "signals": {
                "files_modified_per_minute": round(state.files_modified_per_minute, 2) if state else 0,
                "renames_per_minute": round(state.renames_per_minute, 2) if state else 0,
                "extension_changes_per_minute": round(state.extension_changes_per_minute, 2) if state else 0,
                "avg_entropy": round(state.avg_entropy, 2) if state else 0,
                "max_cpu_percent": state.max_cpu_percent if state else 0,
            } if state else {},
        }
        self._send_json(payload)

    def _serve_dashboard(self):
        html_path = Path(__file__).resolve().parent.parent / "dashboard" / "static" / "index.html"
        try:
            body = html_path.read_bytes()
        except FileNotFoundError:
            self._send_json({"error": "dashboard not found"}, status=404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_reports_list(self):
        reports_dir = Path("data/reports")
        files = []
        if reports_dir.exists():
            files = sorted(str(p) for p in reports_dir.glob("*") if p.is_file())
        self._send_json({"reports": files})

    def _handle_scan(self):
        procs = snapshot_processes(top_n_by_cpu=10)
        self._send_json({
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "top_processes": [
                {"pid": p.pid, "name": p.name, "cpu_percent": p.cpu_percent,
                 "memory_rss_bytes": p.memory_rss_bytes}
                for p in procs
            ],
        })

    def _handle_settings_post(self):
        # This build treats /settings as read-only: it echoes the current
        # config rather than mutating it live, to keep the demo simple and
        # safe. A real deployment could validate + hot-reload config.yaml here.
        body = self._read_json_body()
        settings = _shared_state["settings"]
        self._send_json({
            "message": "Settings are read-only in this build. Edit config.yaml and restart.",
            "received": body,
            "current": {
                "simulation_mode": settings.response.simulation_mode if settings else None,
                "window_seconds": settings.detection.window_seconds if settings else None,
            },
        })


def run_server(host: str, port: int) -> ThreadingHTTPServer:
    """Start the API server on a background thread and return the server
    object so callers can shut it down later."""
    httpd = ThreadingHTTPServer((host, port), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    _log.info(f"API listening on http://{host}:{port}  (try /health, /status, /alerts)")
    return httpd
