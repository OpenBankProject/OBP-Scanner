# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The status page: what OBP-Scanner is doing, and what an administrator has to do for it. HTML at /, JSON at
/status.json. It shows ids and counts, never file content or names of what was scanned.

Also the probes, modelled on OBP-API: /alive and /health say the process answers HTTP and check nothing else; /status
checks what scanning needs (OBP-API and clamd), answers HTML or JSON depending on the Accept header, and answers 503
when a check fails."""

import html
import json
import logging
import threading
import time
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode, urlsplit

import httpx

from .config import Config
from .engines import ClamdEngine, EngineError
from .obp_client import scanner_version
from .scanner import Status

logger = logging.getLogger(__name__)

# How long each /status check may take, so a hung dependency cannot hang the probe
CHECK_TIMEOUT_SECONDS = 5.0


def status_json(config: Config, status: Status, api_manager: str | None) -> dict:
    with status.lock:
        last = asdict(status.last_pass) if status.last_pass else None
        return {
            "obp_base_url": config.obp_base_url,
            "bank_ids": config.bank_ids,
            "started_at": status.started_at,
            "consumer_id": status.consumer_id,
            "declaration": status.declaration,
            "scopes": status.scopes,
            "engine": status.engine,
            "totals": dict(status.totals),
            "last_pass": last,
            "platform_apps_url": (f"{api_manager}/consumers/platform-apps?"
                                  + urlencode({"consumer_id": status.consumer_id, "label": "OBP-Scanner"}))
            if api_manager and status.consumer_id else None,
        }


def render(data: dict) -> str:
    e = html.escape
    held = "".join(
        f"<li><code>{e(s.get('role_name', ''))}</code> at <code>{e(s.get('bank_id', ''))}</code>: "
        f"{'held' if s.get('held') else 'missing'}</li>" for s in data["scopes"])
    last = data["last_pass"]
    last_html = (f"{e(last['at'])}: {last['clean']} clean, {last['rejected']} rejected, "
                 f"{len(last['left_pending'])} left pending, {len(last['errors'])} errors"
                 + "".join(f"<br><small>{e(x)}</small>" for x in last["left_pending"] + last["errors"])
                 ) if last else "no pass yet"
    link = (f'<p><a href="{e(data["platform_apps_url"])}">Open Platform Apps in API Manager</a></p>'
            if data["platform_apps_url"] else "")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OBP-Scanner</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}
code{{background:#8881;padding:0 .2rem}}</style></head><body>
<h1>OBP-Scanner</h1>
<p>OBP-API: <code>{e(data["obp_base_url"])}</code> · spaces: {", ".join(f"<code>{e(b)}</code>" for b in data["bank_ids"])}</p>
<h2>Engine</h2><p>{e(data["engine"])}</p>
<h2>Platform App</h2>
<p>consumer_id: <code>{e(data["consumer_id"] or "unknown")}</code><br>Declaration: {e(data["declaration"])}</p>
<ul>{held}</ul>{link}
<h2>Scanning</h2><p>Last pass: {last_html}</p>
<p>Since {e(data["started_at"])}: {data["totals"]["clean"]} clean, {data["totals"]["rejected"]} rejected.</p>
</body></html>"""


def run_checks(config: Config) -> dict:
    """Check what scanning needs. Both are essential: without OBP-API there is nothing to scan, and without clamd every
    file stays pending."""
    try:
        # The API root needs no login, so this checks only that OBP-API is up and answering.
        response = httpx.get(f"{config.obp_base_url}/obp/v5.1.0/root", timeout=CHECK_TIMEOUT_SECONDS)
        obp_api = "ok" if response.status_code == 200 else "fail"
        if obp_api == "fail":
            logger.warning("Status check: OBP-API root answered %s", response.status_code)
    except httpx.HTTPError as e:
        logger.warning("Status check: OBP-API unreachable: %s", e)
        obp_api = "fail"
    try:
        ClamdEngine(config.clamd_host, config.clamd_port, CHECK_TIMEOUT_SECONDS).version()
        clamd = "ok"
    except EngineError as e:
        logger.warning("Status check: %s", e)
        clamd = "fail"
    return {"obp_api": obp_api, "clamd": clamd}


def readiness_json(status: Status, checks: dict, uptime_seconds: int) -> dict:
    all_ok = all(result == "ok" for result in checks.values())
    with status.lock:
        started_at = status.started_at
    return {
        "status": "ok" if all_ok else "degraded",
        "version": scanner_version() or "unknown",
        "started_at": started_at,
        "uptime_seconds": uptime_seconds,
        "checks": checks,
    }


def render_readiness(data: dict) -> str:
    e = html.escape
    rows = "".join(f"<tr><td>{e(name)}</td><td><strong>{e(result)}</strong></td></tr>"
                   for name, result in data["checks"].items())
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>OBP-Scanner - Status</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{{font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}
td{{padding:.2rem 1rem .2rem 0}}</style></head><body>
<h1>OBP-Scanner - Status: {e(data["status"])}</h1>
<p>Version {e(data["version"])} · started {e(data["started_at"])} · up {data["uptime_seconds"]} seconds</p>
<table>{rows}</table>
<p><a href="/">What the scanner is doing</a></p>
</body></html>"""


def prefers_json(accept_header: str | None) -> bool:
    """True when the Accept header lists application/json, as OBP-API's /status decides."""
    media_ranges = [part.split(";", 1)[0].strip().lower() for part in (accept_header or "").split(",")]
    return "application/json" in media_ranges


def serve(config: Config, status: Status, api_manager_url) -> ThreadingHTTPServer:
    """Start the page in a background thread. api_manager_url is called per request (it is cached by the caller)."""

    started_monotonic = time.monotonic()

    class Handler(BaseHTTPRequestHandler):
        def _send_probe(self, code: int, body: bytes, kind: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            # Probes must never be answered from a cache.
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            request_path = urlsplit(self.path).path
            if request_path == "/alive":
                self._send_probe(200, b"true", "application/json; charset=utf-8")
                return
            if request_path == "/status":
                checks = run_checks(config)
                data = readiness_json(status, checks, int(time.monotonic() - started_monotonic))
                code = 200 if data["status"] == "ok" else 503
                if prefers_json(self.headers.get("Accept")):
                    self._send_probe(code, json.dumps(data, indent=2).encode(), "application/json; charset=utf-8")
                else:
                    self._send_probe(code, render_readiness(data).encode(), "text/html; charset=utf-8")
                return
            data = status_json(config, status, api_manager_url())
            if self.path == "/status.json":
                body, kind = json.dumps(data, indent=2).encode(), "application/json"
            elif self.path in ("/", "/index.html"):
                body, kind = render(data).encode(), "text/html; charset=utf-8"
            elif self.path == "/health":
                body, kind = b'{"status":"ok"}', "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer((config.web_host, config.web_port), Handler)
    threading.Thread(target=server.serve_forever, name="web", daemon=True).start()
    return server
