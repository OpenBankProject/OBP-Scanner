# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The status page: what OBP-Scanner is doing, and what an administrator has to do for it. HTML at /, JSON at
/status.json. It shows ids and counts, never file content or names of what was scanned."""

import html
import json
import threading
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlencode

from .config import Config
from .scanner import Status


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


def serve(config: Config, status: Status, api_manager_url) -> ThreadingHTTPServer:
    """Start the page in a background thread. api_manager_url is called per request (it is cached by the caller)."""

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
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
