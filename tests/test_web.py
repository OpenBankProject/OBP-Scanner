# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from obp_scanner.config import Config
from obp_scanner.scanner import PassResult, Status
from obp_scanner.web import prefers_json, render, serve, status_json

CONFIG = Config(obp_base_url="http://obp", oidc_issuer="http://oidc", oidc_client_id="id", oidc_client_secret="s",
                bank_ids=["cohort"])


def test_the_page_links_to_platform_apps_and_escapes_what_it_shows():
    status = Status(consumer_id="c1", declaration="declared", engine="<ClamAV>")
    status.last_pass = PassResult(at="2026-10-31T10:00:00Z", clean=2, rejected=1)
    data = status_json(CONFIG, status, "http://manager")
    assert data["platform_apps_url"] == "http://manager/consumers/platform-apps?consumer_id=c1&label=OBP-Scanner"
    page = render(data)
    assert "&lt;ClamAV&gt;" in page
    assert "2 clean, 1 rejected" in page


def _fake_obp_api() -> ThreadingHTTPServer:
    """An OBP-API that only answers its root."""
    class Root(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200 if self.path == "/obp/v5.1.0/root" else 404)
            self.end_headers()

        def log_message(self, *args):
            pass

    fake_server = ThreadingHTTPServer(("127.0.0.1", 0), Root)
    threading.Thread(target=fake_server.serve_forever, daemon=True).start()
    return fake_server


def _fake_clamd() -> socket.socket:
    """A clamd that answers VERSION, once per connection."""
    listener = socket.create_server(("127.0.0.1", 0))

    def answer():
        while True:
            try:
                connection, _ = listener.accept()
            except OSError:
                return
            with connection:
                connection.recv(64)
                connection.sendall(b"ClamAV 1.4.0\0")

    threading.Thread(target=answer, daemon=True).start()
    return listener


def _closed_port() -> int:
    with socket.create_server(("127.0.0.1", 0)) as probe_socket:
        return probe_socket.getsockname()[1]


def _scanner_page(obp_base_url: str, clamd_port: int) -> ThreadingHTTPServer:
    config = Config(obp_base_url=obp_base_url, oidc_issuer="http://oidc", oidc_client_id="id",
                    oidc_client_secret="s", bank_ids=["cohort"], clamd_host="127.0.0.1", clamd_port=clamd_port,
                    web_port=0)

    def no_api_manager():
        raise AssertionError("the probes must not look up the API Manager")

    return serve(config, Status(), no_api_manager)


def _get(page: ThreadingHTTPServer, path: str, accept: str | None = None) -> httpx.Response:
    headers = {"Accept": accept} if accept else {}
    return httpx.get(f"http://127.0.0.1:{page.server_address[1]}{path}", headers=headers)


def test_alive_answers_true_without_checking_anything():
    page = _scanner_page("http://127.0.0.1:1", _closed_port())
    try:
        response = _get(page, "/alive")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["cache-control"] == "no-store"
        assert response.text == "true"
    finally:
        page.shutdown()


def test_status_is_ok_when_obp_api_and_clamd_answer():
    fake_obp_api, fake_clamd = _fake_obp_api(), _fake_clamd()
    page = _scanner_page(f"http://127.0.0.1:{fake_obp_api.server_address[1]}", fake_clamd.getsockname()[1])
    try:
        response = _get(page, "/status", "application/json")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        assert body["status"] == "ok"
        assert body["checks"] == {"obp_api": "ok", "clamd": "ok"}
        html_response = _get(page, "/status", "text/html")
        assert html_response.status_code == 200
        assert html_response.headers["content-type"].startswith("text/html")
    finally:
        page.shutdown()
        fake_obp_api.shutdown()
        fake_clamd.close()


def test_status_is_503_when_clamd_is_unreachable():
    fake_obp_api = _fake_obp_api()
    page = _scanner_page(f"http://127.0.0.1:{fake_obp_api.server_address[1]}", _closed_port())
    try:
        response = _get(page, "/status", "application/json")
        assert response.status_code == 503
        assert response.json()["status"] == "degraded"
        assert response.json()["checks"] == {"obp_api": "ok", "clamd": "fail"}
        assert _get(page, "/status").status_code == 503
    finally:
        page.shutdown()
        fake_obp_api.shutdown()


def test_json_is_preferred_only_when_the_accept_header_lists_it():
    assert prefers_json("application/json")
    assert prefers_json("text/html, application/json;q=0.9")
    assert not prefers_json("text/html,*/*")
    assert not prefers_json(None)
