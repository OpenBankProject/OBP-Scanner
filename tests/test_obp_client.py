# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
import json

import httpx

from obp_scanner.config import Config
from obp_scanner.obp_client import OBPClient, required_scopes

CONFIG = Config(obp_base_url="http://obp", oidc_issuer="http://oidc", oidc_client_id="id", oidc_client_secret="s",
                bank_ids=["cohort", "SYS"])


def client(handler):
    return OBPClient(CONFIG, httpx.Client(transport=httpx.MockTransport(handler)))


def test_one_scope_per_space():
    assert [(s["role_name"], s["bank_id"]) for s in required_scopes(CONFIG)] == [
        ("CanUpdateFileScanStatusAtOneBank", "cohort"), ("CanUpdateFileScanStatusAtOneBank", "SYS")]


def test_it_lists_pending_files_and_records_a_result_with_its_own_token():
    seen = []

    def handler(request: httpx.Request):
        seen.append((request.method, request.url.path, dict(request.url.params), request.headers.get("authorization")))
        if request.url.path == "/.well-known/openid-configuration":
            return httpx.Response(200, json={"token_endpoint": "http://oidc/token"})
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "app-token", "expires_in": 300})
        if request.method == "GET":
            return httpx.Response(200, json={"files": [{"file_id": "f1"}]})
        return httpx.Response(200, json=json.loads(request.content))

    c = client(handler)
    assert c.pending_files("cohort", 50) == [{"file_id": "f1"}]
    c.set_scan_status("cohort", "f1", "rejected", "ClamAV: Eicar-Signature")
    calls = [s for s in seen if s[1].startswith("/obp")]
    assert calls[0][:3] == ("GET", "/obp/v7.0.0/management/banks/cohort/files", {"scan_status": "pending", "limit": "50"})
    assert calls[1][:2] == ("PUT", "/obp/v7.0.0/banks/cohort/files/f1/scan-status")
    assert all(s[3] == "Bearer app-token" for s in calls)
