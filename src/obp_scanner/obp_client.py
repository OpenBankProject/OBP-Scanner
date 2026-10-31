# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The OBP-API calls OBP-Scanner makes, as a Platform App with its own application token (OAuth2 client credentials):
its Scope declaration, the files waiting to be scanned, their content, and the scan results."""

import logging
import time
from importlib.metadata import PackageNotFoundError, version
from urllib.parse import quote

import httpx

from .config import Config

logger = logging.getLogger(__name__)

API_VERSION = "v7.0.0"
# Renew the token this many seconds before it expires
TOKEN_MARGIN_SECONDS = 30
# OBP-API's answer to a declaration from a Consumer an administrator has not marked as a Platform App
NOT_MARKED = "OBP-35046"


class OBPError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def required_scopes(config: Config) -> list[dict]:
    """The Scopes OBP-Scanner needs, in the form PUT /consumers/current/platform-app takes: one per space it scans."""
    return [
        {
            "role_name": "CanUpdateFileScanStatusAtOneBank",
            "bank_id": bank_id,
            "needed_for": "Reading the files waiting to be scanned and recording whether each is clean or rejected",
            "optional": False,
        }
        for bank_id in config.bank_ids
    ]


def scanner_version() -> str | None:
    try:
        return version("obp-scanner")
    except PackageNotFoundError:
        return None


class OBPClient:
    def __init__(self, config: Config, http: httpx.Client | None = None):
        self.config = config
        self.http = http or httpx.Client(timeout=60)
        self._token: str | None = None
        self._token_expires_at = 0.0
        self._token_endpoint: str | None = None

    def _send(self, method: str, url: str, **kwargs) -> httpx.Response:
        try:
            return self.http.request(method, url, **kwargs)
        except httpx.HTTPError as e:
            raise OBPError(f"{method} {url} failed: {e}") from e

    def _fetch_token(self) -> str:
        c = self.config
        if not (c.oidc_issuer and c.oidc_client_id and c.oidc_client_secret):
            raise OBPError("OIDC_ISSUER, OIDC_CLIENT_ID and OIDC_CLIENT_SECRET must be set")
        if not self._token_endpoint:
            url = f"{c.oidc_issuer}/.well-known/openid-configuration"
            response = self._send("GET", url)
            if response.status_code != 200:
                raise OBPError(f"OIDC discovery at {url} failed ({response.status_code}): {response.text[:300]}")
            self._token_endpoint = response.json()["token_endpoint"]
        response = self._send("POST", self._token_endpoint,
                              data={"grant_type": "client_credentials", "scope": "openid"},
                              auth=(c.oidc_client_id, c.oidc_client_secret))
        if response.status_code != 200:
            raise OBPError(f"Client credentials token request failed ({response.status_code}): {response.text[:300]}")
        body = response.json()
        self._token = body["access_token"]
        self._token_expires_at = time.monotonic() + float(body.get("expires_in", 300)) - TOKEN_MARGIN_SECONDS
        return self._token

    def _token_now(self) -> str:
        if self._token and time.monotonic() < self._token_expires_at:
            return self._token
        return self._fetch_token()

    def _call(self, method: str, path: str, **kwargs) -> httpx.Response:
        url = f"{self.config.obp_base_url}/obp/{API_VERSION}/{path}"
        for attempt in range(2):
            response = self._send(method, url, headers={"Authorization": f"Bearer {self._token_now()}"}, **kwargs)
            if response.status_code == 401 and attempt == 0:
                self._token = None  # expired or revoked: get a new one once
                continue
            if response.status_code >= 400:
                raise OBPError(f"{method} {url} failed ({response.status_code}): {response.text[:300]}", response.status_code)
            return response
        raise OBPError(f"{method} {url} failed after getting a new token")

    def current_consumer_id(self) -> str:
        return self._call("GET", "consumers/current/identity").json()["consumer_id"]

    def declare_platform_app(self) -> dict:
        """Tell OBP-API which Scopes OBP-Scanner needs; the answer says which are held."""
        body = {"required_scopes": required_scopes(self.config)}
        if v := scanner_version():
            body["version"] = v
        return self._call("PUT", "consumers/current/platform-app", json=body).json()

    def pending_files(self, bank_id: str, limit: int) -> list[dict]:
        response = self._call("GET", f"management/banks/{quote(bank_id, safe='')}/files",
                              params={"scan_status": "pending", "limit": str(limit)})
        return response.json().get("files", [])

    def file_content(self, bank_id: str, file_id: str) -> bytes:
        return self._call("GET", f"banks/{quote(bank_id, safe='')}/files/{quote(file_id, safe='')}/content").content

    def set_scan_status(self, bank_id: str, file_id: str, status: str, reason: str) -> dict:
        return self._call("PUT", f"banks/{quote(bank_id, safe='')}/files/{quote(file_id, safe='')}/scan-status",
                          json={"scan_status": status, "reason": reason[:1000]}).json()

    def api_manager_url(self) -> str | None:
        """The API Manager, from OBP-API's public app directory, for the link to its Platform Apps page."""
        try:
            response = self.http.get(f"{self.config.obp_base_url}/obp/v6.0.0/app-directory", timeout=10)
            response.raise_for_status()
            entries = {e.get("name"): e.get("value") for e in response.json().get("app_directory", [])}
            url = entries.get("public_obp_api_manager_url")
            return url.rstrip("/") if url else None
        except Exception:
            return None
