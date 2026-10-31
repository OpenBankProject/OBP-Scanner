# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
from obp_scanner.config import Config
from obp_scanner.engines import EngineError, Verdict
from obp_scanner.obp_client import OBPError
from obp_scanner.scanner import Scanner

CONFIG = Config(obp_base_url="http://obp", oidc_issuer="http://oidc", oidc_client_id="id", oidc_client_secret="s",
                bank_ids=["cohort"])


class FakeClient:
    def __init__(self, files, contents, declare_error=None):
        self.files, self.contents, self.declare_error = files, contents, declare_error
        self.results = {}

    def current_consumer_id(self):
        return "c1"

    def declare_platform_app(self):
        if self.declare_error:
            raise OBPError(self.declare_error)
        return {"required_scopes": [{"role_name": "CanUpdateFileScanStatusAtOneBank", "bank_id": "cohort", "held": True}]}

    def pending_files(self, bank_id, limit):
        return self.files

    def file_content(self, bank_id, file_id):
        if file_id not in self.contents:
            raise OBPError("403")
        return self.contents[file_id]

    def set_scan_status(self, bank_id, file_id, status, reason):
        self.results[file_id] = (status, reason)
        return {}


class FakeEngine:
    def __init__(self, broken=False):
        self.broken = broken

    def version(self):
        if self.broken:
            raise EngineError("down")
        return "ClamAV test"

    def scan(self, data):
        if self.broken:
            raise EngineError("down")
        return Verdict(False, "ClamAV: Eicar-Signature") if b"EICAR" in data else Verdict(True, "ClamAV: no threats found")


def test_each_pending_file_is_marked_clean_or_rejected():
    client = FakeClient([{"file_id": "a"}, {"file_id": "b"}], {"a": b"fine", "b": b"EICAR"})
    result = Scanner(CONFIG, client, FakeEngine()).run_once()
    assert client.results == {"a": ("clean", "ClamAV: no threats found"), "b": ("rejected", "ClamAV: Eicar-Signature")}
    assert (result.clean, result.rejected) == (1, 1)


def test_nothing_is_marked_when_the_engine_cannot_scan():
    client = FakeClient([{"file_id": "a"}], {"a": b"fine"})
    scanner = Scanner(CONFIG, client, FakeEngine(broken=True))
    result = scanner.run_once()
    assert client.results == {}
    assert len(result.left_pending) == 1
    assert scanner.status.engine.startswith("unreachable")


def test_a_file_that_cannot_be_read_stays_pending():
    client = FakeClient([{"file_id": "missing"}], {})
    result = Scanner(CONFIG, client, FakeEngine()).run_once()
    assert client.results == {}
    assert result.left_pending and result.left_pending[0].startswith("cohort/missing")


def test_an_unmarked_consumer_is_reported():
    client = FakeClient([], {}, declare_error="404 OBP-35046 not a platform app")
    scanner = Scanner(CONFIG, client, FakeEngine())
    scanner.run_once()
    assert scanner.status.declaration.startswith("not marked")
    assert scanner.status.consumer_id is not None  # so the page can link to Platform Apps to mark it
