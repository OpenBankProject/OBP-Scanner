# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
from obp_scanner.config import Config
from obp_scanner.scanner import PassResult, Status
from obp_scanner.web import render, status_json

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
