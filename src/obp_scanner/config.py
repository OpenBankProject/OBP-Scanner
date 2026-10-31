# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Settings, from the environment (and .env). See .env.example."""

import os
from dataclasses import dataclass, field

from dotenv import load_dotenv


class ConfigError(Exception):
    pass


def _list(value: str | None) -> list[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


@dataclass(frozen=True)
class Config:
    obp_base_url: str
    oidc_issuer: str
    oidc_client_id: str
    oidc_client_secret: str
    # The spaces whose files are scanned: bank ids, or SYS for the system space
    bank_ids: list[str] = field(default_factory=list)
    poll_seconds: int = 30
    # The most files handled per space in one pass
    batch_size: int = 50
    clamd_host: str = "localhost"
    clamd_port: int = 3310
    clamd_timeout_seconds: float = 60.0
    web_host: str = "127.0.0.1"
    web_port: int = 8767

    @classmethod
    def from_env(cls, env_file: str | None = ".env") -> "Config":
        if env_file:
            load_dotenv(env_file, override=False)
        e = os.environ
        config = cls(
            obp_base_url=e.get("OBP_BASE_URL", "http://localhost:8080").rstrip("/"),
            oidc_issuer=e.get("OIDC_ISSUER", "http://localhost:9000/obp-oidc").rstrip("/"),
            oidc_client_id=e.get("OIDC_CLIENT_ID", ""),
            oidc_client_secret=e.get("OIDC_CLIENT_SECRET", ""),
            bank_ids=_list(e.get("SCANNER_BANK_IDS")),
            poll_seconds=int(e.get("SCANNER_POLL_SECONDS", "30")),
            batch_size=int(e.get("SCANNER_BATCH_SIZE", "50")),
            clamd_host=e.get("CLAMD_HOST", "localhost"),
            clamd_port=int(e.get("CLAMD_PORT", "3310")),
            clamd_timeout_seconds=float(e.get("CLAMD_TIMEOUT_SECONDS", "60")),
            web_host=e.get("SCANNER_WEB_HOST", "127.0.0.1"),
            web_port=int(e.get("SCANNER_WEB_PORT", "8767")),
        )
        if not config.bank_ids:
            raise ConfigError("SCANNER_BANK_IDS must name at least one space (a bank id, or SYS)")
        return config
