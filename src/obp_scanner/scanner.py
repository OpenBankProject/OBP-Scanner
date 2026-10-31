# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""One scanning pass, and the loop that repeats it. A file is called clean only when the engine says so; any error
leaves it pending for the next pass, so an unreachable scanner never lets a file through."""

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from .config import Config
from .engines import EngineError
from .obp_client import NOT_MARKED, OBPClient, OBPError

logger = logging.getLogger(__name__)

REDECLARE_SECONDS = 3600


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class PassResult:
    at: str
    clean: int = 0
    rejected: int = 0
    # Files left pending because they could not be read or scanned, with why
    left_pending: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class Status:
    """What the status page shows. Shared between the loop and the web thread."""
    started_at: str = field(default_factory=_now)
    consumer_id: str | None = None
    declaration: str = "not yet declared"
    scopes: list[dict] = field(default_factory=list)
    engine: str = "unknown"
    last_pass: PassResult | None = None
    totals: dict = field(default_factory=lambda: {"clean": 0, "rejected": 0})
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False)


class Scanner:
    def __init__(self, config: Config, client: OBPClient, engine, status: Status | None = None):
        self.config, self.client, self.engine = config, client, engine
        self.status = status or Status()
        self._declared_at = 0.0

    def declare(self) -> None:
        """Declare the Scopes every pass until all are held (so a grant shows soon), then hourly."""
        with self.status.lock:
            all_held = bool(self.status.scopes) and all(s.get("held") for s in self.status.scopes)
        if all_held and time.monotonic() - self._declared_at < REDECLARE_SECONDS:
            return
        try:
            # Kept even if the declaration fails: the page needs it for the link that marks this Consumer.
            consumer_id = self.client.current_consumer_id()
            with self.status.lock:
                self.status.consumer_id = consumer_id
            answer = self.client.declare_platform_app()
            scopes = answer.get("required_scopes", [])
            with self.status.lock:
                self.status.declaration = "declared"
                self.status.scopes = scopes
            self._declared_at = time.monotonic()
        except OBPError as e:
            text = ("not marked: an administrator marks this Consumer as a Platform App in the API Manager"
                    if NOT_MARKED in str(e) else f"declaration failed: {e}")
            with self.status.lock:
                self.status.declaration = text
            logger.warning("Platform App declaration: %s", text)

    def run_once(self) -> PassResult:
        result = PassResult(at=_now())
        try:
            engine = self.engine.version()
        except EngineError as e:
            engine = f"unreachable: {e}"
        with self.status.lock:
            self.status.engine = engine
        self.declare()
        for bank_id in self.config.bank_ids:
            try:
                files = self.client.pending_files(bank_id, self.config.batch_size)
            except OBPError as e:
                result.errors.append(f"{bank_id}: {e}")
                continue
            for f in files:
                self._scan_one(bank_id, f, result)
        with self.status.lock:
            self.status.last_pass = result
            self.status.totals["clean"] += result.clean
            self.status.totals["rejected"] += result.rejected
        if result.clean or result.rejected or result.left_pending or result.errors:
            logger.info("Pass: %s clean, %s rejected, %s left pending, %s errors",
                        result.clean, result.rejected, len(result.left_pending), len(result.errors))
        return result

    def _scan_one(self, bank_id: str, f: dict, result: PassResult) -> None:
        file_id = f.get("file_id", "")
        try:
            data = self.client.file_content(bank_id, file_id)
            verdict = self.engine.scan(data)
        except (OBPError, EngineError) as e:
            result.left_pending.append(f"{bank_id}/{file_id}: {e}")
            return
        try:
            self.client.set_scan_status(bank_id, file_id, "clean" if verdict.clean else "rejected", verdict.detail)
        except OBPError as e:
            result.left_pending.append(f"{bank_id}/{file_id}: could not record the result: {e}")
            return
        if verdict.clean:
            result.clean += 1
        else:
            result.rejected += 1
            logger.warning("Rejected %s/%s (%s): %s", bank_id, file_id, f.get("file_name", ""), verdict.detail)

    def run_forever(self, stop: threading.Event | None = None) -> None:
        stop = stop or threading.Event()
        while not stop.is_set():
            try:
                self.run_once()
            except Exception:
                logger.exception("Scanning pass failed")
            stop.wait(self.config.poll_seconds)
