# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Virus scanning engines. Each one takes a file's bytes and returns a Verdict; an engine that cannot decide raises
EngineError, and the file then stays pending. ClamAV is reached through clamd; an ICAP engine, for an installation's
own antivirus, would be another class here."""

import socket
import struct
from dataclasses import dataclass


class EngineError(Exception):
    """The engine could not scan: the file must stay pending, never be called clean."""


@dataclass(frozen=True)
class Verdict:
    clean: bool
    # What the engine said, recorded as the file's scan_status_reason
    detail: str


class ClamdEngine:
    """ClamAV's daemon over TCP, using its INSTREAM command: the bytes go in chunks, each prefixed by its length."""

    CHUNK = 64 * 1024

    def __init__(self, host: str, port: int, timeout_seconds: float = 60.0):
        self.host, self.port, self.timeout = host, port, timeout_seconds

    def _command(self, command: bytes, payload: bytes | None = None) -> str:
        try:
            with socket.create_connection((self.host, self.port), timeout=self.timeout) as s:
                s.sendall(b"z" + command + b"\0")
                if payload is not None:
                    for i in range(0, len(payload), self.CHUNK):
                        chunk = payload[i:i + self.CHUNK]
                        s.sendall(struct.pack("!L", len(chunk)) + chunk)
                    s.sendall(struct.pack("!L", 0))
                reply = b""
                while not reply.endswith(b"\0"):
                    data = s.recv(4096)
                    if not data:
                        break
                    reply += data
        except OSError as e:
            raise EngineError(f"clamd at {self.host}:{self.port}: {e}") from e
        return reply.rstrip(b"\0").decode("utf-8", "replace").strip()

    def version(self) -> str:
        return self._command(b"VERSION")

    def scan(self, data: bytes) -> Verdict:
        reply = self._command(b"INSTREAM", data)
        # "stream: OK", "stream: Eicar-Signature FOUND", or "... ERROR" (e.g. the file is over StreamMaxLength)
        result = reply.split(":", 1)[-1].strip()
        if result == "OK":
            return Verdict(True, f"ClamAV: no threats found ({self.version()})")
        if result.endswith("FOUND"):
            return Verdict(False, f"ClamAV: {result[:-len('FOUND')].strip()}")
        raise EngineError(f"clamd could not scan the file: {reply}")
