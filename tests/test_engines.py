# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
import socketserver
import struct
import threading

import pytest

from obp_scanner.engines import ClamdEngine, EngineError

EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


class FakeClamd(socketserver.BaseRequestHandler):
    """Speaks enough of clamd: VERSION, and INSTREAM, finding the EICAR test string."""

    def handle(self):
        command = b""
        while not command.endswith(b"\0"):
            command += self.request.recv(1)
        if command == b"zVERSION\0":
            self.request.sendall(b"ClamAV 1.4.1/27420\0")
            return
        data = b""
        while True:
            size = struct.unpack("!L", self._read(4))[0]
            if size == 0:
                break
            data += self._read(size)
        self.request.sendall(b"stream: Eicar-Signature FOUND\0" if EICAR in data else b"stream: OK\0")

    def _read(self, n):
        buf = b""
        while len(buf) < n:
            buf += self.request.recv(n - len(buf))
        return buf


@pytest.fixture
def clamd():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), FakeClamd)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield ClamdEngine("127.0.0.1", server.server_address[1], timeout_seconds=5)
    server.shutdown()
    server.server_close()


def test_a_clean_file_is_clean(clamd):
    verdict = clamd.scan(b"%PDF-1.7 a pitch deck" * 10_000)  # several chunks
    assert verdict.clean
    assert "ClamAV 1.4.1" in verdict.detail


def test_the_eicar_test_file_is_found(clamd):
    verdict = clamd.scan(EICAR)
    assert not verdict.clean
    assert verdict.detail == "ClamAV: Eicar-Signature"


def test_an_unreachable_clamd_is_an_error_not_a_verdict():
    with pytest.raises(EngineError):
        ClamdEngine("127.0.0.1", 1, timeout_seconds=1).scan(b"anything")
