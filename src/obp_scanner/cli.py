# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The `scanner` command: `scanner run` (scan forever, with the status page), `scanner once` (one pass) and
`scanner check` (settings, token, engine and Platform App declaration, without scanning)."""

import argparse
import json
import logging
import sys
import time

from .config import Config, ConfigError
from .engines import ClamdEngine, EngineError
from .obp_client import OBPClient, OBPError
from .scanner import Scanner
from .web import serve


def _parts(config: Config):
    client = OBPClient(config)
    engine = ClamdEngine(config.clamd_host, config.clamd_port, config.clamd_timeout_seconds)
    return client, engine, Scanner(config, client, engine)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="scanner", description="OBP-Scanner")
    parser.add_argument("command", choices=["run", "once", "check"])
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    try:
        config = Config.from_env()
    except ConfigError as e:
        print(f"Settings: {e}", file=sys.stderr)
        return 2
    client, engine, scanner = _parts(config)

    if args.command == "check":
        try:
            print("engine:", engine.version())
        except EngineError as e:
            print("engine: unreachable:", e)
        try:
            print("consumer_id:", client.current_consumer_id())
        except OBPError as e:
            print("OBP-API:", e)
            return 1
        scanner.declare()
        print("declaration:", scanner.status.declaration)
        print(json.dumps(scanner.status.scopes, indent=2))
        return 0

    if args.command == "once":
        result = scanner.run_once()
        print(json.dumps(result.__dict__, indent=2))
        return 0

    cached = {"at": 0.0, "url": None}

    def api_manager_url():
        if time.monotonic() - cached["at"] > 300:
            cached["url"], cached["at"] = client.api_manager_url(), time.monotonic()
        return cached["url"]

    serve(config, scanner.status, api_manager_url)
    logging.getLogger(__name__).info("Status page on http://%s:%s", config.web_host, config.web_port)
    try:
        scanner.run_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
