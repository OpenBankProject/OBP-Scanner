#!/bin/bash
# Copyright (C) 2026 TESOBE GmbH
# SPDX-License-Identifier: AGPL-3.0-or-later
# Start ClamAV's daemon (clamd) for OBP-Scanner, from docker-compose.yml, without waiting for it.
# The first start downloads the image and the virus database, so clamd answers on :3310 only after a few minutes;
# until then OBP-Scanner leaves files pending and its status page says the engine is unreachable.
# Running it again while ClamAV is up does nothing.
set -e
cd "$(dirname "$0")"
docker compose up -d clamav
echo "ClamAV container started; clamd answers on 127.0.0.1:3310 once its virus database is loaded."
