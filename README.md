# OBP-Scanner

A Platform App that does OBP-API's background work. Today it virus scans the files waiting to be checked: OBP-API
stores personal files (and, if configured, others) with `scan_status` pending and serves their content only once they
are clean. OBP-Scanner finds them, scans them with ClamAV, and records the result. It is the place for more work of
that kind later: anything that looks for things to do in OBP-API and does them, outside the request path.

## How it works

Every `SCANNER_POLL_SECONDS`, for each space in `SCANNER_BANK_IDS`:

1. `GET /obp/v7.0.0/management/banks/BANK_ID/files?scan_status=pending` lists the waiting files.
2. `GET /obp/v7.0.0/banks/BANK_ID/files/FILE_ID/content` reads each one.
3. ClamAV's daemon scans it (`clamd`, INSTREAM over TCP).
4. `PUT /obp/v7.0.0/banks/BANK_ID/files/FILE_ID/scan-status` records `clean` or `rejected`, with ClamAV's verdict as
   the reason.

A file is marked clean only when ClamAV says so. If clamd is unreachable, or a file cannot be read or its result
cannot be recorded, the file stays pending and is tried again on the next pass. OBP-Scanner never sees a file it may
not: the Role it holds, CanUpdateFileScanStatusAtOneBank, lets it read only files that are not yet clean.

## Setup

1. OBP-OIDC client: create `obp-scanner` (client credentials). In the TESOBE dev setup
   `/srv/work/workspace_2026/commands/_helpers/sync_obp_consumers.sh` does it and writes `.env`.
2. Copy `.env.example` to `.env` and set `SCANNER_BANK_IDS`.
3. Start ClamAV: `./start_clamav.sh` (`docker compose up -d clamav`; the first start downloads the virus database).
   clamd keeps the database in memory, about 1 to 1.5 GB, whether or not there are files to scan.
4. `uv run scanner check` shows the engine, the consumer_id and the Platform App declaration.
5. In the API Manager, mark the Consumer as a Platform App and grant the declared Scopes; the status page links there.
6. `uv run scanner run` scans forever and serves the status page on http://127.0.0.1:8767 (`/status.json` as JSON).

`uv run scanner once` runs one pass and prints what it did. Tests: `uv run pytest`.

## Licence

Copyright (C) 2026, TESOBE GmbH. Licensed under the GNU Affero General Public License v3.0 or later;
see [LICENSE](LICENSE) and [NOTICE](NOTICE).
