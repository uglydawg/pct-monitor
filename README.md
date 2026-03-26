# PCT API Evidence Monitor

**Case No. 494-07423-2025 — Closed Circuit, Inc. and SOC, LLC v. Parler Cloud Technologies, LLC**

Single-file Python script. No dependencies beyond the standard library.

## Setup

```bash
python3 monitor.py
```

Then open http://localhost:8080 in your browser.

## OAuth Setup (for authenticated endpoints)

### Getting the token from your browser

1. Log in to **app.parler.com** in Chrome/Edge/Firefox
2. Open Developer Tools (`F12` or `Ctrl+Shift+I`)
3. Go to the **Application** tab (Chrome/Edge) or **Storage** tab (Firefox)
4. In the left sidebar, expand **Local Storage** and click on `https://app.parler.com`
5. Find the key that stores your session (look for a JSON value containing `accessToken` and `refreshToken`)
6. Copy the full JSON value
7. Save it as `credentials.json` in the same directory as `monitor.py`

The file should look like this (the monitor accepts both camelCase and snake_case keys):

```json
{
  "accessToken": "eyJ0eXAiOiJKV1...",
  "refreshToken": "def50200a1b2c3..."
}
```

### Token management

- If `credentials.json` is missing, the monitor runs **public endpoints only**
- On a `401` response, the monitor automatically refreshes the access token using the refresh token
- Updated tokens are saved back to `credentials.json`
- Token refresh events are logged in the database for audit trail
- Use the "Refresh Token" button in the web UI to manually trigger a refresh
- If the refresh token also expires, repeat the browser extraction steps above

## What it does

- Hits Parler API endpoints at 9:00 AM PT and 6:00 PM PT daily
- Stores every request + response in a local SQLite database (`evidence.db`)
- SHA-256 hashes every response for tamper-evident record
- **Schema fingerprinting** — extracts the structural shape of each JSON response and scores CC platform field coverage
- **Blockchain timestamping** — submits capture hashes to OriginStamp for independent tamper-proof attestation (optional)
- Web UI to browse and view all captures, filterable by public/authenticated
- Click any capture to see full request/response detail with schema analysis

## Schema Fingerprinting

Each JSON response is analyzed to extract:

- **Field paths** — all dot-notation key paths in the response structure
- **Schema hash** — SHA-256 of the sorted field paths (proves the structure, independent of data values)
- **CC fingerprint score** — percentage of known Closed Circuit field names present (e.g., `userUlid`, `userEngagement`, `hasReposted`)
- **ULID field count** — number of fields containing values matching the Crockford Base32 ULID pattern

This creates a structural fingerprint that proves the API responses use CC's proprietary data model, regardless of the actual data values returned.

## Blockchain Timestamping (OriginStamp)

Optional integration with [OriginStamp](https://originstamp.com) for blockchain-based timestamp attestation.

### Setup

Set the `ORIGINSTAMP_API_KEY` environment variable:

```bash
ORIGINSTAMP_API_KEY=your-api-key-here python3 monitor.py
```

Free tier provides 200 timestamps/month (sufficient for 2x/day captures).

### How it works

- After each capture, the response SHA-256 hash is submitted to OriginStamp
- The schema hash is also submitted as a separate timestamp
- OriginStamp anchors these hashes to Bitcoin, Ethereum, and other blockchains
- This provides an independent, third-party proof that the capture existed at a specific time
- Results are stored in the `blockchain_stamps` table in `evidence.db`

If no API key is set, blockchain timestamping is silently skipped.

## Postman Collection

`parler-evidence.postman_collection.json` is a portable Postman Collection (v2.1) that can run independently from Postman's cloud infrastructure.

### Setup

1. Import `parler-evidence.postman_collection.json` into Postman
2. Set the `bearer_token` collection variable to your OAuth token
3. Run requests manually or set up a [Postman Monitor](https://learning.postman.com/docs/monitoring-your-api/intro-monitors/)

### What it tests

Each request includes test scripts that:
- Assert the response is JSON with HTTP 200
- Check for CC-specific field names (`userUlid`, `userEngagement`, `displayName`, etc.)
- Check for ULID patterns in ID fields (`/^[0-9a-hjkmnp-tv-z]{26}$/`)
- Check for CC structural patterns (`data` envelope, nested engagement objects, ULID-keyed maps)
- Log all found CC fingerprint fields to the Postman console

Postman Monitors run from Postman's cloud infrastructure and store timestamped results, providing another independent evidence source.

## Endpoints monitored

### Public (no authentication)

| Endpoint | Method | Significance |
|----------|--------|--------------|
| `/public/v4/posts/map` | POST | CC `/public/v4/` namespace + ULID fingerprint |
| `app.parler.com/` | GET | Platform liveness + encrypted copyright marker |
| `playtv.parler.com/` | GET | PlayTV liveness + encrypted copyright marker |

### Authenticated (OAuth bearer token)

| Endpoint | Method | Significance |
|----------|--------|--------------|
| `/v3/user/settings` | GET | CC user settings endpoint |
| `/v3/profile` | POST | CC ULID-based profile bulk lookup (map pattern) |
| `/v3/user` | GET | CC authenticated user endpoint |
| `/v3/trending/hashtags/last24` | GET | CC trending system |
| `/v3/user/notifications` | GET | CC notification system |
| `/v3/profile/parlersupport` | GET | CC profile-by-username endpoint |
| `/v3/posts/influencers` | GET | CC influencer/trending posts |

## Evidence use

- `evidence.db` is the evidentiary record — do not delete or modify
- Each capture has a UTC timestamp and SHA-256 hash
- The hash proves the response was not altered after capture
- Schema hashes prove the API structure matches CC's proprietary data model
- Blockchain stamps (if enabled) provide independent third-party timestamp attestation
- Token refresh events are logged separately for audit trail
- Export individual captures from the web UI for submission to counsel

## For your friend running this

1. Download `monitor.py` to any computer
2. Log in to app.parler.com, extract `credentials.json` from browser localStorage (see above)
3. Place `credentials.json` next to `monitor.py`
4. Run `python3 monitor.py`
5. Leave it running — it auto-captures at 9 AM PT and 6 PM PT daily
6. Send the `evidence.db` file to Sean periodically
7. (Optional) Set `ORIGINSTAMP_API_KEY` env var for blockchain timestamping
8. (Optional) Import the Postman collection for independent cloud-based monitoring






