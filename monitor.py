#!/usr/bin/env python3
"""
Parler API Evidence Monitor
Captures and logs API requests/responses to SQLite for legal evidence.
Supports both public and authenticated (OAuth) endpoints.

Run: python3 monitor.py
Then open: http://localhost:8080

OAuth: Place credentials.json in the same directory with:
  {"accessToken": "...", "refreshToken": "..."}
  Tokens auto-refresh via POST /auth/refreshtoken (same as the Parler web UI).
"""

import sqlite3
import json
import hashlib
import datetime
import urllib.request
import urllib.error
import threading
import time
import http.server
import socketserver
import html as html_mod
import re
import os
from pathlib import Path

DB_FILE = "evidence.db"
PORT = 8080
CREDENTIALS_FILE = "credentials.json"
ORIGINSTAMP_API_KEY = os.environ.get("ORIGINSTAMP_API_KEY", "")

# --- CC-Specific Field Names (known Closed Circuit platform fields) ---

CC_KNOWN_FIELDS = {
    # ULID identifiers (Crockford Base32 — CC signature)
    "ulid", "userUlid", "parentUlid", "threadUlid", "rootUlid",
    "userId", "postId", "notificationId", "fromUserId", "liveStreamId",
    # Engagement / social graph
    "ProfileEngagement", "isFollowing", "isFollowingYou",
    "isBanned", "isBlocked", "isBlockedByThem", "isBlockedByYou",
    "isMuted", "isSubscribed", "is_partner",
    # Counts
    "postCount", "followers", "following", "friendCount",
    "networkSize", "burstCount", "mediaCount", "repliesCount",
    "videoCount", "joinedGroupCount",
    # Profile fields
    "avatar", "background", "background_color", "branding_logo",
    "primary_colors", "secondary_colors", "theme", "dark_mode",
    "badges", "bio", "username", "emailVerified",
    "name", "email", "phone_number", "website", "website_name",
    # Account / onboarding
    "acceptTermsOfService", "accountSetup",
    # Timestamps (CC epoch pattern)
    "createdAt", "updatedAt", "updatedAtEpoch", "lastActiveAt",
    "userUpdatedAt", "userUpdatedAtEpoch",
    "postUpdatedAt", "postUpdatedAtEpoch", "postUpdatedAtUTC",
    "fromUserUpdatedAt", "fromUserUpdatedAtEpoch",
    "current_streak", "longest_streak",
    # Notifications
    "notificationType", "notificationTypeId",
    "rootId", "rootType", "parentId",
    "postIsSuperComment", "reactionName",
    "contentNotAvailableReason",
    "read", "seen",
    # Streaming / media
    "can_stream", "streaming_permissions", "available_qualities",
    # Pagination (CC cursor pattern)
    "next_cursor", "prev_cursor", "next_page_url", "prev_page_url",
    # Products / monetization
    "products", "referral_code", "transactionAmount",
    # Settings key-value pattern
    "value",
}

# --- OAuth Token Management ---

_token_lock = threading.Lock()
_credentials = None


def load_credentials():
    """Load OAuth credentials from credentials.json.
    Supports both snake_case (access_token) and camelCase (accessToken) keys.
    """
    global _credentials
    creds_path = Path(CREDENTIALS_FILE)
    if not creds_path.exists():
        print(f"  [AUTH] No {CREDENTIALS_FILE} found — authenticated endpoints will be skipped")
        _credentials = None
        return
    with open(creds_path) as f:
        raw = json.load(f)

    # Normalize to snake_case keys
    _credentials = {
        "access_token": raw.get("access_token") or raw.get("accessToken", ""),
        "refresh_token": raw.get("refresh_token") or raw.get("refreshToken", ""),
        "token_url": raw.get("token_url", "https://api.parler.com/oauth/token"),
        "client_id": raw.get("client_id", ""),
        "client_secret": raw.get("client_secret", ""),
        "_raw": raw,  # preserve original for save-back
    }
    token = _credentials["access_token"]
    print(f"  [AUTH] Loaded credentials (token ends ...{token[-8:] if token else 'empty'})")


def save_credentials():
    """Persist updated credentials back to credentials.json in original format."""
    if _credentials is None:
        return
    raw = _credentials.get("_raw", {})
    # Write back in whichever format the original used
    if "accessToken" in raw:
        raw["accessToken"] = _credentials["access_token"]
        raw["refreshToken"] = _credentials["refresh_token"]
    else:
        raw["access_token"] = _credentials["access_token"]
        raw["refresh_token"] = _credentials["refresh_token"]
    with open(CREDENTIALS_FILE, "w") as f:
        json.dump(raw, f, indent=2)


def get_access_token():
    """Return the current access token, or None if no credentials."""
    if _credentials is None:
        return None
    return _credentials.get("access_token")


def refresh_access_token():
    """Try OAuth refresh, then fall back to reloading credentials.json from disk."""
    global _credentials
    with _token_lock:
        if _credentials is None:
            # Try loading from disk in case file was just created
            load_credentials()
            return _credentials is not None

        refresh_token = _credentials.get("refresh_token")

        # Parler UI refresh: POST /auth/refreshtoken with JSON body
        if refresh_token:
            print("  [AUTH] Refreshing access token via /auth/refreshtoken...")

            body = json.dumps({"refresh_token": refresh_token}).encode()

            req = urllib.request.Request(
                "https://api.parler.com/auth/refreshtoken",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )

            try:
                with urllib.request.urlopen(req, timeout=15) as resp:
                    token_data = json.loads(resp.read().decode())
                    _credentials["access_token"] = token_data.get("access_token") or token_data.get("accessToken", "")
                    new_refresh = token_data.get("refresh_token") or token_data.get("refreshToken")
                    if new_refresh:
                        _credentials["refresh_token"] = new_refresh
                    save_credentials()
                    print(f"  [AUTH] Token refreshed (ends ...{_credentials['access_token'][-8:]})")
                    return True
            except Exception as e:
                print(f"  [AUTH] OAuth refresh failed: {e}")

        # Fall back: reload credentials.json from disk
        # (user may have updated it manually from browser localStorage)
        print("  [AUTH] Reloading credentials from disk...")
        old_token = _credentials.get("access_token", "")

    # Release lock before calling load_credentials (which sets global)
    load_credentials()
    new_token = get_access_token() or ""
    if new_token and new_token != old_token:
        print("  [AUTH] New token loaded from disk")
        save_token_event("reloaded_from_disk", "success")
        return True
    elif new_token:
        print("  [AUTH] Token unchanged on disk")
        return True
    else:
        print("  [AUTH] No valid token found")
        return False


import urllib.parse  # needed for urlencode in refresh


# --- Schema Fingerprinting ---

ULID_PATTERN = re.compile(r"^[0-9a-hjkmnp-tv-z]{26}$")

# --- CC Architectural Pattern Detection ---
# These are design patterns unique to the CC Platform that go beyond field names.
# Each pattern is a structural signature that the expert witness can reference.

CC_ARCH_PATTERNS = {
    "cache_first_feed": {
        "name": "Cache-First Feed Architecture",
        "description": "Feed endpoint returns ULID arrays with minimal metadata (timestamps, parent refs) — "
                       "no full content. Client checks IndexedDB cache, hydrates missing items via /map endpoints.",
        "indicators": ["ulid", "updatedAtEpoch", "parentUlid", "userId", "userUpdatedAtEpoch"],
        "min_indicators": 4,
    },
    "dual_timestamp": {
        "name": "Dual Timestamp Pattern",
        "description": "Every entity has both ISO-8601 (updatedAt) and Unix epoch (updatedAtEpoch) timestamps. "
                       "The epoch value drives client-side cache invalidation comparisons.",
        "indicators": ["updatedAt", "updatedAtEpoch"],
        "min_indicators": 2,
    },
    "ulid_primary_keys": {
        "name": "ULID Primary Keys",
        "description": "26-character Crockford Base32 ULIDs used as primary keys throughout. "
                       "Not standard UUIDs — lexicographically sortable, timestamp-embedded.",
        "indicators": [],  # Detected via ULID value pattern match, not field names
        "min_indicators": 0,
    },
    "map_endpoint": {
        "name": "Bulk Map Endpoint Pattern",
        "description": "POST endpoints that accept {\"ulids\": [...]} arrays and return bulk-mapped data. "
                       "Unique CC Platform pattern for client-side cache hydration.",
        "indicators": [],  # Detected via URL pattern /map or /profile with ULID body
        "min_indicators": 0,
    },
    "user_cache_invalidation": {
        "name": "User Cache Invalidation Timestamps",
        "description": "Separate userUpdatedAt/userUpdatedAtEpoch fields on every entity to enable "
                       "client-side detection of stale user data independent of content updates.",
        "indicators": ["userUpdatedAt", "userUpdatedAtEpoch"],
        "min_indicators": 2,
    },
    "engagement_object": {
        "name": "ProfileEngagement Object Pattern",
        "description": "Dedicated ProfileEngagement object containing follow/block/mute state as a nested "
                       "object with boolean fields. CC Platform's relationship state pattern.",
        "indicators": ["ProfileEngagement", "isFollowing", "isFollowingYou", "isBlocked", "isMuted"],
        "min_indicators": 3,
    },
}


def detect_arch_patterns(schema_result):
    """Detect CC architectural patterns in a schema extraction result."""
    found_patterns = []
    cc_fields = set(schema_result.get("cc_fingerprint_fields", []))
    ulid_count = len(schema_result.get("ulid_fields", []))

    for key, pattern in CC_ARCH_PATTERNS.items():
        if key == "ulid_primary_keys":
            if ulid_count > 0:
                found_patterns.append(pattern["name"])
        elif key == "map_endpoint":
            continue  # Detected by URL, not schema
        else:
            matched = sum(1 for ind in pattern["indicators"] if ind in cc_fields)
            if matched >= pattern["min_indicators"]:
                found_patterns.append(pattern["name"])

    return found_patterns


def extract_schema(obj, prefix=""):
    """Recursively extract the structural schema from a JSON response.

    Returns dict with:
        field_paths: sorted list of dot-notation key paths
        field_types: mapping of path -> JSON type
        ulid_fields: list of fields whose values match ULID pattern
        cc_fingerprint_fields: list of CC-specific field names found
        cc_fingerprint_score: ratio of CC fields found / total known CC fields
        schema_hash: SHA-256 of sorted field_paths
    """
    field_paths = []
    field_types = {}
    ulid_fields = []

    def _walk(node, path):
        if isinstance(node, dict):
            for key in sorted(node.keys()):
                child_path = f"{path}.{key}" if path else key
                field_paths.append(child_path)
                child = node[key]
                if isinstance(child, dict):
                    field_types[child_path] = "object"
                    _walk(child, child_path)
                elif isinstance(child, list):
                    field_types[child_path] = "array"
                    if child:
                        # Walk first element as representative
                        arr_path = f"{child_path}[]"
                        _walk(child[0], arr_path)
                elif isinstance(child, bool):
                    field_types[child_path] = "boolean"
                elif isinstance(child, int):
                    field_types[child_path] = "integer"
                elif isinstance(child, float):
                    field_types[child_path] = "number"
                elif child is None:
                    field_types[child_path] = "null"
                else:
                    field_types[child_path] = "string"
                    # Check for ULID values
                    if isinstance(child, str) and ULID_PATTERN.match(child):
                        ulid_fields.append(child_path)
        elif isinstance(node, list) and node:
            _walk(node[0], path)

    _walk(obj, prefix)

    # Deduplicate and sort
    field_paths = sorted(set(field_paths))

    # Find CC-specific fields (check leaf name against known set)
    found_cc = set()
    for fp in field_paths:
        leaf = fp.split(".")[-1].rstrip("[]")
        if leaf in CC_KNOWN_FIELDS:
            found_cc.add(leaf)

    cc_fields_list = sorted(found_cc)
    # Per-endpoint score: what fraction of THIS response's APPLICATION fields are CC-specific
    # Excludes standard framework boilerplate (Laravel pagination, JSON:API envelope fields)
    # that dilute the score without representing application-level code
    FRAMEWORK_BOILERPLATE = {
        # Laravel pagination envelope
        "data", "links", "meta", "first", "last", "next", "prev",
        "path", "per_page", "current_page", "from", "to", "total",
        "last_page", "last_page_url", "first_page_url",
        # Generic JSON:API / envelope fields
        "type", "attributes", "relationships", "included", "jsonapi",
        "self", "related", "pagination",
        # HTTP/cache metadata
        "status", "message", "success", "error", "errors",
    }
    response_leaves = set()
    for fp in field_paths:
        leaf = fp.split(".")[-1].rstrip("[]")
        response_leaves.add(leaf)
    # Remove framework boilerplate from denominator
    app_leaves = response_leaves - FRAMEWORK_BOILERPLATE
    cc_score = len(found_cc) / len(app_leaves) if app_leaves else 0.0

    # Schema hash = SHA-256 of the sorted field paths (structure only, no data)
    schema_str = "\n".join(field_paths)
    schema_hash = hashlib.sha256(schema_str.encode()).hexdigest()

    return {
        "field_paths": field_paths,
        "field_types": field_types,
        "ulid_fields": ulid_fields,
        "cc_fingerprint_fields": cc_fields_list,
        "cc_fingerprint_score": round(cc_score, 4),
        "schema_hash": schema_hash,
    }


# --- Blockchain Timestamping (OriginStamp) ---


def submit_to_originstamp(hash_value, comment=""):
    """Submit a SHA-256 hash to OriginStamp for blockchain timestamping.
    Returns the API response dict, or None if no API key or on error.
    """
    if not ORIGINSTAMP_API_KEY:
        return None

    body = json.dumps({
        "comment": comment[:256],
        "hash": hash_value,
        "hash_string": True,
    }).encode()

    req = urllib.request.Request(
        "https://api.originstamp.com/v4/timestamp/create",
        data=body,
        headers={
            "Content-Type": "application/json",
            "x-api-key": ORIGINSTAMP_API_KEY,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        print(f"  [BLOCKCHAIN] OriginStamp error: {e}")
        return None


def save_blockchain_stamp(capture_id, hash_type, hash_value, response):
    """Save a blockchain timestamp record."""
    conn = sqlite3.connect(DB_FILE)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute("""
        INSERT INTO blockchain_stamps (
            stamped_at, capture_id, hash_type, hash_value, service, submitted, response
        ) VALUES (?, ?, ?, ?, 'originstamp', ?, ?)
    """, (
        now,
        capture_id,
        hash_type,
        hash_value,
        1 if response else 0,
        json.dumps(response) if response else None,
    ))
    conn.commit()
    conn.close()


# --- Endpoints ---

# Public endpoints (no auth required)
PUBLIC_ENDPOINTS = [
    {
        "label": "Posts Map (POST /public/v4/posts/map)",
        "category": "public",
        "method": "POST",
        "url": "https://api.parler.com/public/v4/posts/map",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"ulids": []}),
    },
    {
        "label": "App Parler Home (GET app.parler.com)",
        "category": "public",
        "method": "GET",
        "url": "https://app.parler.com/",
        "headers": {},
        "body": None,
    },
    {
        "label": "PlayTV Home (GET playtv.parler.com)",
        "category": "public",
        "method": "GET",
        "url": "https://playtv.parler.com/",
        "headers": {},
        "body": None,
    },
]

# Authenticated endpoints (require OAuth bearer token)
AUTH_ENDPOINTS = [
    {
        "label": "User Settings (GET /v3/user/settings)",
        "category": "auth",
        "method": "GET",
        "url": "https://api.parler.com/v3/user/settings",
        "headers": {},
        "body": None,
    },
    {
        "label": "Profile Map (POST /v3/profile)",
        "category": "auth",
        "method": "POST",
        "url": "https://api.parler.com/v3/profile",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"ulids": [
            "01ecyq99tgjana70v365ynhwv4",
            "01cyb6bvrgwnncdcxk9bmw5ssg",
            "01dd14f88r5rfve8wp7kqzts3y",
            "01hpptvsfvfnn143qd07qj1829",
            "01e9dq87f02t1fz0efjc1gxdb8",
            "01cp0gev20wp1zeg5aynege5fd",
            "01dc5fkwf8mywf3zwjwx50n0qk",
            "01cyc8jny84pqm7swddxfvxe22",
        ]}),
    },
    {
        "label": "Current User (GET /v3/user)",
        "category": "auth",
        "method": "GET",
        "url": "https://api.parler.com/v3/user",
        "headers": {},
        "body": None,
    },
    {
        "label": "Notifications (GET /v3/user/notifications)",
        "category": "auth",
        "method": "GET",
        "url": "https://api.parler.com/v3/user/notifications",
        "headers": {},
        "body": None,
    },
    {
        "label": "Profile: parlersupport (GET /v3/profile/parlersupport)",
        "category": "auth",
        "method": "GET",
        "url": "https://api.parler.com/v3/profile/parlersupport",
        "headers": {},
        "body": None,
    },
    {
        "label": "Influencers (GET /v3/posts/influencers)",
        "category": "auth",
        "method": "GET",
        "url": "https://api.parler.com/v3/posts/influencers",
        "headers": {},
        "body": None,
    },
]

ENDPOINTS = PUBLIC_ENDPOINTS + AUTH_ENDPOINTS

# --- Database ---


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS captures (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            captured_at TEXT NOT NULL,
            epoch       INTEGER NOT NULL,
            label       TEXT NOT NULL,
            category    TEXT NOT NULL DEFAULT 'public',
            method      TEXT NOT NULL,
            url         TEXT NOT NULL,
            request_headers TEXT,
            request_body    TEXT,
            http_status     INTEGER,
            response_headers TEXT,
            response_body   TEXT,
            response_size   INTEGER,
            sha256          TEXT,
            error           TEXT
        )
    """)
    # Add columns if upgrading from old schema
    _alter_columns = [
        ("captures", "category", "TEXT NOT NULL DEFAULT 'public'"),
        ("captures", "schema_hash", "TEXT"),
        ("captures", "schema_fields", "TEXT"),
        ("captures", "cc_fingerprint_score", "REAL"),
        ("captures", "cc_fingerprint_fields", "TEXT"),
        ("captures", "ulid_field_count", "INTEGER"),
        ("captures", "arch_patterns", "TEXT"),
    ]
    for table, col, typedef in _alter_columns:
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {typedef}")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
    conn.execute("""
        CREATE TABLE IF NOT EXISTS token_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            event_at    TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            detail      TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS blockchain_stamps (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            stamped_at  TEXT NOT NULL,
            capture_id  INTEGER,
            hash_type   TEXT NOT NULL,
            hash_value  TEXT NOT NULL,
            service     TEXT NOT NULL DEFAULT 'originstamp',
            submitted   INTEGER NOT NULL DEFAULT 0,
            response    TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_capture(data: dict):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.execute("""
        INSERT INTO captures (
            captured_at, epoch, label, category, method, url,
            request_headers, request_body,
            http_status, response_headers, response_body,
            response_size, sha256, error,
            schema_hash, schema_fields, cc_fingerprint_score,
            cc_fingerprint_fields, ulid_field_count, arch_patterns
        ) VALUES (
            :captured_at, :epoch, :label, :category, :method, :url,
            :request_headers, :request_body,
            :http_status, :response_headers, :response_body,
            :response_size, :sha256, :error,
            :schema_hash, :schema_fields, :cc_fingerprint_score,
            :cc_fingerprint_fields, :ulid_field_count, :arch_patterns
        )
    """, data)
    capture_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return capture_id


def save_token_event(event_type, detail=None):
    conn = sqlite3.connect(DB_FILE)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn.execute(
        "INSERT INTO token_events (event_at, event_type, detail) VALUES (?, ?, ?)",
        (now, event_type, detail),
    )
    conn.commit()
    conn.close()


def get_captures(limit=200, category=None):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    if category:
        rows = conn.execute(
            "SELECT * FROM captures WHERE category = ? ORDER BY id DESC LIMIT ?",
            (category, limit),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT * FROM captures ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_capture(capture_id):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        "SELECT * FROM captures WHERE id = ?", (capture_id,)
    ).fetchone()
    conn.close()
    return dict(row) if row else None


def get_stats():
    conn = sqlite3.connect(DB_FILE)
    stats = {}
    stats["total"] = conn.execute("SELECT COUNT(*) FROM captures").fetchone()[0]
    stats["public"] = conn.execute(
        "SELECT COUNT(*) FROM captures WHERE category = 'public'"
    ).fetchone()[0]
    stats["auth"] = conn.execute(
        "SELECT COUNT(*) FROM captures WHERE category = 'auth'"
    ).fetchone()[0]
    stats["errors"] = conn.execute(
        "SELECT COUNT(*) FROM captures WHERE error IS NOT NULL"
    ).fetchone()[0]
    stats["last_capture"] = conn.execute(
        "SELECT captured_at FROM captures ORDER BY id DESC LIMIT 1"
    ).fetchone()
    stats["last_capture"] = stats["last_capture"][0] if stats["last_capture"] else "Never"
    stats["auth_status"] = "Active" if get_access_token() else "No credentials"
    # Avg CC fingerprint score (only for captures that have schema data)
    avg_row = conn.execute(
        "SELECT AVG(cc_fingerprint_score) FROM captures WHERE cc_fingerprint_score IS NOT NULL"
    ).fetchone()
    stats["avg_cc_score"] = round(avg_row[0], 3) if avg_row and avg_row[0] is not None else None
    # Combined platform score: unique CC fields found across ALL latest endpoint captures / total known CC fields
    # Uses the most recent capture per endpoint label for deduplication
    combined_rows = conn.execute(
        """SELECT cc_fingerprint_fields FROM captures
           WHERE cc_fingerprint_fields IS NOT NULL AND cc_fingerprint_fields != '[]'
           AND id IN (SELECT MAX(id) FROM captures WHERE cc_fingerprint_score IS NOT NULL GROUP BY label)"""
    ).fetchall()
    all_cc_fields = set()
    for row in combined_rows:
        try:
            fields = json.loads(row[0])
            all_cc_fields.update(fields)
        except (json.JSONDecodeError, TypeError):
            pass
    stats["combined_cc_fields"] = sorted(all_cc_fields)
    stats["combined_cc_count"] = len(all_cc_fields)
    stats["combined_cc_score"] = round(len(all_cc_fields) / len(CC_KNOWN_FIELDS), 4) if CC_KNOWN_FIELDS else 0.0
    # Count distinct architectural patterns detected across all captures
    pattern_rows = conn.execute(
        """SELECT arch_patterns FROM captures
           WHERE arch_patterns IS NOT NULL
           AND id IN (SELECT MAX(id) FROM captures WHERE arch_patterns IS NOT NULL GROUP BY label)"""
    ).fetchall()
    all_patterns = set()
    for row in pattern_rows:
        try:
            patterns = json.loads(row[0])
            all_patterns.update(patterns)
        except (json.JSONDecodeError, TypeError):
            pass
    stats["arch_patterns"] = sorted(all_patterns)
    stats["arch_pattern_count"] = len(all_patterns)
    # Blockchain stamps count
    stamps_row = conn.execute("SELECT COUNT(*) FROM blockchain_stamps WHERE submitted = 1").fetchone()
    stats["blockchain_stamps"] = stamps_row[0] if stamps_row else 0
    conn.close()
    return stats


# --- API Capture ---


def capture_endpoint(endpoint: dict) -> dict:
    now = datetime.datetime.now(datetime.timezone.utc)
    captured_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    epoch = int(now.timestamp())
    category = endpoint.get("category", "public")

    # Skip auth endpoints if no credentials
    if category == "auth" and get_access_token() is None:
        return None

    data = {
        "captured_at": captured_at,
        "epoch": epoch,
        "label": endpoint["label"],
        "category": category,
        "method": endpoint["method"],
        "url": endpoint["url"],
        "request_headers": None,
        "request_body": endpoint.get("body"),
        "http_status": None,
        "response_headers": None,
        "response_body": None,
        "response_size": None,
        "sha256": None,
        "error": None,
        "schema_hash": None,
        "schema_fields": None,
        "cc_fingerprint_score": None,
        "cc_fingerprint_fields": None,
        "ulid_field_count": None,
        "arch_patterns": None,
    }

    # Build headers
    headers = dict(endpoint.get("headers", {}))
    if category == "auth":
        token = get_access_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

    data["request_headers"] = json.dumps(headers)

    try:
        body_bytes = endpoint["body"].encode() if endpoint.get("body") else None
        req = urllib.request.Request(
            endpoint["url"],
            data=body_bytes,
            headers=headers,
            method=endpoint["method"],
        )
        req.add_header("User-Agent", "Mozilla/5.0 (Evidence Monitor)")

        with urllib.request.urlopen(req, timeout=15) as resp:
            response_body = resp.read().decode("utf-8", errors="replace")
            data["http_status"] = resp.status
            data["response_headers"] = json.dumps(dict(resp.headers))
            data["response_body"] = response_body
            data["response_size"] = len(response_body)
            data["sha256"] = hashlib.sha256(response_body.encode()).hexdigest()

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        data["http_status"] = e.code
        data["response_headers"] = json.dumps(dict(e.headers))
        data["response_body"] = body
        data["response_size"] = len(body)
        data["sha256"] = hashlib.sha256(body.encode()).hexdigest()
        data["error"] = f"HTTP {e.code}: {e.reason}"

        # Auto-refresh on 401
        if e.code == 401 and category == "auth":
            save_token_event("401_received", endpoint["url"])
            if refresh_access_token():
                save_token_event("token_refreshed", "success")
                # Retry once with new token
                return capture_endpoint(endpoint)
            else:
                save_token_event("token_refresh_failed", endpoint["url"])

    except Exception as e:
        data["error"] = str(e)

    # --- Schema fingerprinting ---
    if data["response_body"]:
        try:
            parsed = json.loads(data["response_body"])
            schema = extract_schema(parsed)
            data["schema_hash"] = schema["schema_hash"]
            data["schema_fields"] = json.dumps(schema["field_paths"])
            data["cc_fingerprint_score"] = schema["cc_fingerprint_score"]
            data["cc_fingerprint_fields"] = json.dumps(schema["cc_fingerprint_fields"])
            data["ulid_field_count"] = len(schema["ulid_fields"])
            # Detect CC architectural patterns
            patterns = detect_arch_patterns(schema)
            # Check for map endpoint pattern by URL
            if "/map" in data["url"] or ("/profile" in data["url"] and data["method"] == "POST"):
                patterns.append("Bulk Map Endpoint Pattern")
            data["arch_patterns"] = json.dumps(patterns) if patterns else None
        except (json.JSONDecodeError, TypeError):
            pass  # Non-JSON response (HTML pages etc.)

    return data


def run_all_captures():
    results = []
    for endpoint in ENDPOINTS:
        data = capture_endpoint(endpoint)
        if data is not None:
            capture_id = save_capture(data)

            # --- Blockchain timestamping ---
            if ORIGINSTAMP_API_KEY and data.get("sha256"):
                comment = f"Parler API capture: {data['label']} at {data['captured_at']}"
                resp = submit_to_originstamp(data["sha256"], comment)
                save_blockchain_stamp(capture_id, "response", data["sha256"], resp)

                if data.get("schema_hash"):
                    comment_s = f"Schema hash: {data['label']} at {data['captured_at']}"
                    resp_s = submit_to_originstamp(data["schema_hash"], comment_s)
                    save_blockchain_stamp(capture_id, "schema", data["schema_hash"], resp_s)

            results.append(data)
    return results


# --- Background Scheduler ---


PT = datetime.timezone(datetime.timedelta(hours=-8))  # Pacific Time (PST)
CAPTURE_TIMES = [(9, 0), (18, 0)]  # 9:00 AM PT, 6:00 PM PT


def _next_capture_time():
    """Calculate seconds until the next scheduled capture (9 AM PT or 6 PM PT)."""
    now_pt = datetime.datetime.now(PT)
    today = now_pt.date()

    candidates = []
    for hour, minute in CAPTURE_TIMES:
        t = datetime.datetime(today.year, today.month, today.day, hour, minute, tzinfo=PT)
        if t > now_pt:
            candidates.append(t)
    # If no more captures today, use tomorrow's first slot
    if not candidates:
        tomorrow = today + datetime.timedelta(days=1)
        hour, minute = CAPTURE_TIMES[0]
        candidates.append(
            datetime.datetime(tomorrow.year, tomorrow.month, tomorrow.day, hour, minute, tzinfo=PT)
        )

    next_time = min(candidates)
    wait_seconds = (next_time - now_pt).total_seconds()
    return next_time, wait_seconds


def scheduler():
    """Run captures at 9:00 AM PT and 6:00 PM PT daily."""
    while True:
        next_time, wait_seconds = _next_capture_time()
        next_utc = next_time.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        next_pt = next_time.strftime("%Y-%m-%d %I:%M %p PT")
        print(f"  Next capture: {next_pt} ({next_utc}) — sleeping {wait_seconds/3600:.1f}h")
        time.sleep(wait_seconds)

        print(
            f"[{datetime.datetime.now(datetime.timezone.utc).isoformat()}] Running scheduled capture..."
        )
        results = run_all_captures()
        ok = sum(1 for r in results if r.get("http_status") and r["http_status"] < 400)
        err = sum(1 for r in results if r.get("error"))
        print(f"  Captured {len(results)} endpoints ({ok} ok, {err} errors)")


# --- Web UI ---

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Parler API Evidence Monitor</title>
<style>
  body {{ font-family: monospace; background: #0f0f0f; color: #d4d4d4; margin: 0; padding: 20px; }}
  h1 {{ color: #e50038; }}
  h2 {{ color: #aaa; font-size: 14px; margin-top: 0; }}
  .stats {{ display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }}
  .stat {{ background: #1a1a1a; padding: 12px 20px; border-radius: 4px; border-left: 3px solid #e50038; }}
  .stat .n {{ font-size: 24px; color: #fff; }}
  .stat .l {{ font-size: 11px; color: #888; }}
  .stat.auth-ok {{ border-left-color: #4caf50; }}
  .stat.auth-none {{ border-left-color: #ff9800; }}
  .btn {{ background: #e50038; color: white; border: none; padding: 10px 20px;
           cursor: pointer; border-radius: 4px; font-family: monospace; font-size: 13px; }}
  .btn:hover {{ background: #c00030; }}
  .btn-sm {{ padding: 6px 14px; font-size: 12px; }}
  .tabs {{ display: flex; gap: 0; margin-bottom: 16px; }}
  .tab {{ padding: 8px 20px; background: #1a1a1a; color: #888; cursor: pointer;
           border: 1px solid #333; font-family: monospace; font-size: 12px; text-decoration: none; }}
  .tab:first-child {{ border-radius: 4px 0 0 4px; }}
  .tab:last-child {{ border-radius: 0 4px 4px 0; }}
  .tab.active {{ background: #e50038; color: white; border-color: #e50038; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ background: #1a1a1a; color: #888; text-align: left; padding: 8px; border-bottom: 1px solid #333; }}
  td {{ padding: 8px; border-bottom: 1px solid #1a1a1a; vertical-align: top; }}
  tr:hover td {{ background: #161616; }}
  .status-ok {{ color: #4caf50; }}
  .status-err {{ color: #e50038; }}
  .status-warn {{ color: #ff9800; }}
  .hash {{ color: #555; font-size: 10px; }}
  .label {{ color: #69b4ff; }}
  .cat-public {{ color: #4caf50; font-size: 10px; text-transform: uppercase; }}
  .cat-auth {{ color: #ff9800; font-size: 10px; text-transform: uppercase; }}
  a {{ color: #69b4ff; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .note {{ background: #1a1200; border-left: 3px solid #ff9800; padding: 12px; margin-bottom: 20px; font-size: 12px; }}
</style>
</head>
<body>
<h1>Parler API Evidence Monitor</h1>
<h2>Case No. 494-07423-2025 &mdash; Closed Circuit, Inc. and SOC, LLC v. Parler Cloud Technologies, LLC</h2>

<div class="note">
  All captures are timestamped UTC and stored with SHA-256 hashes for evidentiary integrity.
  Injunction signed: 2026-02-19 10:55 AM CST (16:55 UTC).
</div>

<div class="stats">
  <div class="stat"><div class="n">{total}</div><div class="l">Total Captures</div></div>
  <div class="stat"><div class="n">{public}</div><div class="l">Public</div></div>
  <div class="stat"><div class="n">{auth}</div><div class="l">Authenticated</div></div>
  <div class="stat"><div class="n">{errors}</div><div class="l">Errors</div></div>
  <div class="stat"><div class="n">{last_capture}</div><div class="l">Last Capture (UTC)</div></div>
  <div class="stat {auth_class}"><div class="n">{auth_status}</div><div class="l">OAuth Status</div></div>
  <div class="stat" style="border-left-color:#e91e63;"><div class="n">{combined_cc_score}</div><div class="l">Platform CC Score ({combined_cc_count}/{total_cc_fields})</div></div>
  <div class="stat" style="border-left-color:#9c27b0;"><div class="n">{avg_cc_score}</div><div class="l">Avg Endpoint Score</div></div>
  <div class="stat" style="border-left-color:#2196f3;"><div class="n">{blockchain_stamps}</div><div class="l">Blockchain Stamps</div></div>
</div>

<form method="POST" action="/capture" style="margin-bottom:20px; display:inline;">
  <button class="btn" type="submit">Run Capture Now</button>
</form>
<form method="POST" action="/refresh-token" style="margin-bottom:20px; display:inline; margin-left:8px;">
  <button class="btn btn-sm" type="submit" style="background:#333;">Reload Credentials</button>
</form>
<span style="color:#555;font-size:12px;margin-left:12px;">Auto-runs at 9:00 AM PT &amp; 6:00 PM PT daily</span>

<div class="tabs" style="margin-top:20px;">
  <a class="tab {tab_all}" href="/">All</a>
  <a class="tab {tab_public}" href="/?cat=public">Public</a>
  <a class="tab {tab_auth}" href="/?cat=auth">Authenticated</a>
</div>

<table>
<tr>
  <th>ID</th>
  <th>Captured (UTC)</th>
  <th>Type</th>
  <th>Endpoint</th>
  <th>Method</th>
  <th>Status</th>
  <th>Size</th>
  <th>CC Score</th>
  <th>SHA-256</th>
  <th>Detail</th>
</tr>
{rows}
</table>
</body>
</html>"""

ROW_TEMPLATE = """<tr>
  <td>{id}</td>
  <td>{captured_at}</td>
  <td class="{cat_class}">{category}</td>
  <td class="label">{label}</td>
  <td>{method}</td>
  <td class="{status_class}">{status_display}</td>
  <td>{size}</td>
  <td class="{cc_score_class}">{cc_score}</td>
  <td class="hash">{sha256}</td>
  <td><a href="/detail/{id}">View</a></td>
</tr>"""

DETAIL_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Capture #{id}</title>
<style>
  body {{ font-family: monospace; background: #0f0f0f; color: #d4d4d4; margin: 0; padding: 20px; }}
  h1 {{ color: #e50038; }}
  .meta {{ background: #1a1a1a; padding: 16px; border-radius: 4px; margin-bottom: 16px; font-size: 13px; }}
  .meta table td {{ padding: 4px 12px 4px 0; color: #aaa; }}
  .meta table td:first-child {{ color: #555; width: 160px; }}
  pre {{ background: #111; padding: 16px; border-radius: 4px; overflow-x: auto;
         font-size: 11px; white-space: pre-wrap; word-break: break-all; max-height: 600px; overflow-y: auto; }}
  .section {{ color: #888; font-size: 12px; margin: 16px 0 4px 0; text-transform: uppercase; letter-spacing: 1px; }}
  a {{ color: #69b4ff; text-decoration: none; }}
  .hash {{ color: #4caf50; font-size: 12px; }}
  .error {{ color: #e50038; }}
  .cat-public {{ color: #4caf50; }}
  .cat-auth {{ color: #ff9800; }}
  .schema-section {{ background: #1a1a2a; padding: 16px; border-radius: 4px; margin: 16px 0; border-left: 3px solid #9c27b0; }}
  .schema-section h3 {{ color: #9c27b0; margin: 0 0 12px 0; font-size: 14px; }}
  .cc-field {{ display: inline-block; background: #2a1a2a; color: #ce93d8; padding: 2px 8px;
               border-radius: 3px; font-size: 11px; margin: 2px; }}
  .score-bar {{ background: #333; border-radius: 4px; height: 16px; margin: 4px 0; overflow: hidden; }}
  .score-fill {{ background: linear-gradient(90deg, #e50038, #9c27b0); height: 100%; border-radius: 4px; }}
</style>
</head>
<body>
<h1>Capture #{id}</h1>
<a href="/">&larr; Back</a>

<div class="meta">
<table>
  <tr><td>Captured At</td><td>{captured_at}</td></tr>
  <tr><td>Epoch</td><td>{epoch}</td></tr>
  <tr><td>Category</td><td class="{cat_class}">{category}</td></tr>
  <tr><td>Label</td><td>{label}</td></tr>
  <tr><td>Method</td><td>{method}</td></tr>
  <tr><td>URL</td><td>{url}</td></tr>
  <tr><td>HTTP Status</td><td>{http_status}</td></tr>
  <tr><td>Response Size</td><td>{response_size} bytes</td></tr>
  <tr><td>SHA-256</td><td class="hash">{sha256}</td></tr>
  {error_row}
</table>
</div>

{schema_section}

<div class="section">Request Headers</div>
<pre>{request_headers}</pre>

<div class="section">Request Body</div>
<pre>{request_body}</pre>

<div class="section">Response Headers</div>
<pre>{response_headers}</pre>

<div class="section">Response Body</div>
<pre>{response_body}</pre>

</body>
</html>"""


class Handler(http.server.BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        pass  # Suppress request logs

    def send_html(self, html, status=200):
        encoded = html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(encoded))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/":
            self.serve_index()
        elif path.startswith("/detail/"):
            capture_id = path.split("/")[-1]
            self.serve_detail(capture_id)
        else:
            self.send_html("<h1>Not Found</h1>", 404)

    def do_POST(self):
        if self.path == "/capture":
            run_all_captures()
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
        elif self.path == "/refresh-token":
            refresh_access_token()
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()

    def serve_index(self):
        # Parse category filter from query string
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        params = urllib.parse.parse_qs(query)
        cat_filter = params.get("cat", [None])[0]

        stats = get_stats()
        captures = get_captures(200, category=cat_filter)

        rows = []
        for c in captures:
            if c["error"]:
                status_class = "status-err"
                status_display = html_mod.escape(c["error"][:40])
            elif c["http_status"] and c["http_status"] < 400:
                status_class = "status-ok"
                status_display = str(c["http_status"])
            else:
                status_class = "status-warn"
                status_display = str(c["http_status"] or "—")

            cat = c.get("category", "public")
            cc_score = c.get("cc_fingerprint_score")
            if cc_score is not None:
                cc_score_display = f"{cc_score:.0%}"
                cc_score_class = "status-ok" if cc_score > 0.1 else "status-warn"
            else:
                cc_score_display = "—"
                cc_score_class = ""
            rows.append(
                ROW_TEMPLATE.format(
                    id=c["id"],
                    captured_at=c["captured_at"],
                    category=cat.upper(),
                    cat_class=f"cat-{cat}",
                    label=html_mod.escape(c["label"]),
                    method=c["method"],
                    status_class=status_class,
                    status_display=status_display,
                    size=f"{c['response_size']:,}" if c["response_size"] else "—",
                    cc_score=cc_score_display,
                    cc_score_class=cc_score_class,
                    sha256=c["sha256"][:16] + "..." if c["sha256"] else "—",
                )
            )

        auth_class = "auth-ok" if stats["auth_status"] == "Active" else "auth-none"
        tab_all = "active" if cat_filter is None else ""
        tab_public = "active" if cat_filter == "public" else ""
        tab_auth = "active" if cat_filter == "auth" else ""

        avg_score = stats.get("avg_cc_score")
        avg_cc_display = f"{avg_score:.0%}" if avg_score is not None else "N/A"
        combined_score = stats.get("combined_cc_score", 0)
        combined_cc_display = f"{combined_score:.0%}"

        html = HTML_TEMPLATE.format(
            total=stats["total"],
            public=stats["public"],
            auth=stats["auth"],
            errors=stats["errors"],
            last_capture=stats["last_capture"],
            auth_status=stats["auth_status"],
            auth_class=auth_class,
            avg_cc_score=avg_cc_display,
            combined_cc_score=combined_cc_display,
            combined_cc_count=stats.get("combined_cc_count", 0),
            total_cc_fields=len(CC_KNOWN_FIELDS),
            blockchain_stamps=stats.get("blockchain_stamps", 0),
            tab_all=tab_all,
            tab_public=tab_public,
            tab_auth=tab_auth,
            rows="\n".join(rows),
        )
        self.send_html(html)

    def serve_detail(self, capture_id):
        try:
            c = get_capture(int(capture_id))
        except (ValueError, TypeError):
            self.send_html("<h1>Not Found</h1>", 404)
            return
        if not c:
            self.send_html("<h1>Not Found</h1>", 404)
            return

        def pretty(s):
            if not s:
                return "—"
            try:
                return html_mod.escape(json.dumps(json.loads(s), indent=2))
            except Exception:
                return html_mod.escape(s)

        error_row = (
            f'<tr><td>Error</td><td class="error">{html_mod.escape(c["error"])}</td></tr>'
            if c["error"]
            else ""
        )

        # Build schema analysis section
        schema_section = ""
        if c.get("schema_hash"):
            cc_score = c.get("cc_fingerprint_score", 0) or 0
            cc_pct = int(cc_score * 100)
            cc_fields_raw = c.get("cc_fingerprint_fields", "[]")
            try:
                cc_fields_list = json.loads(cc_fields_raw)
            except (json.JSONDecodeError, TypeError):
                cc_fields_list = []
            cc_fields_html = " ".join(
                f'<span class="cc-field">{html_mod.escape(f)}</span>' for f in cc_fields_list
            ) or "<em style='color:#555'>None detected</em>"
            ulid_count = c.get("ulid_field_count", 0) or 0

            # Architectural patterns
            try:
                arch_list = json.loads(c.get("arch_patterns") or "[]")
            except (json.JSONDecodeError, TypeError):
                arch_list = []
            arch_html = " ".join(
                f'<span style="display:inline-block;background:#1a237e;color:#90caf9;padding:2px 8px;border-radius:3px;margin:2px;font-size:12px;">{html_mod.escape(p)}</span>'
                for p in arch_list
            ) or "<em style='color:#555'>None detected</em>"

            schema_section = f"""
<div class="schema-section">
  <h3>Schema Analysis (CC Fingerprinting)</h3>
  <table style="font-size:13px;">
    <tr><td style="color:#555;width:180px;padding:4px 12px 4px 0;">Schema Hash</td>
        <td class="hash">{html_mod.escape(c['schema_hash'])}</td></tr>
    <tr><td style="color:#555;padding:4px 12px 4px 0;">CC Field Density</td>
        <td><strong style="color:#ce93d8;">{cc_pct}%</strong> of response fields are CC-specific ({len(cc_fields_list)} CC fields found)
            <div class="score-bar" style="width:200px;">
              <div class="score-fill" style="width:{min(cc_pct, 100)}%;"></div>
            </div>
        </td></tr>
    <tr><td style="color:#555;padding:4px 12px 4px 0;">CC Fields Found</td>
        <td>{cc_fields_html}</td></tr>
    <tr><td style="color:#555;padding:4px 12px 4px 0;">ULID Fields</td>
        <td>{ulid_count} field(s) contain ULID values</td></tr>
    <tr><td style="color:#555;padding:4px 12px 4px 0;">Architectural Patterns</td>
        <td>{arch_html}</td></tr>
  </table>
</div>"""

        cat = c.get("category", "public")
        html = DETAIL_TEMPLATE.format(
            id=c["id"],
            captured_at=c["captured_at"],
            epoch=c["epoch"],
            category=cat.upper(),
            cat_class=f"cat-{cat}",
            label=html_mod.escape(c["label"]),
            method=c["method"],
            url=html_mod.escape(c["url"]),
            http_status=c["http_status"] or "—",
            response_size=f'{c["response_size"]:,}' if c["response_size"] else "—",
            sha256=c["sha256"] or "—",
            error_row=error_row,
            schema_section=schema_section,
            request_headers=pretty(c["request_headers"]),
            request_body=pretty(c["request_body"]),
            response_headers=pretty(c["response_headers"]),
            response_body=pretty(c["response_body"]),
        )
        self.send_html(html)


# --- Main ---

if __name__ == "__main__":
    init_db()
    load_credentials()

    has_auth = get_access_token() is not None
    public_count = len(PUBLIC_ENDPOINTS)
    auth_count = len(AUTH_ENDPOINTS) if has_auth else 0

    print("=" * 60)
    print("  Parler API Evidence Monitor")
    print("  Case No. 494-07423-2025")
    print("=" * 60)
    print(f"  Database : {Path(DB_FILE).absolute()}")
    print(f"  Web UI   : http://localhost:{PORT}")
    print(f"  Endpoints: {public_count} public + {auth_count} authenticated")
    print(f"  OAuth    : {'Active' if has_auth else 'No credentials (auth endpoints skipped)'}")
    print(f"  Blockchain: {'OriginStamp active' if ORIGINSTAMP_API_KEY else 'No API key (set ORIGINSTAMP_API_KEY)'}")
    print(f"  Schedule : 9:00 AM PT + 6:00 PM PT daily")
    print("=" * 60)

    # Run initial capture immediately
    print("\nRunning initial capture...")
    results = run_all_captures()
    ok = sum(1 for r in results if r.get("http_status") and r["http_status"] < 400)
    err = sum(1 for r in results if r.get("error"))
    print(f"  Captured {len(results)} endpoints ({ok} ok, {err} errors)")
    print(f"\nOpen http://localhost:{PORT} in your browser.")

    # Start background scheduler (9 AM PT + 6 PM PT)
    t = threading.Thread(target=scheduler, daemon=True)
    t.start()

    # Threaded server so captures/refresh don't block the UI
    class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with ThreadedTCPServer(("", PORT), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
