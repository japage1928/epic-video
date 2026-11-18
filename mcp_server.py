#!/usr/bin/env python3
"""Epic Video — public MCP server (remote, Streamable HTTP) + OAuth 2.0 AS.

Stdlib only. Runs beside the Epic Video app (127.0.0.1:8795) and exposes a
subset of its API as MCP tools. Authentication is a real OAuth 2.0
authorization-code + PKCE (S256) flow with dynamic client registration:
the authorize step signs the user in with their existing Epic Video
account (email + password, checked against the app's own login API), and
the issued bearer tokens call the app API with that user's app session.

Public identity (behind the Cloudflare tunnel):
  issuer   https://mcp.epicvideo.lol
  MCP      https://mcp.epicvideo.lol/mcp
Local bind: 127.0.0.1:8796 (env MCP_PORT).

The authorize page also offers "Sign in with Google": this server runs
its own Google OAuth leg using the same Google client as the main site,
and on callback finds-or-creates the matching account in the app's own
database — mirroring the account rules of the app's /auth/google/callback
— then mints an app session exactly the way the app does (stateless
HMAC token signed with the app's EPIC_SECRET_KEY) and completes the
authorization. Google sign-in needs GOOGLE_CLIENT_ID and
GOOGLE_CLIENT_SECRET in this server's .env; without them the Google
button reports "not configured" instead of failing silently.
"""

import base64
import hashlib
import hmac
import html
import http.client
import ipaddress
import json
import os
import secrets
import socket
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "data" / "mcp.db"

HOST = os.environ.get("MCP_HOST", "127.0.0.1")
PORT = int(os.environ.get("MCP_PORT", "8796"))
ISSUER = os.environ.get("MCP_ISSUER", "https://mcp.epicvideo.lol").rstrip("/")
RESOURCE = ISSUER + "/mcp"
APP_API = os.environ.get("EPIC_API_BASE", "http://127.0.0.1:8795").rstrip("/")
SITE = os.environ.get("EPIC_SITE_BASE", "https://epicvideo.lol").rstrip("/")
LEGAL_URL = SITE + "/#terms-section"  # the app's built Terms & Privacy view


def _load_env_file() -> dict:
    """Read BASE/.env (KEY=VALUE lines), the way the main app loads config."""
    out = {}
    p = BASE / ".env"
    if p.exists():
        for line in p.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


_FILE_ENV = _load_env_file()


def cfg(name: str, default: str = "") -> str:
    return os.environ.get(name) or _FILE_ENV.get(name, default)


# Google sign-in for the authorize page: the same Google OAuth client the
# main site uses (its id/secret also belong in the app's .env). The
# redirect URI below must be registered for that client in Google Cloud
# Console, or Google rejects the flow with redirect_uri_mismatch.
GOOGLE_CLIENT_ID = cfg("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = cfg("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = cfg("GOOGLE_REDIRECT_URI", ISSUER + "/auth/google/callback")
# The app's own database and session secret: on Google callback this
# server finds-or-creates the user there and mints an app session
# identical to the app's make_session() (HMAC-signed stateless token).
APP_DB_PATH = cfg("EPIC_APP_DB", "/home/john/epic-video-app/data/epic.db")
EPIC_SECRET_KEY = cfg("EPIC_SECRET_KEY")
GSTATE_TTL = 600

SCOPE = "epicvideo"
ACCESS_TTL = 24 * 3600
REFRESH_TTL = 30 * 86400
CODE_TTL = 600
FLOW_TTL = 600
PROTOCOLS = ["2025-06-18", "2025-03-26", "2024-11-05"]
MAX_BODY = 1_000_000


def now() -> int:
    return int(time.time())


def sha256hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def pkce_challenge(verifier: str) -> str:
    return b64url(hashlib.sha256(verifier.encode()).digest())


# ---------------------------------------------------------------- DB layer

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    (BASE / "data").mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BASE / "data", 0o700)
    except OSError:
        pass
    conn = db()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS clients (
            client_id TEXT PRIMARY KEY,
            secret_hash TEXT,
            client_name TEXT,
            redirect_uris TEXT NOT NULL,
            grant_types TEXT NOT NULL,
            auth_method TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS flows (
            flow_id TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            state TEXT,
            scope TEXT,
            code_challenge TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS codes (
            code_hash TEXT PRIMARY KEY,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            redirect_uri TEXT NOT NULL,
            code_challenge TEXT NOT NULL,
            scope TEXT,
            app_session TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS gstates (
            state_hash TEXT PRIMARY KEY,
            flow_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS tokens (
            access_hash TEXT PRIMARY KEY,
            refresh_hash TEXT,
            client_id TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            app_session TEXT NOT NULL,
            scope TEXT,
            created_at INTEGER NOT NULL,
            access_expires_at INTEGER NOT NULL,
            refresh_expires_at INTEGER NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0
        );
        """
    )
    conn.commit()
    conn.close()
    try:
        os.chmod(DB_PATH, 0o600)
    except OSError:
        pass


# ------------------------------------------------------- Epic Video app API

def app_login(email: str, password: str):
    """POST the app's own login API. Returns (status, payload, session|None)."""
    req = urllib.request.Request(
        APP_API + "/api/auth/login",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode() or "{}")
            set_cookie = resp.headers.get("Set-Cookie") or ""
            status = resp.status
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {}
        return e.code, payload, None
    except Exception:
        return 0, {"error": "app_unreachable"}, None
    session = None
    for part in set_cookie.split(";"):
        part = part.strip()
        if part.startswith("epic_session="):
            session = part.split("=", 1)[1]
            break
    return status, payload, session


def app_call(method: str, path: str, app_session: str, body: dict | None = None):
    """Call the app API as the given user. Returns (status, payload)."""
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Cookie": f"epic_session={app_session}"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(APP_API + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode() or "{}")
        except Exception:
            payload = {"error": "app_error"}
        return e.code, payload
    except Exception:
        return 0, {"error": "app_unreachable"}


def app_db() -> sqlite3.Connection:
    conn = sqlite3.connect(APP_DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def make_app_session(user_id: int) -> str:
    """Mint an app session token identical to the app's make_session(),
    including the user's current session_version ("sv") — the app rejects
    sessions whose sv doesn't match the users row."""
    sv = 0
    conn = app_db()
    try:
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(users)").fetchall()}
        if "session_version" in cols:
            row = conn.execute("SELECT session_version FROM users WHERE id=?", (user_id,)).fetchone()
            if row is None:
                raise ValueError("user not found")
            sv = int(row["session_version"] or 0)
    finally:
        conn.close()
    payload = base64.urlsafe_b64encode(json.dumps(
        {"uid": user_id, "exp": now() + 30 * 86400, "sv": sv}).encode()).decode()
    sig = hmac.new(EPIC_SECRET_KEY.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return payload + "." + sig


def app_user_for_google(sub_id: str, email: str, name, email_verified) -> int:
    """Find-or-create the Epic Video user for a verified Google identity.

    Mirrors the account rules of the app's own /auth/google/callback:
    match on google_sub, else on email (and link the sub), else create a
    fresh free-tier account. An existing password account is never linked
    to Google automatically: raises ValueError("account_exists_use_password").
    """
    if email_verified is not True:
        raise ValueError("email_not_verified")
    t = now()
    conn = app_db()
    try:
        u = conn.execute("SELECT * FROM users WHERE google_sub=?", (sub_id,)).fetchone()
        if not u:
            u = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
            if u and u["password_hash"] and not u["google_sub"]:
                raise ValueError("account_exists_use_password")
            if u and u["google_sub"] and u["google_sub"] != sub_id:
                # Email already linked to a different Google identity: never re-link.
                raise ValueError("account_exists_use_password")
        if u:
            if not u["google_sub"]:
                conn.execute("UPDATE users SET google_sub=? WHERE id=?", (sub_id, u["id"]))
                conn.commit()
            return int(u["id"])
        cur = conn.execute(
            "INSERT INTO users(email,password_hash,google_sub,display_name,created_at,terms_agreed_at) VALUES(?,NULL,?,?,?,?)",
            (email, sub_id, name, t, t))
        uid = cur.lastrowid
        conn.execute(
            "INSERT INTO subscriptions(user_id,tier,status,anchor_ts,quality_mode) VALUES(?,'free','active',?,'720')",
            (uid, t))
        conn.commit()
        return int(uid)
    finally:
        conn.close()


# ------------------------------------------------------------------- tools

TOOLS = [
    {
        "name": "create_video",
        "description": (
            "Generate a short AI video with synced sound from a text prompt using Epic Video. "
            "Videos are 5, 15, 30, 60 or 120 seconds long; anything over 15 seconds is stitched "
            "from chained 5-second clips for consistency. Videos cost tokens per second: 1 token/sec at "
            "480p, 2 tokens/sec at 720p (e.g. a 15-second 480p video costs 15 tokens). Free plans get "
            "15 tokens/week and can make videos up to 15 seconds; 60/120 require the Creator plan "
            "($19.99/mo, 480 tokens/month released 120/week). $4.99/mo = 120 tokens/month released "
            "30/week; $9.99/mo = 240 tokens/month released 60/week. Paid users can also spend top-up "
            "tokens bought on the website. Paid plans can attach a locked character (get its id "
            "from list_characters) so the same character appears in the video. Image-to-video: pass "
            "image_url (a public image URL) and the video will start from that image as its first "
            "frame and animate it — the prompt then describes the motion. Returns a job id — "
            "poll get_job_status until the status is 'done' to get the video URL. Check "
            "get_my_usage first to see the user's tokens left this week/month and top-up balance."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {
                    "type": "string",
                    "minLength": 1,
                    "description": "What the video should show, e.g. 'a red sports car on a coastal highway at golden hour, waves crashing'. With image_url, describe the motion instead, e.g. 'the car pulls away and speeds down the coast, camera tracking'.",
                },
                "image_url": {
                    "type": "string",
                    "description": "Optional public URL of an image (JPEG, PNG or WebP, up to 10 MB) to animate: the video starts from this image as its first frame (image-to-video). The server fetches and validates the image; private/loopback addresses are rejected.",
                },
                "duration_s": {
                    "type": "integer",
                    "enum": [5, 15, 30, 60, 120],
                    "default": 5,
                    "description": "Length in seconds: 5, 15, 30, 60 or 120. Free plans: up to 15. 60/120 require the Creator plan ($19.99/mo). Cost is duration x rate: 1 token/sec at 480p, 2 tokens/sec at 720p.",
                },
                "character_id": {
                    "type": "integer",
                    "description": "Optional id of a locked character from list_characters, so that character appears in the video. Paid plans only.",
                },
                "quality": {
                    "type": "string",
                    "enum": ["480", "720"],
                    "description": "Requested quality. The actual quality is set by the user's plan (free and $4.99 plans render 480p; the $9.99 and Creator plans use the user's 720p/480p switch). The returned job shows the real quality used.",
                },
            },
            "required": ["prompt"],
        },
    },
    {
        "name": "get_job_status",
        "description": (
            "Check the status of an Epic Video generation job by its job id. Returns the status "
            "(queued, rendering, upscaling, done, or failed) and, when done, the video URL."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "integer", "description": "The job id returned by create_video."}
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "list_my_videos",
        "description": (
            "List the signed-in Epic Video user's finished videos, newest first, with playback URLs."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                    "default": 20,
                    "description": "Maximum number of videos to return.",
                }
            },
        },
    },
    {
        "name": "get_my_usage",
        "description": (
            "Show the signed-in Epic Video user's plan tier, plan tokens left in the current rolling "
            "7-day window and this month, top-up (bonus) token balance, and per-second token rates "
            "(1 token/sec at 480p, 2 tokens/sec at 720p)."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "list_characters",
        "description": (
            "List the Epic Video characters available to the signed-in user — their own locked "
            "characters plus shared presets — for use with create_video's character_id."
        ),
        "inputSchema": {"type": "object", "properties": {}},
    },
]


def tool_result(obj, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text", "text": json.dumps(obj, indent=2)}],
        "isError": is_error,
    }


def abs_url(path):
    if not path:
        return None
    return SITE + path if path.startswith("/") else path


class ToolContext:
    """Per-call context: the token row of the authenticated user."""

    def __init__(self, token_row):
        self.token = token_row

    def call_app(self, method, path, body=None):
        status, payload = app_call(method, path, self.token["app_session"], body)
        if status == 401:
            # The user's app session died (30-day cookie) — force re-auth.
            conn = db()
            conn.execute("UPDATE tokens SET revoked=1 WHERE access_hash=?", (self.token["access_hash"],))
            conn.commit()
            conn.close()
            return 401, {
                "error": "app_session_expired",
                "message": "Your Epic Video sign-in has expired. Reconnect Epic Video (run the authorization flow again) and try again.",
            }
        return status, payload


MAX_IMAGE_BYTES = 10 * 1024 * 1024  # same decoded cap as the app API


_IMAGE_UA = "Mozilla/5.0 (compatible; EpicVideo-MCP/1.0; +https://epicvideo.lol)"
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
MAX_IMAGE_REDIRECTS = 4
IMAGE_FETCH_TIMEOUT = 20  # seconds, total across all redirect hops


def _resolve_public(hostname: str) -> list:
    """Resolve hostname and return its IP strings. Every resolved address
    must be globally routable, so image_url can't be used to reach this
    server's own network (a host with ANY non-global address is rejected)."""
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except Exception:
        raise ValueError("image_url host could not be resolved")
    ips = []
    for info in infos:
        ip = info[4][0].split("%", 1)[0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            raise ValueError("image_url must point to a public address")
        if not addr.is_global:
            raise ValueError("image_url must point to a public address")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise ValueError("image_url host could not be resolved")
    return ips


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTP connection to a pre-validated IP; Host header stays the name."""

    def __init__(self, host, port, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self.host = host
        self.port = port
        self.pinned_ip = pinned_ip
        self.timeout = timeout

    def connect(self):
        self.sock = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)
        if self._tunnel_host:
            self._tunnel()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection to a pre-validated IP; SNI and certificate
    verification use the original hostname."""

    def __init__(self, host, port, pinned_ip, timeout):
        super().__init__(host, port, timeout=timeout)
        self.host = host
        self.port = port
        self.pinned_ip = pinned_ip
        self.timeout = timeout

    def connect(self):
        raw = socket.create_connection((self.pinned_ip, self.port), self.timeout, self.source_address)
        try:
            self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
        except Exception:
            raw.close()
            raise


def _fetch_once(url: str, deadline: float):
    """One GET hop against a validated, pinned address.
    Returns (status, headers_lowercased, body_or_None_for_redirects)."""
    try:
        parts = urllib.parse.urlparse(url)
        port = parts.port
    except ValueError:
        raise ValueError("image_url must be a public http(s) URL")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise ValueError("image_url must be a public http(s) URL")
    hostname = parts.hostname
    if port is None:
        port = 443 if parts.scheme == "https" else 80
    ips = _resolve_public(hostname)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ValueError("image_url fetch timed out")
    timeout = max(1, remaining)
    cls = _PinnedHTTPSConnection if parts.scheme == "https" else _PinnedHTTPConnection
    conn = cls(hostname, port, ips[0], timeout)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request("GET", path, headers={
            "Host": parts.netloc.rsplit("@", 1)[-1],
            "User-Agent": _IMAGE_UA,
            "Accept": "image/*",
            "Connection": "close",
        })
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        if resp.status in _REDIRECT_STATUSES:
            return resp.status, headers, None
        body = resp.read(MAX_IMAGE_BYTES + 1)
        return resp.status, headers, body
    finally:
        conn.close()


def fetch_image_url(url: str) -> bytes:
    """Fetch and validate an image for image-to-video. Returns raw bytes;
    raises ValueError with a client-facing message on any problem.

    Every hop resolves the host, requires all its addresses to be global,
    and connects to that exact (pinned) IP — no DNS rebinding window, no
    proxy env vars (http.client ignores them), redirects re-validated."""
    deadline = time.monotonic() + IMAGE_FETCH_TIMEOUT
    current = url
    for _hop in range(MAX_IMAGE_REDIRECTS + 1):
        status, headers, data = _fetch_once(current, deadline)
        if status in _REDIRECT_STATUSES:
            location = headers.get("location")
            if not location:
                raise ValueError(f"image_url fetch failed (HTTP {status} without a Location header)")
            current = urllib.parse.urljoin(current, location)
            continue
        if status != 200:
            raise ValueError(f"image_url fetch failed (HTTP {status})")
        ctype = (headers.get("content-type") or "").split(";")[0].strip().lower()
        if not ctype.startswith("image/"):
            raise ValueError(f"image_url did not return an image (Content-Type: {ctype or 'missing'})")
        break
    else:
        raise ValueError("image_url redirected too many times")
    if len(data) > MAX_IMAGE_BYTES:
        raise ValueError("image is too large: max 10 MB")
    if not (data[:3] == b"\xff\xd8\xff" or data[:8] == b"\x89PNG\r\n\x1a\n"
            or (data[:4] == b"RIFF" and data[8:12] == b"WEBP")):
        raise ValueError("image_url did not return a JPEG, PNG or WebP image")
    return data


# Tokens per second of video by render quality (mirrors the app's usage "rates").
TOKEN_RATES = {"480": 1, "720": 2}
# Display name and token grant per tier.
PLAN_GRANTS = {
    "trial": ("$1 trial week", " (30 tokens)"),
    "plan499": ("$4.99/mo", " (120 tokens/month, released 30/week)"),
    "plan999": ("$9.99/mo", " (240 tokens/month, released 60/week)"),
    "plan1999": ("Creator $19.99/mo", " (480 tokens/month, released 120/week)"),
}


def tool_create_video(ctx: ToolContext, args: dict) -> dict:
    prompt = (args.get("prompt") or "").strip()
    if not prompt:
        return tool_result({"error": "prompt_required", "message": "A text prompt is required."}, True)
    duration = args.get("duration_s", 5)
    if duration not in (5, 15, 30, 60, 120):
        return tool_result({"error": "invalid_duration", "message": "duration_s must be 5, 15, 30, 60 or 120."}, True)
    body = {"prompt": prompt, "duration_s": duration}
    if args.get("character_id") is not None:
        body["character_id"] = args["character_id"]
    if args.get("image_url"):
        try:
            img = fetch_image_url(str(args["image_url"]))
        except ValueError as e:
            return tool_result({"error": "invalid_image_url", "message": str(e)}, True)
        except Exception as e:
            print(f"[mcp] image fetch failed: {type(e).__name__}: {e}", flush=True)
            return tool_result(
                {"error": "image_fetch_failed",
                 "message": "Image could not be fetched from that URL."}, True)
        body["image_base64"] = base64.b64encode(img).decode()
    status, payload = ctx.call_app("POST", "/api/jobs", body)
    if status != 201:
        cta = payload.get("cta") if isinstance(payload, dict) else None
        if isinstance(cta, dict) and cta.get("plan"):
            upgrade_url = SITE + "/?upgrade=" + str(cta["plan"])
            payload["upgrade_url"] = upgrade_url
            if not payload.get("message"):
                if payload.get("error") == "allotment_exceeded":
                    payload["message"] = (
                        f"You've used this plan's allotment for now. Upgrade at {upgrade_url} to keep creating."
                    )
                else:
                    payload["message"] = f"That needs a different plan — see {upgrade_url}"
        if isinstance(cta, dict) and cta.get("topups"):
            topup_note = (
                f"You can also buy top-up tokens on the website ({SITE}): 150 tokens for $10 or "
                "300 tokens for $20, and they never expire."
            )
            payload["message"] = (
                (str(payload["message"]).rstrip() + " " + topup_note) if payload.get("message") else topup_note
            )
        return tool_result(payload, True)
    job = payload
    tokens_charged = job.get("tokens")
    if tokens_charged is None:
        try:
            tokens_charged = int(job.get("duration_s") or duration) * TOKEN_RATES.get(str(job.get("quality")), 1)
        except (TypeError, ValueError):
            tokens_charged = None
    out = {
        "job_id": job.get("id"),
        "status": job.get("status"),
        "duration_s": job.get("duration_s"),
        "quality": job.get("quality"),
        "tokens_charged": tokens_charged,
        "usage": job.get("usage"),
        "note": "Poll get_job_status with this job_id until status is 'done'.",
    }
    if args.get("quality") and args["quality"] != job.get("quality"):
        out["quality_note"] = (
            f"You requested {args['quality']}p, but your plan renders at {job.get('quality')}p."
        )
    if job.get("has_image"):
        out["image_to_video"] = True
    return tool_result(out)


def tool_get_job_status(ctx: ToolContext, args: dict) -> dict:
    job_id = args.get("job_id")
    if not isinstance(job_id, int):
        return tool_result({"error": "job_id_required", "message": "job_id (integer) is required."}, True)
    status, payload = ctx.call_app("GET", f"/api/jobs/{job_id}")
    if status != 200:
        return tool_result(payload, True)
    out = {
        "job_id": payload.get("id"),
        "status": payload.get("status"),
        "duration_s": payload.get("duration_s"),
        "clips_done": payload.get("clips_done"),
        "clips_total": payload.get("clips_total"),
        "quality": payload.get("quality"),
        "prompt": payload.get("user_prompt"),
        "image_to_video": bool(payload.get("has_image")),
        "character_id": payload.get("character_id"),
        "created_at": payload.get("created_at"),
        "finished_at": payload.get("finished_at"),
        "error": payload.get("error"),
    }
    if payload.get("status") == "done":
        out["video_url"] = abs_url(payload.get("video_url"))
        out["poster_url"] = abs_url(payload.get("poster_url"))
    return tool_result(out)


def tool_list_my_videos(ctx: ToolContext, args: dict) -> dict:
    limit = args.get("limit", 20)
    if not isinstance(limit, int) or limit < 1:
        limit = 20
    limit = min(limit, 100)
    status, payload = ctx.call_app("GET", "/api/library")
    if status != 200:
        return tool_result(payload, True)
    videos = []
    for j in (payload.get("jobs") or [])[:limit]:
        videos.append(
            {
                "job_id": j.get("id"),
                "prompt": j.get("prompt"),
                "duration_s": j.get("duration_s"),
                "quality": j.get("quality"),
                "character_name": j.get("character_name"),
                "created_at": j.get("created_at"),
                "video_url": abs_url(j.get("video_url")),
                "poster_url": abs_url(j.get("poster_url")),
                "watermark": j.get("watermark"),
            }
        )
    return tool_result({"videos": videos, "count": len(videos)})


def tool_get_my_usage(ctx: ToolContext, args: dict) -> dict:
    status, usage = ctx.call_app("GET", "/api/usage")
    if status != 200:
        return tool_result(usage, True)
    _, me = ctx.call_app("GET", "/api/me")
    week = usage.get("week") or {}
    month = usage.get("month") or {}
    tier = usage.get("tier")
    rates = usage.get("rates") or {k: v for k, v in TOKEN_RATES.items()}
    bonus = usage.get("bonus_balance") or 0
    wt = week.get("tokens_left")
    mt = month.get("tokens_left")
    rate_text = f"Rates: {rates.get('480', 1)} token/sec at 480p, {rates.get('720', 2)} tokens/sec at 720p."
    if tier == "free":
        wl = week.get("videos_left_in_mode")
        if wl is not None:
            summary = f"Free plan: {wl} watermarked video(s) up to 15 seconds left in the current rolling 7-day window"
            summary += f" ({wt} of {week.get('cap_tokens', 15)} tokens left)." if wt is not None else "."
        else:
            summary = (
                f"Free plan: {wt} of {week.get('cap_tokens', 15)} tokens left in the current rolling 7-day "
                "window for watermarked videos up to 15 seconds."
            )
    elif usage.get("status") == "trialing":
        # Trialing users are reported under their target plan tier (e.g. plan499), but the
        # trial-week grant is 30 tokens total, so don't describe the paid monthly grant.
        plan, grant = PLAN_GRANTS["trial"]
        trial_left = wt if wt is not None else mt
        summary = f"{plan}{grant}, rendering at {usage.get('quality_mode')}p mode"
        summary += f": {trial_left} tokens left." if trial_left is not None else "."
        summary += f" Top-up (bonus) balance: {bonus} tokens."
    else:
        plan, grant = PLAN_GRANTS.get(tier, (tier, ""))
        parts = [f"{plan} plan{grant}, rendering at {usage.get('quality_mode')}p mode:"]
        if wt is not None:
            parts.append(f"{wt} of {week.get('cap_tokens')} plan tokens left in the current rolling 7-day window")
        if mt is not None and month.get("cap_tokens") is not None:
            parts.append(f"{mt} of {month.get('cap_tokens')} left this month")
        summary = parts[0] + " " + ", ".join(parts[1:]) + "."
        summary += f" Top-up (bonus) balance: {bonus} tokens."
    summary += " " + rate_text
    return tool_result(
        {
            "tier": tier,
            "display_name": me.get("display_name"),
            "quality_mode": usage.get("quality_mode"),
            "week": week,
            "month": month,
            "bonus_balance": bonus,
            "rates": rates,
            "summary": summary,
        }
    )


def tool_list_characters(ctx: ToolContext, args: dict) -> dict:
    status, payload = ctx.call_app("GET", "/api/characters")
    if status != 200:
        return tool_result(payload, True)
    chars = []
    for c in payload.get("characters") or []:
        chars.append(
            {
                "id": c.get("id"),
                "name": c.get("name"),
                "description": c.get("description"),
                "status": c.get("status"),
                "is_preset": c.get("is_preset"),
                "reference_sheet_ready": bool(c.get("sheet_images")),
            }
        )
    return tool_result({"characters": chars, "count": len(chars)})


TOOL_FUNCS = {
    "create_video": tool_create_video,
    "get_job_status": tool_get_job_status,
    "list_my_videos": tool_list_my_videos,
    "get_my_usage": tool_get_my_usage,
    "list_characters": tool_list_characters,
}


# ------------------------------------------------------------- OAuth pages

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize — Epic Video</title>
<style>
  body {{ background:#0d1117; color:#e8f0ea; font-family:system-ui,sans-serif;
         display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }}
  .card {{ background:#151b24; border:1px solid #26303d; border-radius:14px;
          padding:32px; width:min(92vw,380px); }}
  h1 {{ font-size:20px; margin:0 0 6px; }} h1 span {{ color:#7fd6a4; }}
  p {{ color:#9fb3a8; font-size:14px; line-height:1.5; }}
  label {{ display:block; font-size:13px; margin:16px 0 6px; color:#c8d6cd; }}
  input {{ width:100%; box-sizing:border-box; padding:11px 12px; border-radius:9px;
          border:1px solid #33404e; background:#0d1117; color:#b9e8cc; font-size:15px; }}
  button {{ width:100%; margin-top:22px; padding:12px; border:0; border-radius:9px;
           background:#2f9e63; color:#fff; font-size:15px; font-weight:600; cursor:pointer; }}
  .err {{ background:#3a1d1d; border:1px solid #7a3535; color:#f0b9b9;
         padding:10px 12px; border-radius:9px; font-size:13px; }}
  .divider {{ display:flex; align-items:center; gap:10px; color:#5f7267;
         font-size:12px; margin:22px 0 2px; }}
  .divider::before, .divider::after {{ content:""; flex:1;
         border-top:1px solid #26303d; }}
  a.gbtn {{ display:block; text-align:center; margin-top:14px; padding:12px;
         border-radius:9px; background:#ffffff; color:#1f2937; font-size:15px;
         font-weight:600; text-decoration:none; }}
  a {{ color:#7fd6a4; }}
</style></head><body>
<div class="card">
  <h1>Epic <span>Video</span></h1>
  <p><strong>{client_name}</strong> wants to connect to your Epic Video account
     so it can generate videos and read your library and usage on your behalf.</p>
  {error_block}
  <form method="POST" action="/authorize/login">
    <input type="hidden" name="flow_id" value="{flow_id}">
    <label for="email">Epic Video email</label>
    <input id="email" name="email" type="email" autocomplete="username" required>
    <label for="password">Password</label>
    <input id="password" name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign in and authorize</button>
  </form>
  <div class="divider">or</div>
  <a class="gbtn" href="/authorize/google?flow_id={flow_id}">Sign in with Google</a>
  <p>Use the email and password of your account at
     <a href="{site}">{site}</a>. No account yet? Create one there first, then come back.</p>
</div></body></html>"""


def error_page(title: str, msg: str) -> bytes:
    return (
        "<!DOCTYPE html><html><head><meta charset='utf-8'><title>"
        + html.escape(title)
        + "</title></head><body style='background:#0d1117;color:#e8f0ea;font-family:system-ui;padding:40px'>"
        + f"<h2>{html.escape(title)}</h2><p>{html.escape(msg)}</p></body></html>"
    ).encode()


# --------------------------------------------------------------- throttling

_login_fails: dict[str, list[int]] = {}


def login_throttled(ip: str) -> bool:
    attempts = [t for t in _login_fails.get(ip, []) if now() - t < 300]
    _login_fails[ip] = attempts
    return len(attempts) >= 10


def note_login_fail(ip: str) -> None:
    _login_fails.setdefault(ip, []).append(now())


_registrations: dict[str, list[int]] = {}
REGISTER_LIMIT = 10  # per client IP per hour


def register_throttled(ip: str) -> bool:
    t = now()
    if len(_registrations) > 10000:  # bound memory: drop idle buckets
        for k in [k for k, v in _registrations.items() if not v or t - v[-1] >= 3600]:
            _registrations.pop(k, None)
    recent = [x for x in _registrations.get(ip, []) if t - x < 3600]
    if recent:
        _registrations[ip] = recent
    else:
        _registrations.pop(ip, None)
    return len(recent) >= REGISTER_LIMIT


def note_register(ip: str) -> None:
    _registrations.setdefault(ip, []).append(now())


def _redirect_uri_ok(uri) -> bool:
    """https:// anywhere; plain http:// only for loopback (native apps)."""
    if not isinstance(uri, str):
        return False
    try:
        parts = urllib.parse.urlparse(uri)
        parts.port  # raises ValueError on a malformed port
    except ValueError:
        return False
    if parts.scheme == "https":
        return bool(parts.hostname)
    if parts.scheme == "http":
        return parts.hostname in ("localhost", "127.0.0.1", "::1")
    return False


# ------------------------------------------------------------------ handler

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "same-origin",
    "Strict-Transport-Security": "max-age=31536000",
    "Content-Security-Policy": "frame-ancestors 'none'; object-src 'none'; base-uri 'self'",
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "EpicVideoMCP/1.0"

    def log_message(self, fmt, *args):
        # Paths only — never bodies, never tokens.
        print(f"[mcp] {self.address_string()} {self.command} {self.path.split('?')[0]}", flush=True)

    # -- plumbing
    def _client_ip(self) -> str:
        """Real client address: Cloudflare's header when behind the tunnel."""
        return (self.headers.get("CF-Connecting-IP") or "").strip() or self.address_string()

    def _send(self, code, body: bytes, ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _json(self, code, obj, extra=None):
        self._send(code, json.dumps(obj).encode(), "application/json", extra)

    def _read_body(self) -> bytes:
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            return b""
        return self.rfile.read(n) if n else b""

    def _body_json(self) -> dict:
        raw = self._read_body()
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode())
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _body_form(self) -> dict:
        raw = self._read_body().decode(errors="replace")
        qs = urllib.parse.parse_qs(raw)
        return {k: v[0] for k, v in qs.items()}

    def _cookies(self) -> dict:
        out = {}
        for part in (self.headers.get("Cookie") or "").split(";"):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                out[k] = v
        return out

    # -- routing
    def do_GET(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/":
                return self._json(200, {
                    "name": "Epic Video MCP",
                    "description": "Generate short AI videos with sound from text prompts.",
                    "mcp_endpoint": RESOURCE,
                    "oauth_authorization_server": ISSUER + "/.well-known/oauth-authorization-server",
                    "website": SITE,
                    "terms": LEGAL_URL,
                    "privacy": LEGAL_URL,
                })
            if path == "/healthz":
                return self._json(200, {"ok": True, "service": "epic-video-mcp"})
            if path == "/.well-known/oauth-authorization-server":
                return self._json(200, {
                    "issuer": ISSUER,
                    "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token",
                    "registration_endpoint": ISSUER + "/register",
                    "revocation_endpoint": ISSUER + "/revoke",
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code", "refresh_token"],
                    "code_challenge_methods_supported": ["S256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post", "none"],
                    "scopes_supported": [SCOPE],
                    "service_documentation": SITE,
                })
            if path in ("/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"):
                return self._json(200, {
                    "resource": RESOURCE,
                    "authorization_servers": [ISSUER],
                    "bearer_methods_supported": ["header"],
                    "scopes_supported": [SCOPE],
                    "resource_documentation": SITE,
                })
            if path == "/authorize":
                return self.authorize_get()
            if path == "/authorize/google":
                return self.authorize_google()
            if path == "/auth/google/callback":
                return self.google_callback()
            if path == "/mcp":
                return self._json(405, {"error": "method_not_allowed", "message": "POST JSON-RPC to this endpoint."}, {"Allow": "POST"})
            return self._json(404, {"error": "not_found"})
        except BrokenPipeError:
            pass
        except Exception as e:  # keep the server up; surface a clean 500
            print(f"[mcp] error on GET {path}: {e!r}", flush=True)
            try:
                return self._json(500, {"error": "server_error"})
            except Exception:
                pass

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        try:
            if path == "/register":
                return self.register()
            if path == "/authorize/login":
                return self.authorize_login()
            if path == "/token":
                return self.token()
            if path == "/revoke":
                return self.revoke()
            if path == "/mcp":
                return self.mcp_post()
            return self._json(404, {"error": "not_found"})
        except BrokenPipeError:
            pass
        except Exception as e:
            print(f"[mcp] error on POST {path}: {e!r}", flush=True)
            try:
                return self._json(500, {"error": "server_error"})
            except Exception:
                pass

    def do_DELETE(self):
        path = urllib.parse.urlparse(self.path).path
        if path == "/mcp":
            return self._json(405, {"error": "method_not_allowed", "message": "This server is stateless; there is no session to delete."}, {"Allow": "POST"})
        return self._json(404, {"error": "not_found"})

    # ------------------------------------------------------- OAuth: register
    def register(self):
        ip = self._client_ip()
        if register_throttled(ip):
            return self._json(429, {"error": "rate_limited"})
        try:
            pconn = db()
            pconn.execute("DELETE FROM codes WHERE created_at < ?", (now() - 86400,))
            pconn.execute("DELETE FROM tokens WHERE refresh_expires_at < ?", (now(),))
            pconn.commit()
            pconn.close()
        except Exception as e:
            print(f"[mcp] register purge failed: {e!r}", flush=True)
        body = self._body_json()
        redirect_uris = body.get("redirect_uris") or []
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return self._json(400, {"error": "invalid_redirect_uri", "error_description": "redirect_uris (non-empty list) is required."})
        for uri in redirect_uris:
            if not _redirect_uri_ok(uri):
                return self._json(400, {"error": "invalid_redirect_uri", "error_description": f"Bad redirect URI: {uri!r} (https required; http only for localhost loopback)."})
        grant_types = body.get("grant_types") or ["authorization_code"]
        if "authorization_code" not in grant_types:
            grant_types.append("authorization_code")
        auth_method = body.get("token_endpoint_auth_method") or "client_secret_post"
        if auth_method not in ("client_secret_basic", "client_secret_post", "none"):
            auth_method = "client_secret_post"
        client_id = "evc_" + secrets.token_urlsafe(18)
        client_secret = None if auth_method == "none" else secrets.token_urlsafe(32)
        conn = db()
        conn.execute(
            "INSERT INTO clients (client_id, secret_hash, client_name, redirect_uris, grant_types, auth_method, created_at) VALUES (?,?,?,?,?,?,?)",
            (client_id, sha256hex(client_secret) if client_secret else None,
             str(body.get("client_name") or "MCP client")[:120],
             json.dumps(redirect_uris), json.dumps(grant_types), auth_method, now()),
        )
        conn.commit()
        conn.close()
        note_register(ip)
        resp = {
            "client_id": client_id,
            "client_id_issued_at": now(),
            "client_secret_expires_at": 0,
            "redirect_uris": redirect_uris,
            "grant_types": grant_types,
            "response_types": body.get("response_types") or ["code"],
            "token_endpoint_auth_method": auth_method,
            "client_name": body.get("client_name") or "MCP client",
            "scope": SCOPE,
        }
        if client_secret:
            resp["client_secret"] = client_secret
        return self._json(201, resp)

    # ------------------------------------------------------ OAuth: authorize
    def _get_client(self, client_id):
        conn = db()
        row = conn.execute("SELECT * FROM clients WHERE client_id=?", (client_id,)).fetchone()
        conn.close()
        return row

    def authorize_get(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        g = lambda k: (qs.get(k) or [None])[0]
        client_id, redirect_uri = g("client_id"), g("redirect_uri")
        response_type, state = g("response_type"), g("state")
        code_challenge, ccm = g("code_challenge"), g("code_challenge_method")
        resource = g("resource")
        client = self._get_client(client_id) if client_id else None
        if not client:
            return self._send(400, error_page("Unknown client", "This authorization link names a client that is not registered. Register the client first, then retry."), "text/html")
        registered = json.loads(client["redirect_uris"])
        if not redirect_uri or redirect_uri not in registered:
            return self._send(400, error_page("Bad redirect", "The redirect URI in this authorization link does not match the client's registered URIs, so the request was stopped."), "text/html")

        def deny(error, desc):
            q = {"error": error, "error_description": desc}
            if state:
                q["state"] = state
            loc = redirect_uri + ("&" if "?" in redirect_uri else "?") + urllib.parse.urlencode(q)
            return self._send(302, b"", "text/html", {"Location": loc})

        if response_type != "code":
            return deny("unsupported_response_type", "Only response_type=code is supported.")
        if not code_challenge or ccm != "S256":
            return deny("invalid_request", "PKCE with code_challenge_method=S256 is required.")
        if resource and resource != RESOURCE:
            return deny("invalid_target", f"The resource parameter must be {RESOURCE}.")
        flow_id = secrets.token_urlsafe(24)
        conn = db()
        conn.execute("DELETE FROM flows WHERE created_at < ?", (now() - FLOW_TTL,))
        conn.execute(
            "INSERT INTO flows (flow_id, client_id, redirect_uri, state, scope, code_challenge, created_at) VALUES (?,?,?,?,?,?,?)",
            (flow_id, client_id, redirect_uri, state, g("scope") or SCOPE, code_challenge, now()),
        )
        conn.commit()
        conn.close()
        page = LOGIN_PAGE.format(
            client_name=html.escape(client["client_name"] or "An app"),
            error_block="",
            flow_id=flow_id,
            site=SITE,
        )
        cookie = f"epic_mcp_flow={flow_id}; HttpOnly; Path=/; Max-Age={FLOW_TTL}; SameSite=Lax"
        if ISSUER.startswith("https://"):
            cookie += "; Secure"
        return self._send(200, page.encode(), "text/html", {"Set-Cookie": cookie})

    def authorize_login(self):
        form = self._body_form()
        flow_id = form.get("flow_id") or ""
        email = (form.get("email") or "").strip()
        password = form.get("password") or ""
        # Behind the tunnel every request arrives from 127.0.0.1, so key the
        # throttle on the real client (Cloudflare's header) plus the email.
        throttle_key = self._client_ip() + "|" + email.lower()
        if self._cookies().get("epic_mcp_flow") != flow_id or not flow_id:
            return self._send(400, error_page("Session expired", "This sign-in form is no longer valid. Start the authorization again from your app."), "text/html")
        conn = db()
        flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        conn.close()
        if not flow or now() - flow["created_at"] > FLOW_TTL:
            return self._send(400, error_page("Session expired", "This authorization request expired. Start again from your app."), "text/html")
        client = self._get_client(flow["client_id"])

        def render_error(msg, code=401):
            page = LOGIN_PAGE.format(
                client_name=html.escape((client["client_name"] if client else None) or "An app"),
                error_block=f'<div class="err">{html.escape(msg)}</div>',
                flow_id=flow_id,
                site=SITE,
            )
            return self._send(code, page.encode(), "text/html")

        if login_throttled(throttle_key):
            return render_error("Too many failed attempts. Wait a few minutes and try again.", 429)
        status, payload, session = app_login(email, password)
        if status != 200 or not session or not payload.get("id"):
            note_login_fail(throttle_key)
            return render_error("That email and password did not match an Epic Video account. Try again.")
        code = secrets.token_urlsafe(32)
        conn = db()
        conn.execute("DELETE FROM flows WHERE flow_id=?", (flow_id,))
        conn.execute(
            "INSERT INTO codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, app_session, created_at, used) VALUES (?,?,?,?,?,?,?,?,0)",
            (sha256hex(code), flow["client_id"], int(payload["id"]), flow["redirect_uri"],
             flow["code_challenge"], flow["scope"], session, now()),
        )
        conn.commit()
        conn.close()
        q = {"code": code}
        if flow["state"]:
            q["state"] = flow["state"]
        loc = flow["redirect_uri"] + ("&" if "?" in flow["redirect_uri"] else "?") + urllib.parse.urlencode(q)
        return self._send(302, b"", "text/html", {"Location": loc})

    # ------------------------------------------------- OAuth: Google leg
    def _flow_or_none(self, flow_id):
        conn = db()
        flow = conn.execute("SELECT * FROM flows WHERE flow_id=?", (flow_id,)).fetchone()
        conn.close()
        if not flow or now() - flow["created_at"] > FLOW_TTL:
            return None
        return flow

    def _complete_authorize(self, flow, user_id, app_session):
        """Issue the authorization code for a signed-in user and redirect
        back to the MCP client (same code row the password path writes)."""
        code = secrets.token_urlsafe(32)
        conn = db()
        conn.execute("DELETE FROM flows WHERE flow_id=?", (flow["flow_id"],))
        conn.execute(
            "INSERT INTO codes (code_hash, client_id, user_id, redirect_uri, code_challenge, scope, app_session, created_at, used) VALUES (?,?,?,?,?,?,?,?,0)",
            (sha256hex(code), flow["client_id"], int(user_id), flow["redirect_uri"],
             flow["code_challenge"], flow["scope"], app_session, now()),
        )
        conn.commit()
        conn.close()
        q = {"code": code}
        if flow["state"]:
            q["state"] = flow["state"]
        loc = flow["redirect_uri"] + ("&" if "?" in flow["redirect_uri"] else "?") + urllib.parse.urlencode(q)
        return self._send(302, b"", "text/html", {"Location": loc})

    def authorize_google(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        flow_id = (qs.get("flow_id") or [None])[0]
        if not flow_id or self._cookies().get("epic_mcp_flow") != flow_id:
            return self._send(400, error_page("Session expired", "This sign-in link is no longer valid. Start the authorization again from your app."), "text/html")
        if not self._flow_or_none(flow_id):
            return self._send(400, error_page("Session expired", "This authorization request expired. Start again from your app."), "text/html")
        if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
            return self._send(503, error_page("Google sign-in is not configured yet", "Google sign-in has not been configured for Epic Video yet. For now, use your Epic Video email and password on the sign-in page."), "text/html")
        if not EPIC_SECRET_KEY:
            return self._send(503, error_page("Google sign-in is not configured yet", "Google sign-in is missing its session configuration. For now, use your Epic Video email and password on the sign-in page."), "text/html")
        state = secrets.token_urlsafe(24)
        conn = db()
        conn.execute("DELETE FROM gstates WHERE created_at < ?", (now() - GSTATE_TTL,))
        conn.execute("INSERT INTO gstates (state_hash, flow_id, created_at) VALUES (?,?,?)",
                     (sha256hex(state), flow_id, now()))
        conn.commit()
        conn.close()
        params = urllib.parse.urlencode({
            "client_id": GOOGLE_CLIENT_ID, "redirect_uri": GOOGLE_REDIRECT_URI,
            "response_type": "code", "scope": "openid email profile",
            "state": state, "access_type": "online", "prompt": "select_account"})
        cookie = f"epic_mcp_gstate={state}; HttpOnly; Path=/; Max-Age={GSTATE_TTL}; SameSite=Lax"
        if ISSUER.startswith("https://"):
            cookie += "; Secure"
        return self._send(302, b"", "text/html", {
            "Location": "https://accounts.google.com/o/oauth2/v2/auth?" + params,
            "Set-Cookie": cookie})

    def google_callback(self):
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        g = lambda k: (qs.get(k) or [None])[0]
        if g("error"):
            return self._send(400, error_page("Google sign-in did not complete", "Google reported: " + str(g("error")) + ". Start the authorization again from your app and try again."), "text/html")
        state = g("state")
        if not state or self._cookies().get("epic_mcp_gstate") != state:
            return self._send(400, error_page("Session expired", "This Google sign-in is no longer valid. Start the authorization again from your app."), "text/html")
        conn = db()
        gs = conn.execute("SELECT * FROM gstates WHERE state_hash=?", (sha256hex(state),)).fetchone()
        if gs:
            conn.execute("DELETE FROM gstates WHERE state_hash=?", (sha256hex(state),))
            conn.commit()
        conn.close()
        if not gs or now() - gs["created_at"] > GSTATE_TTL:
            return self._send(400, error_page("Session expired", "This Google sign-in expired. Start the authorization again from your app."), "text/html")
        flow = self._flow_or_none(gs["flow_id"])
        if not flow:
            return self._send(400, error_page("Session expired", "This authorization request expired. Start again from your app."), "text/html")
        code = g("code")
        if not code:
            return self._send(400, error_page("Google sign-in failed", "Google did not return an authorization code. Start again from your app."), "text/html")
        try:
            data = urllib.parse.urlencode({
                "code": code, "client_id": GOOGLE_CLIENT_ID, "client_secret": GOOGLE_CLIENT_SECRET,
                "redirect_uri": GOOGLE_REDIRECT_URI, "grant_type": "authorization_code"}).encode()
            req = urllib.request.Request("https://oauth2.googleapis.com/token", data=data, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                tok = json.loads(resp.read().decode())
        except Exception as e:
            print(f"[mcp] google token exchange failed: {e!r}", flush=True)
            return self._send(502, error_page("Google sign-in failed", "Could not complete the exchange with Google. Start again from your app."), "text/html")
        # Verify the ID token with Google: audience, issuer, expiry.
        info = None
        id_token = tok.get("id_token") if isinstance(tok, dict) else None
        if id_token:
            try:
                ti_url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": id_token})
                with urllib.request.urlopen(urllib.request.Request(ti_url), timeout=30) as resp:
                    ti = json.loads(resp.read().decode())
                if (isinstance(ti, dict)
                        and ti.get("aud") == GOOGLE_CLIENT_ID
                        and ti.get("iss") in ("accounts.google.com", "https://accounts.google.com")
                        and int(ti.get("exp") or 0) > now()):
                    info = ti
                else:
                    print("[mcp] google id_token rejected (aud/iss/exp mismatch)", flush=True)
            except Exception as e:
                print(f"[mcp] google tokeninfo check failed: {e!r}", flush=True)
        else:
            print("[mcp] google token response had no id_token", flush=True)
        if info is None:
            return self._send(502, error_page("Google sign-in failed", "Google identity could not be verified."), "text/html")
        sub_id = info.get("sub")
        email = (info.get("email") or "").strip().lower()
        if not sub_id or not email:
            return self._send(502, error_page("Google sign-in failed", "Google did not return a complete profile. Start again from your app."), "text/html")
        email_verified = info.get("email_verified") in (True, "true")
        if not email_verified:
            return self._send(400, error_page("Google sign-in failed", "That Google account's email address is not verified. Verify it with Google, or use your Epic Video email and password instead."), "text/html")
        try:
            uid = app_user_for_google(sub_id, email, info.get("name"), email_verified)
            session = make_app_session(uid)
        except ValueError as e:
            if str(e) == "account_exists_use_password":
                return self._send(409, error_page("Account already exists", "An Epic Video account with that email already exists. Sign in with your Epic Video email and password instead."), "text/html")
            print(f"[mcp] google sign-in account error: {e!r}", flush=True)
            return self._send(502, error_page("Sign-in failed", "Your Google identity checked out, but Epic Video could not open your account session. Try again."), "text/html")
        except Exception as e:
            print(f"[mcp] google sign-in account error: {e!r}", flush=True)
            return self._send(502, error_page("Sign-in failed", "Your Google identity checked out, but Epic Video could not open your account session. Try again."), "text/html")
        st, me = app_call("GET", "/api/me", session)
        if st != 200 or not me.get("id"):
            return self._send(502, error_page("Sign-in failed", "Epic Video did not accept the new session. Try again, or use your email and password."), "text/html")
        return self._complete_authorize(flow, uid, session)

    # ---------------------------------------------------------- OAuth: token
    def _client_auth(self, form):
        """Resolve + authenticate the client. Returns (client_row, error_tuple|None)."""
        client_id = form.get("client_id")
        secret = form.get("client_secret")
        authz = self.headers.get("Authorization") or ""
        if authz.startswith("Basic "):
            try:
                decoded = base64.b64decode(authz[6:]).decode()
                cid, _, sec = decoded.partition(":")
                client_id = client_id or urllib.parse.unquote(cid)
                secret = secret or urllib.parse.unquote(sec)
            except Exception:
                pass
        if not client_id:
            return None, (401, {"error": "invalid_client", "error_description": "client_id is required."})
        client = self._get_client(client_id)
        if not client:
            return None, (401, {"error": "invalid_client", "error_description": "Unknown client."})
        if client["secret_hash"]:
            if not secret or sha256hex(secret) != client["secret_hash"]:
                return None, (401, {"error": "invalid_client", "error_description": "Client authentication failed."})
        return client, None

    def _issue_tokens(self, client_id, user_id, app_session, scope):
        access = secrets.token_urlsafe(32)
        refresh = secrets.token_urlsafe(32)
        t = now()
        conn = db()
        conn.execute(
            "INSERT INTO tokens (access_hash, refresh_hash, client_id, user_id, app_session, scope, created_at, access_expires_at, refresh_expires_at, revoked) VALUES (?,?,?,?,?,?,?,?,?,0)",
            (sha256hex(access), sha256hex(refresh), client_id, user_id, app_session, scope, t, t + ACCESS_TTL, t + REFRESH_TTL),
        )
        conn.commit()
        conn.close()
        return {
            "access_token": access,
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": refresh,
            "scope": scope or SCOPE,
        }

    def token(self):
        form = self._body_form()
        grant = form.get("grant_type")
        client, err = self._client_auth(form)
        if err:
            code_, obj = err
            extra = {"WWW-Authenticate": 'Basic realm="epic-video-token"'} if code_ == 401 else None
            return self._json(code_, obj, extra)
        if grant == "authorization_code":
            code_val = form.get("code") or ""
            conn = db()
            row = conn.execute("SELECT * FROM codes WHERE code_hash=?", (sha256hex(code_val),)).fetchone()
            if not row or row["used"] or now() - row["created_at"] > CODE_TTL:
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "Authorization code is invalid, expired, or already used."})
            if row["client_id"] != client["client_id"]:
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "Code was issued to a different client."})
            if form.get("redirect_uri") != row["redirect_uri"]:
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "redirect_uri does not match the authorization request."})
            verifier = form.get("code_verifier") or ""
            if not verifier or pkce_challenge(verifier) != row["code_challenge"]:
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "PKCE code_verifier check failed."})
            # Atomic claim: only one concurrent redemption can flip used 0->1.
            cur = conn.execute("UPDATE codes SET used=1 WHERE code_hash=? AND used=0", (sha256hex(code_val),))
            if cur.rowcount != 1:
                conn.rollback()
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "Authorization code is invalid, expired, or already used."})
            conn.commit()
            conn.close()
            return self._json(200, self._issue_tokens(client["client_id"], row["user_id"], row["app_session"], row["scope"]))
        if grant == "refresh_token":
            rt = form.get("refresh_token") or ""
            conn = db()
            row = conn.execute("SELECT * FROM tokens WHERE refresh_hash=?", (sha256hex(rt),)).fetchone()
            if not row or row["revoked"] or row["refresh_expires_at"] < now():
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "Refresh token is invalid, expired, or revoked."})
            if row["client_id"] != client["client_id"]:
                conn.close()
                return self._json(400, {"error": "invalid_grant", "error_description": "Refresh token was issued to a different client."})
            # Rotate: kill the old row, issue a fresh pair on the same app session.
            conn.execute("DELETE FROM tokens WHERE refresh_hash=?", (sha256hex(rt),))
            conn.commit()
            conn.close()
            return self._json(200, self._issue_tokens(client["client_id"], row["user_id"], row["app_session"], row["scope"]))
        return self._json(400, {"error": "unsupported_grant_type", "error_description": "Supported: authorization_code, refresh_token."})

    def revoke(self):
        form = self._body_form()
        tok = form.get("token") or ""
        if tok:
            h = sha256hex(tok)
            conn = db()
            conn.execute("UPDATE tokens SET revoked=1 WHERE access_hash=? OR refresh_hash=?", (h, h))
            conn.commit()
            conn.close()
        return self._send(200, b"", "application/json")

    # ------------------------------------------------------------------- MCP
    def _bearer_row(self):
        authz = self.headers.get("Authorization") or ""
        if not authz.startswith("Bearer "):
            return None
        tok = authz[7:].strip()
        if not tok:
            return None
        conn = db()
        row = conn.execute("SELECT * FROM tokens WHERE access_hash=?", (sha256hex(tok),)).fetchone()
        conn.close()
        if not row or row["revoked"] or row["access_expires_at"] < now():
            return None
        return row

    def _unauthorized(self):
        www = (
            f'Bearer realm="epic-video-mcp", '
            f'resource_metadata="{ISSUER}/.well-known/oauth-protected-resource", '
            f'scope="{SCOPE}"'
        )
        return self._json(401, {
            "error": "invalid_token",
            "error_description": "A valid Epic Video access token is required. Start the OAuth flow at the authorization server named in resource_metadata.",
        }, {"WWW-Authenticate": www})

    # Discovery methods any client may call without a token (MCP spec
    # allows it; directories like mcptry score it). Tool CALLS still
    # require a valid bearer token.
    PUBLIC_METHODS = ("initialize", "tools/list", "ping")

    def mcp_post(self):
        raw = self._read_body()
        try:
            msg = json.loads(raw.decode()) if raw else None
        except Exception:
            return self._json(400, {"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None})
        row = self._bearer_row()
        if isinstance(msg, list):  # legacy batching (2025-03-26 and earlier)
            needs_auth = any(
                isinstance(i, dict) and i.get("method") == "tools/call" for i in msg
            )
            if needs_auth and not row:
                return self._unauthorized()
            out = []
            for item in msg:
                resp = self._mcp_handle(row, item)
                if resp is not None:
                    out.append(resp)
            if not out:
                return self._send(202, b"", "application/json")
            return self._json(200, out)
        if not isinstance(msg, dict):
            return self._json(400, {"jsonrpc": "2.0", "error": {"code": -32600, "message": "Invalid request"}, "id": None})
        method = msg.get("method")
        is_public = (
            method in self.PUBLIC_METHODS
            or method is None
            or (isinstance(method, str) and method.startswith("notifications/"))
        )
        if not is_public and not row:
            return self._unauthorized()
        resp = self._mcp_handle(row, msg)
        if resp is None:
            return self._send(202, b"", "application/json")
        return self._json(200, resp)

    def _mcp_handle(self, token_row, msg):
        method = msg.get("method")
        mid = msg.get("id")
        if method is None:  # a response/notification payload we don't need
            return None
        if mid is None or (isinstance(method, str) and method.startswith("notifications/")):
            return None  # notification → 202 upstream
        params = msg.get("params") or {}

        def result(r):
            return {"jsonrpc": "2.0", "id": mid, "result": r}

        def error(code, message):
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}

        if method == "initialize":
            want = params.get("protocolVersion")
            version = want if want in PROTOCOLS else PROTOCOLS[0]
            return result({
                "protocolVersion": version,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "epic-video", "title": "Epic Video", "version": "1.0.0"},
                "instructions": (
                    "Epic Video generates short AI videos with synced sound from text prompts. "
                    "Check get_my_usage before create_video to see the user's remaining tokens, "
                    "and poll get_job_status after create_video until the job is done."
                ),
            })
        if method == "ping":
            return result({})
        if method == "tools/list":
            return result({"tools": TOOLS})
        if method == "tools/call":
            name = params.get("name")
            fn = TOOL_FUNCS.get(name)
            if not fn:
                return error(-32602, f"Unknown tool: {name}")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return error(-32602, "arguments must be an object")
            try:
                return result(fn(ToolContext(token_row), args))
            except Exception as e:
                print(f"[mcp] tool {name} failed: {e!r}", flush=True)
                return result(tool_result({"error": "tool_failed", "message": "The tool call failed on the server."}, True))
        return error(-32601, f"Method not found: {method}")


def main():
    init_db()
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    server.daemon_threads = True
    print(f"Epic Video MCP listening on {HOST}:{PORT} (issuer {ISSUER}, app {APP_API})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
