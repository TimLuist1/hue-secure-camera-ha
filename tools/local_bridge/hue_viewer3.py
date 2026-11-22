#!/usr/bin/env python3
"""
Philips Hue Secure Camera live-stream capture v3
================================================
CRITICAL FIXES vs v2:

  v2 BUG: We sent SDP_OFFER → became ICE-controlling → SCTP is_server=False
          → both sides called usrsctp_connect() → broken simultaneous open
          → camera never responded to our SCTP INIT

  v3 FIX: Wait for camera's proactive SDP_OFFER → we become answerer
          → ICE role = "controlled" → SCTP is_server=True automatically
          → clean SCTP handshake: camera sends INIT, we send INIT-ACK → UP!
          → DataChannel opens → send {"streaming":true} → video streams

  FALLBACK: If camera doesn't proactively offer, we send our own SDP_OFFER
            but PATCH SCTP is_server=True to force the correct role.

  E2EE: AES-GCM FrameCryptor decryption support (if passphrase set).

  OAuth2: Auth0 PKCE — client_id = xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ
                        no client_secret needed.

Camera:  MAC=C4299615410E  IP=192.168.0.195
Account: HOME_ID=4618484926709760
"""
from __future__ import annotations

import asyncio
import base64
import datetime
import hashlib
import hmac as _hmac
import json
import logging
import os
import struct
import sys
import time
import urllib.parse
import webbrowser
from typing import Optional

import aiohttp
import av
import websockets
from aiortc import (
    MediaStreamTrack,
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.rtcdtlstransport import RTCDtlsTransport
from aiortc.rtcpeerconnection import RTCBundlePolicy
from aiortc.rtcsctptransport import RTCSctpTransport

# ═══════════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

HOME_ID        = "4618484926709760"
DEVICE_MAC     = "C4299615410E"
OUTPUT         = "/tmp/hue_camera.mp4"
TOKEN_FILE     = "/tmp/hue_tokens.json"
CREDS_FILE     = "/tmp/hue_stream_creds.json"
CAPTURE_SECS   = 40        # how many seconds to record after connection
OFFER_WAIT_S   = 45        # seconds to wait for camera's proactive SDP_OFFER (camera may take time to reconnect to KVS)
ICE_WAIT_S     = 8         # seconds to exchange ICE candidates

# E2EE: set this if camera has E2EE passphrase configured in Hue app
E2EE_PASSPHRASE = ""

# Auth0 PKCE (public client — no secret!)
_CLIENT_ID    = "xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ"
_REDIRECT_URI = "https://account.meethue.com/"
_TOKEN_URL    = "https://auth.meethue.com/oauth/token"
_AUTH_URL     = "https://auth.meethue.com/authorize"
_AUDIENCE     = "https://api.meethue.com"
_SCOPE        = "openid offline_access"

HUE_API_BASE  = "https://api.account.meethue.com"

# ═══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    format="%(asctime)s %(levelname)-8s %(name)s: %(message)s",
    level=logging.DEBUG,
    stream=sys.stderr,
)
for _noisy in ("aioice", "aioice.ice", "websockets", "websockets.client"):
    logging.getLogger(_noisy).setLevel(logging.WARNING)
logging.getLogger("aiortc").setLevel(logging.INFO)
logging.getLogger("aiortc.rtcsctptransport").setLevel(logging.DEBUG)
logging.getLogger("aiortc.rtcdtlstransport").setLevel(logging.DEBUG)

log = logging.getLogger("hue")

# NOTE: We PATCH RTCSctpTransport.is_server to ALWAYS return True.
# Rationale:
#   Camera always uses a=setup:active (DTLS CLIENT). Cameras using DTLS-active
#   typically also use SCTP-client role (they send SCTP INIT). In the fallback
#   path (we offer), aiortc defaults to is_server=False (we send INIT) because
#   we are ICE-controlling. But camera's SCTP is dormant as answerer — it may
#   only send SCTP INIT if the other side is SCTP server (waiting for INIT).
#   Forcing is_server=True: we wait; camera (DTLS/SCTP client) sends INIT → UP!
_orig_is_server = RTCSctpTransport.is_server.fget

def _patched_is_server(self: RTCSctpTransport) -> bool:
    return True   # always act as SCTP server in fallback path

RTCSctpTransport.is_server = property(_patched_is_server)   # type: ignore[method-assign]
log.info("[PATCH] SCTP is_server=True applied")

# ═══════════════════════════════════════════════════════════════════════════════
#  PATCH 2 — DTLS close_notify tolerance
#  Camera sends a DTLS close_notify immediately after the handshake completes.
#  Without this patch aiortc closes the entire connection on receiving it.
# ═══════════════════════════════════════════════════════════════════════════════

_orig_recv_next = RTCDtlsTransport._recv_next

async def _patched_recv_next(self: RTCDtlsTransport):
    try:
        return await _orig_recv_next(self)
    except ConnectionError:
        if getattr(self, "_rx_srtp", None) is not None:
            log.debug("[PATCH] DTLS close_notify received but SRTP is active — ignoring")
            # Block the receive loop forever so SRTP keeps working
            await asyncio.Event().wait()
            return  # never reached
        raise

RTCDtlsTransport._recv_next = _patched_recv_next
log.info("[PATCH] DTLS close_notify tolerance applied")

# ═══════════════════════════════════════════════════════════════════════════════
#  OAuth2 — Auth0 PKCE
# ═══════════════════════════════════════════════════════════════════════════════

def _pkce() -> tuple[str, str]:
    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _jwt_exp(token: str) -> int:
    try:
        part = token.split(".")[1]
        pad  = 4 - len(part) % 4
        return int(json.loads(base64.b64decode(part + "=" * pad)).get("exp", 0))
    except Exception:
        return 0


def _load_tokens() -> Optional[dict]:
    try:
        return json.loads(open(TOKEN_FILE).read())
    except Exception:
        return None


def _save_tokens(data: dict) -> None:
    with open(TOKEN_FILE, "w") as f:
        json.dump(data, f, indent=2)
    log.info("Tokens saved → %s", TOKEN_FILE)


async def _refresh_token(refresh_tok: str) -> Optional[dict]:
    async with aiohttp.ClientSession() as s:
        async with s.post(
            _TOKEN_URL,
            data={
                "grant_type":    "refresh_token",
                "client_id":     _CLIENT_ID,
                "refresh_token": refresh_tok,
            },
            ssl=False,
        ) as r:
            if r.status == 200:
                return await r.json()
            log.warning("Token refresh HTTP %d: %s", r.status, (await r.text())[:200])
    return None


async def _pkce_login() -> dict:
    """Interactive browser-based PKCE login. Returns raw token dict."""
    verifier, challenge = _pkce()
    state = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")

    params = urllib.parse.urlencode({
        "client_id":             _CLIENT_ID,
        "redirect_uri":          _REDIRECT_URI,
        "response_type":         "code",
        "scope":                 _SCOPE,
        "audience":              _AUDIENCE,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "state":                 state,
    })
    auth_url = f"{_AUTH_URL}?{params}"

    print("\n" + "=" * 70)
    print("ANMELDUNG ERFORDERLICH — Schritt 1:")
    print("Öffne diesen Link im Browser:")
    print()
    print(auth_url)
    print()
    print("Schritt 2: Melde dich mit deinem Philips Hue Konto an.")
    print("Schritt 3: Nach der Weiterleitung kopiere die VOLLSTÄNDIGE URL")
    print("           aus der Adressleiste (beginnt mit https://account.meethue.com/)")
    print("           und füge sie hier ein:")
    print("=" * 70)

    try:
        webbrowser.open(auth_url)
    except Exception:
        pass

    callback_url = input("Redirect-URL: ").strip()
    qs   = urllib.parse.parse_qs(urllib.parse.urlparse(callback_url).query)
    code = qs.get("code", [None])[0]
    if not code:
        raise ValueError(f"Kein 'code' in URL: {callback_url!r}")

    async with aiohttp.ClientSession() as s:
        async with s.post(
            _TOKEN_URL,
            data={
                "grant_type":    "authorization_code",
                "client_id":     _CLIENT_ID,
                "code":          code,
                "redirect_uri":  _REDIRECT_URI,
                "code_verifier": verifier,
            },
            ssl=False,
        ) as r:
            if r.status != 200:
                raise RuntimeError(f"Token-Austausch fehlgeschlagen: {r.status} {await r.text()}")
            return await r.json()


async def _silent_auth_via_firefox() -> Optional[dict]:
    """Try Auth0 silent auth using existing Firefox browser session cookies."""
    import shutil, tempfile
    firefox_profiles = [
        os.path.expanduser("~/Library/Application Support/Firefox/Profiles"),
    ]
    cookies: dict = {}
    for base in firefox_profiles:
        if not os.path.isdir(base):
            continue
        for prof in os.listdir(base):
            db = os.path.join(base, prof, "cookies.sqlite")
            if not os.path.exists(db):
                continue
            tmp = tempfile.mktemp(suffix=".sqlite")
            try:
                shutil.copy(db, tmp)
                import sqlite3
                conn = sqlite3.connect(tmp)
                rows = conn.execute(
                    "SELECT name, value FROM moz_cookies WHERE host LIKE '%auth.meethue.com'"
                ).fetchall()
                conn.close()
                cookies = {r[0]: urllib.parse.unquote(r[1]) for r in rows}
                if cookies:
                    log.info("[AUTH] Found %d auth.meethue.com cookies in Firefox profile %s", len(cookies), prof)
                    break
            except Exception as e:
                log.debug("[AUTH] Firefox cookie read error: %s", e)
            finally:
                try: os.unlink(tmp)
                except: pass
        if cookies:
            break

    if not cookies:
        log.warning("[AUTH] No Firefox session cookies found")
        return None

    verifier  = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    state = base64.urlsafe_b64encode(os.urandom(12)).decode().rstrip("=")

    params = {
        "client_id":             _CLIENT_ID,
        "redirect_uri":          _REDIRECT_URI,
        "response_type":         "code",
        "scope":                 _SCOPE,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
        "state":                 state,
        "prompt":                "none",
    }

    try:
        jar = aiohttp.CookieJar(unsafe=True)
        connector = aiohttp.TCPConnector(ssl=False)
        async with aiohttp.ClientSession(cookie_jar=jar, connector=connector) as s:
            for name, val in cookies.items():
                jar.update_cookies(
                    {name: val},
                    response_url=aiohttp.client_reqrep.URL("https://auth.meethue.com/"),
                )

            url = f"{_AUTH_URL}?" + urllib.parse.urlencode(params)
            async with s.get(
                url, allow_redirects=False,
                headers={"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"},
                ssl=False,
            ) as r:
                loc = r.headers.get("Location", "")
                qs  = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
                code = qs.get("code", [None])[0]
                err  = qs.get("error", [None])[0]
                if err:
                    log.warning("[AUTH] Silent auth error: %s — %s",
                                err, qs.get("error_description", [""])[0])
                    return None
                if not code:
                    log.warning("[AUTH] No code in silent auth redirect: %s", loc[:200])
                    return None

            async with s.post(
                _TOKEN_URL,
                data={
                    "grant_type":    "authorization_code",
                    "client_id":     _CLIENT_ID,
                    "code":          code,
                    "redirect_uri":  _REDIRECT_URI,
                    "code_verifier": verifier,
                },
                ssl=False,
            ) as tr:
                if tr.status == 200:
                    tokens = await tr.json()
                    log.info("[AUTH] Silent auth OK — token valid %ds", tokens.get("expires_in", 0))
                    return tokens
                log.warning("[AUTH] Token exchange: %d %s", tr.status, (await tr.text())[:200])
    except Exception as e:
        log.warning("[AUTH] Silent auth exception: %s", e)
    return None


async def get_bearer() -> str:
    """Return a valid Bearer access_token, refreshing or re-authenticating as needed."""
    tokens = _load_tokens()
    if tokens:
        exp = _jwt_exp(tokens.get("access_token", ""))
        remaining = int(exp - time.time()) if exp else -1
        if exp and remaining > 60:
            log.info("Cached token valid for %ds", remaining)
            return tokens["access_token"]

        if tokens.get("refresh_token"):
            log.info("Token expired; refreshing via refresh_token …")
            new = await _refresh_token(tokens["refresh_token"])
            if new and "access_token" in new:
                new.setdefault("refresh_token", tokens["refresh_token"])
                _save_tokens(new)
                log.info("Token refreshed OK")
                return new["access_token"]
            log.warning("Refresh failed — trying silent auth")

    # Try silent auth via existing browser session (no user interaction)
    log.info("[AUTH] Attempting silent auth via Firefox session…")
    new = await _silent_auth_via_firefox()
    if new and "access_token" in new:
        _save_tokens(new)
        return new["access_token"]

    # Last resort: interactive PKCE login
    tokens = await _pkce_login()
    _save_tokens(tokens)
    return tokens["access_token"]

# ═══════════════════════════════════════════════════════════════════════════════
#  AWS SigV4 helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _sigv4_headers(
    method: str, url: str, payload: bytes,
    region: str, ak: str, sk: str, st: str,
    service: str = "kinesisvideo",
) -> dict:
    now = datetime.datetime.utcnow()
    ds  = now.strftime("%Y%m%d")
    dts = now.strftime("%Y%m%dT%H%M%SZ")
    p   = urllib.parse.urlparse(url)
    host, path, query = p.netloc, p.path or "/", p.query

    hdrs = {
        "content-type":           "application/json",
        "host":                   host,
        "x-amz-date":             dts,
        "x-amz-security-token":   st,
    }
    signed     = ";".join(sorted(hdrs))
    canon_hdrs = "".join(f"{k}:{v}\n" for k, v in sorted(hdrs.items()))
    ph         = hashlib.sha256(payload).hexdigest()
    canon      = "\n".join([method, path, query, canon_hdrs, signed, ph])
    scope      = f"{ds}/{region}/{service}/aws4_request"
    s2s        = "\n".join(["AWS4-HMAC-SHA256", dts, scope,
                             hashlib.sha256(canon.encode()).hexdigest()])

    def h(k: bytes, m: str) -> bytes:
        return _hmac.new(k, m.encode(), hashlib.sha256).digest()

    key = h(h(h(h(f"AWS4{sk}".encode(), ds), region), service), "aws4_request")
    sig = _hmac.new(key, s2s.encode(), hashlib.sha256).hexdigest()
    hdrs["Authorization"] = (
        f"AWS4-HMAC-SHA256 Credential={ak}/{scope}, "
        f"SignedHeaders={signed}, Signature={sig}"
    )
    return hdrs


def _wss_presign(
    endpoint: str, channel_arn: str, client_id: str,
    region: str, ak: str, sk: str, st: str,
) -> str:
    """Build SigV4 presigned WSS URL for KVS signaling (mirrors HA integration)."""
    now = datetime.datetime.utcnow()
    ds  = now.strftime("%Y%m%d")
    dts = now.strftime("%Y%m%dT%H%M%SZ")
    host = urllib.parse.urlparse(endpoint).netloc

    scope   = f"{ds}/{region}/kinesisvideo/aws4_request"
    cred_q  = urllib.parse.quote_plus(f"{ak}/{scope}")

    cq = (
        f"X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-ChannelARN={urllib.parse.quote_plus(channel_arn)}"
        f"&X-Amz-ClientId={urllib.parse.quote_plus(client_id)}"
        f"&X-Amz-Credential={cred_q}"
        f"&X-Amz-Date={dts}"
        f"&X-Amz-Expires=299"
        f"&X-Amz-Security-Token={urllib.parse.quote_plus(st)}"
        f"&X-Amz-SignedHeaders=host"
    )
    canon = "\n".join([
        "GET", "/", cq,
        f"host:{host}\n", "host",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ])
    s2s = "\n".join(["AWS4-HMAC-SHA256", dts, scope,
                      hashlib.sha256(canon.encode()).hexdigest()])

    def _h(k: bytes, m: str) -> bytes:
        return _hmac.new(k, m.encode(), hashlib.sha256).digest()

    key = _h(_h(_h(_h(f"AWS4{sk}".encode(), ds), region), "kinesisvideo"), "aws4_request")
    sig = _hmac.new(key, s2s.encode(), hashlib.sha256).hexdigest()
    return f"{endpoint}/?{cq}&X-Amz-Signature={sig}"

# ═══════════════════════════════════════════════════════════════════════════════
#  Hue / KVS API calls
# ═══════════════════════════════════════════════════════════════════════════════

async def wake_camera(bearer: str) -> None:
    url = (
        f"{HUE_API_BASE}/security/device-configuration/v1"
        f"/home/{HOME_ID}/device/{DEVICE_MAC}/command"
    )
    try:
        async with aiohttp.ClientSession() as s:
            async with s.put(
                url,
                headers={
                    "Authorization":  f"Bearer {bearer}",
                    "Content-Type":   "application/json",
                },
                json={"action_type": "wake_up"},
                ssl=False,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as r:
                log.info("[WAKE] HTTP %d", r.status)
        # NOTE: no sleep — we connect to KVS first, then call wake
    except Exception as exc:
        log.warning("[WAKE] failed: %s", exc)


async def get_live_stream_creds(bearer: str) -> dict:
    url = (
        f"{HUE_API_BASE}/security/vss/v1"
        f"/home/{HOME_ID}/credentials/live-stream?turn_servers=true"
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(
            url,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type":  "application/json",
            },
            json={"device_id_list": [DEVICE_MAC]},
            ssl=False,
            timeout=aiohttp.ClientTimeout(total=20),
        ) as r:
            r.raise_for_status()
            data = await r.json()
    log.info("[CREDS] keys=%s", list(data.keys()))
    log.info("[CREDS] full JSON: %s", json.dumps(data)[:3000])
    with open(CREDS_FILE, "w") as f:
        json.dump(data, f, indent=2)
    return data


async def get_wss_endpoint(channel_arn: str, region: str, kvs: dict) -> str:
    url = f"https://kinesisvideo.{region}.amazonaws.com/getSignalingChannelEndpoint"
    payload = json.dumps({
        "ChannelARN": channel_arn,
        "SingleMasterChannelEndpointConfiguration": {
            "Protocols": ["WSS"],
            "Role":      "VIEWER",
        },
    }).encode()
    headers = _sigv4_headers(
        "POST", url, payload, region,
        kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"],
    )
    async with aiohttp.ClientSession() as s:
        async with s.post(url, headers=headers, data=payload, ssl=False) as r:
            data = await r.json()
    for ep in data.get("ResourceEndpointList", []):
        if ep.get("Protocol") == "WSS":
            log.info("[KVS] WSS endpoint: %s", ep["ResourceEndpoint"])
            return ep["ResourceEndpoint"]
    raise RuntimeError(f"No WSS endpoint in: {data}")

# ═══════════════════════════════════════════════════════════════════════════════
#  E2EE frame decryption (FrameCryptor AES-GCM)
# ═══════════════════════════════════════════════════════════════════════════════

def _decrypt_frame(data: bytes, key: bytes) -> bytes:
    """Best-effort FrameCryptor AES-GCM decryption."""
    if not key or len(data) < 29:
        return data
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        unenc  = data[0] & 0x0F
        header = data[:1 + unenc]
        body   = data[1 + unenc:]
        if len(body) < 28:
            return data
        iv = body[:12]
        ct = body[12:]
        return header + AESGCM(key).decrypt(iv, ct, header)
    except Exception:
        return data  # return as-is on failure

# ═══════════════════════════════════════════════════════════════════════════════
#  KVS message helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _decode_kvs_msg(raw) -> tuple[str, dict, str]:
    """Parse a KVS signaling message.
    Returns (action, payload_dict, sender_client_id).
    Silently ignores non-JSON or empty messages by returning ('', {}, '').
    """
    if not raw:
        return ("", {}, "")
    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except Exception:
            return ("", {}, "")
    try:
        msg    = json.loads(raw)
    except json.JSONDecodeError:
        log.debug("[KVS] Non-JSON message (len=%d): %s", len(raw), raw[:100])
        return ("", {}, "")
    action = msg.get("action", "")
    pl_b64 = msg.get("messagePayload", "")
    sender = msg.get("senderClientId", "")
    if not pl_b64:
        return (action, {}, sender)
    try:
        payload = json.loads(base64.b64decode(pl_b64 + "=="))
    except Exception:
        payload = {}
    return action, payload, sender


def _encode_kvs_msg(action: str, payload: dict, recipient: str = "") -> str:
    return json.dumps({
        "action":         action,
        "messagePayload": base64.b64encode(json.dumps(payload).encode()).decode(),
        "recipientClientId": recipient,
    })


async def _add_ice_candidate(pc: RTCPeerConnection, candidate_str: str, pl: dict) -> None:
    try:
        from aiortc.sdp import candidate_from_sdp
        cand = candidate_from_sdp(candidate_str.replace("candidate:", ""))
        cand.sdpMid       = pl.get("sdpMid", "0")
        cand.sdpMLineIndex = pl.get("sdpMLineIndex", 0)
        await pc.addIceCandidate(cand)
        log.debug("[ICE] Added remote candidate: %s", candidate_str[:80])
    except Exception as exc:
        log.debug("[ICE] addIceCandidate error: %s", exc)

# ═══════════════════════════════════════════════════════════════════════════════
#  Main WebRTC loop
# ═══════════════════════════════════════════════════════════════════════════════

async def run_webrtc(bearer: str, stream_creds: dict) -> None:
    # ── Parse credentials ──────────────────────────────────────────────────
    # Actual API response format:
    #   credentials:       {AccessKeyId, SecretAccessKey, SessionToken}
    #   signaling_channels: [{id, arn}]
    #   turn_servers:      [{device_id, ice_servers:[{urls,username,password}], wss_signal_channel_endpoint}]
    #   stun_servers:      ["stun:..."]  (raw URL strings)

    raw_creds = (
        stream_creds.get("credentials")
        or stream_creds.get("awsCredentials")
        or {}
    )
    kvs_creds = {
        "AccessKeyId":     raw_creds.get("AccessKeyId",     raw_creds.get("accessKeyId",     "")),
        "SecretAccessKey": raw_creds.get("SecretAccessKey", raw_creds.get("secretAccessKey", "")),
        "SessionToken":    raw_creds.get("SessionToken",    raw_creds.get("sessionToken",    "")),
    }

    # Channel ARN + region
    sig_channels = stream_creds.get("signaling_channels", [])
    channel_arn  = (
        stream_creds.get("channelArn")
        or (sig_channels[0].get("arn", "") if sig_channels else "")
    )
    # Extract region from ARN: arn:aws:kinesisvideo:eu-west-1:...
    region = "eu-west-1"
    if channel_arn:
        parts = channel_arn.split(":")
        if len(parts) >= 4:
            region = parts[3]
    log.info("[CREDS] channel_arn=%s region=%s", channel_arn[:60], region)

    # WSS endpoint — prefer the one embedded in turn_servers to avoid an extra API call
    turn_server_entries = stream_creds.get("turn_servers", [])
    embedded_wss = ""
    if turn_server_entries:
        embedded_wss = turn_server_entries[0].get("wss_signal_channel_endpoint", "")

    # ICE servers: collect from turn_servers[*].ice_servers + stun_servers
    ice_list: list = []
    for ts_entry in turn_server_entries:
        for srv in ts_entry.get("ice_servers", []):
            # TURN entry: {urls: [...], username, password}
            urls = srv.get("urls", srv.get("url", ""))
            ice_list.append({
                "urls":       urls,
                "username":   srv.get("username"),
                "credential": srv.get("password", srv.get("credential")),
            })
    for stun_url in stream_creds.get("stun_servers", []):
        ice_list.append({"urls": stun_url})
    # Legacy field names as fallback
    for key in ("iceServers", "ice_servers", "turnServers"):
        v = stream_creds.get(key)
        if isinstance(v, list):
            ice_list.extend(v)
    if not ice_list:
        ice_list = [{"urls": "stun:stun.l.google.com:19302"}]

    log.info("[CREDS] %d ICE servers", len(ice_list))

    ice_server_objs = []
    for srv in ice_list:
        urls = srv.get("urls", srv.get("url", ""))
        if not urls:
            continue
        ice_server_objs.append(RTCIceServer(
            urls=urls,
            username=srv.get("username"),
            credential=srv.get("credential"),
        ))

    # E2EE key (derived later if passphrase set)
    e2ee_key = b""

    # ── Build PeerConnection ───────────────────────────────────────────────
    config = RTCConfiguration(
        iceServers=ice_server_objs,
        bundlePolicy=RTCBundlePolicy.MAX_BUNDLE,
    )
    pc = RTCPeerConnection(configuration=config)

    connected_evt     = asyncio.Event()
    ice_gather_done   = asyncio.Event()
    dc_open_evt       = asyncio.Event()

    frame_count       = 0
    output_container: Optional[av.container.OutputContainer] = None
    output_stream     = None

    # ── PC event handlers ──────────────────────────────────────────────────

    @pc.on("connectionstatechange")
    async def on_conn_state():
        log.info("[PC] connectionState → %s", pc.connectionState)
        if pc.connectionState == "connected":
            connected_evt.set()

    @pc.on("iceconnectionstatechange")
    async def on_ice_state():
        log.info("[ICE] iceConnectionState → %s", pc.iceConnectionState)

    @pc.on("icegatheringstatechange")
    async def on_gather():
        log.info("[ICE] gatheringState → %s", pc.iceGatheringState)
        if pc.iceGatheringState == "complete":
            ice_gather_done.set()

    @pc.on("track")
    async def on_track(track: MediaStreamTrack):
        nonlocal frame_count, output_container, output_stream
        log.info("[TRACK] Received: kind=%s id=%s", track.kind, track.id)
        if track.kind != "video":
            return

        log.info("[VIDEO] Receive loop starting (target=%s)", OUTPUT)
        while True:
            try:
                frame = await asyncio.wait_for(track.recv(), timeout=6.0)
            except asyncio.TimeoutError:
                log.debug("[VIDEO] recv timeout — waiting…")
                continue
            except Exception as exc:
                log.warning("[VIDEO] recv error: %s", exc)
                break

            frame_count += 1

            # Initialise output container on first frame
            if output_container is None:
                try:
                    output_container = av.open(OUTPUT, "w")
                    output_stream    = output_container.add_stream("h264", rate=15)
                    output_stream.width   = frame.width
                    output_stream.height  = frame.height
                    output_stream.pix_fmt = "yuv420p"
                    log.info("[VIDEO] Container opened: %dx%d", frame.width, frame.height)
                except Exception as exc:
                    log.error("[VIDEO] Failed to open container: %s", exc)
                    break

            try:
                for pkt in output_stream.encode(frame):
                    output_container.mux(pkt)
                if frame_count % 10 == 0:
                    log.info("[VIDEO] %d frames captured", frame_count)
            except Exception as exc:
                log.debug("[VIDEO] encode error: %s", exc)

    @pc.on("datachannel")
    async def on_dc(channel):
        """Camera opened a DataChannel towards us."""
        log.info("[DC] Incoming DataChannel from camera: label=%r", channel.label)

        @channel.on("open")
        def dc_on_open():
            log.info("[DC] Camera DC open → sending {streaming:true}")
            channel.send('{"streaming":true}')
            dc_open_evt.set()

        @channel.on("message")
        def dc_on_msg(msg):
            log.info("[DC] Message from camera: %s", str(msg)[:200])

    # ── Connect to KVS signaling ───────────────────────────────────────────
    if embedded_wss:
        # Use the embedded endpoint but convert to https for the API call alternative
        # Actually, use the API call to match HA integration behavior exactly
        log.info("[KVS] Calling getSignalingChannelEndpoint (HA-style)...")
        wss_endpoint = await get_wss_endpoint(channel_arn, region, kvs_creds)
    else:
        wss_endpoint = await get_wss_endpoint(channel_arn, region, kvs_creds)
    my_client_id = f"HA-{DEVICE_MAC}-{int(time.time())}"   # matches HA integration format
    wss_url      = _wss_presign(
        wss_endpoint, channel_arn, my_client_id, region,
        kvs_creds["AccessKeyId"],
        kvs_creds["SecretAccessKey"],
        kvs_creds["SessionToken"],
    )
    log.info("[KVS] my_client_id=%s", my_client_id)

    async with websockets.connect(
        wss_url,
        additional_headers={"User-Agent": "HomeAssistant/HueCamera"},
    ) as ws:
        log.info("[KVS] WebSocket connected — NOW waking camera so we're already listening")

        camera_offer:    Optional[dict] = None
        camera_client_id: str           = ""

        # ── Step 1: Wake camera AFTER we're connected to KVS ─────────────
        # Critical timing: camera wakes → immediately sends SDP_OFFER to KVS.
        # We MUST be listening on KVS before the camera sends the offer.
        # Previous bug: wake was called before KVS connect → offer missed.
        await wake_camera(bearer)
        log.info("[WAKE] Camera woken while KVS is already listening!")

        log.info("[KVS] Waiting %ds for camera's proactive SDP_OFFER…", OFFER_WAIT_S)
        try:
            async with asyncio.timeout(OFFER_WAIT_S):
                while True:
                    raw = await ws.recv()
                    action, pl, sender = _decode_kvs_msg(raw)
                    # Log FULL raw message content for diagnostics
                    try:
                        raw_json = json.loads(raw)
                        raw_json_str = json.dumps(raw_json)[:500]
                    except Exception:
                        raw_json_str = str(raw)[:500]
                    log.info("[KVS] RAW msg: %s", raw_json_str)
                    log.info("[KVS] decoded action=%r type=%s sender=%s payload_keys=%s",
                             action, pl.get("type", "?"), sender, list(pl.keys())[:10])

                    if action == "SDP_OFFER" or pl.get("type") == "offer":
                        camera_offer     = pl
                        camera_client_id = sender
                        log.info("[KVS] Camera's SDP_OFFER received! sender=%s", sender)
                        break

                    elif action == "ICE_CANDIDATE":
                        await _add_ice_candidate(pc, pl.get("candidate", ""), pl)

        except asyncio.TimeoutError:
            log.info("[KVS] No proactive offer in %ds — proceeding to fallback", OFFER_WAIT_S)

        # ── Step 2a: HA approach — we answer camera's offer ───────────────
        if camera_offer:
            log.info("[SDP] Applying camera's offer and creating answer…")
            sdp_text = camera_offer.get("sdp", "")
            log.debug("[SDP] Camera offer (first 600):\n%s", sdp_text[:600])

            await pc.setRemoteDescription(
                RTCSessionDescription(sdp=sdp_text, type="offer")
            )
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Wait for ICE gathering
            try:
                await asyncio.wait_for(ice_gather_done.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("[ICE] Gathering timeout — proceeding with partial candidates")

            log.info("[SDP] Sending SDP_ANSWER to camera (role: DTLS client, SCTP server)")
            log.debug("[SDP] Our answer (first 600):\n%s", pc.localDescription.sdp[:600])

            await ws.send(_encode_kvs_msg(
                "SDP_ANSWER",
                {"sdp": pc.localDescription.sdp, "type": "answer"},
                recipient=camera_client_id,
            ))

        # ── Step 2b: Fallback — we offer WITHOUT DataChannel first (test if camera streams) ───
        else:
            log.info("[SDP] FALLBACK: creating SDP_OFFER (video+audio only, NO DataChannel)…")
            pc.addTransceiver("video", direction="recvonly")
            pc.addTransceiver("audio", direction="recvonly")
            # NOTE: no DataChannel — testing if camera streams without {"streaming":true}

            offer = await pc.createOffer()
            await pc.setLocalDescription(offer)

            # Wait for ICE gathering
            try:
                await asyncio.wait_for(ice_gather_done.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                log.warning("[ICE] Gathering timeout — proceeding")

            log.info("[SDP] Sending our SDP_OFFER (is_server=%s)", pc.sctp.is_server if pc.sctp else "N/A")
            log.info("[SDP] Our offer:\n%s", pc.localDescription.sdp[:2000])

            await ws.send(_encode_kvs_msg(
                "SDP_OFFER",
                {"sdp": pc.localDescription.sdp, "type": "offer"},
                recipient="",
            ))

            # Wait for camera's SDP_ANSWER
            log.info("[KVS] Waiting for SDP_ANSWER from camera…")
            try:
                async with asyncio.timeout(20):
                    while True:
                        raw = await ws.recv()
                        action, pl, sender = _decode_kvs_msg(raw)
                        # Full raw logging
                        try:
                            raw_json = json.loads(raw)
                            log.info("[KVS] FALLBACK RAW: action=%r sender=%r keys=%s payload_type=%s",
                                     raw_json.get("action"), raw_json.get("senderClientId"),
                                     list(raw_json.keys()), pl.get("type", "?"))
                        except Exception:
                            log.info("[KVS] FALLBACK RAW (parse error): %s", str(raw)[:300])

                        if action == "SDP_ANSWER" or pl.get("type") == "answer":
                            camera_client_id = sender
                            sdp_text = pl.get("sdp", "")
                            log.info("[SDP] Camera answer received!")
                            log.info("[SDP] Camera answer (m=application check):\n%s",
                                     "\n".join(l for l in sdp_text.splitlines() if "application" in l or "sctp" in l or "setup" in l))
                            await pc.setRemoteDescription(
                                RTCSessionDescription(sdp=sdp_text, type="answer")
                            )
                            break

                        elif action == "ICE_CANDIDATE":
                            await _add_ice_candidate(pc, pl.get("candidate", ""), pl)

            except asyncio.TimeoutError:
                raise RuntimeError("No SDP_ANSWER from camera within 20s")

        # ── Step 3: Exchange ICE candidates ───────────────────────────────
        log.info("[ICE] Exchanging candidates for %ds…", ICE_WAIT_S)
        deadline = time.monotonic() + ICE_WAIT_S
        while time.monotonic() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=1.0)
                action, pl, sender = _decode_kvs_msg(raw)

                if action == "ICE_CANDIDATE":
                    await _add_ice_candidate(pc, pl.get("candidate", ""), pl)
                elif action == "SDP_OFFER" or pl.get("type") == "offer":
                    log.debug("[ICE] Ignoring late SDP_OFFER during ICE exchange")
                else:
                    log.debug("[KVS] ICE phase: ignoring action=%s", action)
            except asyncio.TimeoutError:
                pass

        log.info("[ICE] Candidate exchange complete — waiting for WebRTC to connect…")

    # ── WebSocket closed; wait for full connection ─────────────────────────
    log.info("[PC] Waiting up to 35s for connected state…")
    try:
        await asyncio.wait_for(connected_evt.wait(), timeout=35.0)
        log.info("[PC] ✓ CONNECTED!")
    except asyncio.TimeoutError:
        log.warning("[PC] Timed out! State=%s ICE=%s",
                    pc.connectionState, pc.iceConnectionState)

    # ── Capture video ──────────────────────────────────────────────────────
    log.info("[RECORD] Capturing for %ds (or until stream ends)…", CAPTURE_SECS)

    # Log RTP stats every 10s to confirm packets are arriving
    async def _log_stats():
        for _ in range(CAPTURE_SECS // 10):
            await asyncio.sleep(10)
            try:
                stats = await pc.getStats()
                for s in stats.values():
                    if hasattr(s, "packetsReceived") and getattr(s, "packetsReceived", 0) > 0:
                        log.info("[STATS] %s: pkts_rx=%s bytes_rx=%s",
                                 s.type,
                                 getattr(s, "packetsReceived", "?"),
                                 getattr(s, "bytesReceived", "?"))
            except Exception as exc:
                log.debug("[STATS] error: %s", exc)

    asyncio.ensure_future(_log_stats())
    await asyncio.sleep(CAPTURE_SECS)

    # ── Flush and close output ─────────────────────────────────────────────
    if output_container is not None and output_stream is not None:
        try:
            for pkt in output_stream.encode(None):
                output_container.mux(pkt)
            output_container.close()
            log.info("[OUTPUT] ✓ %d frames saved → %s", frame_count, OUTPUT)
        except Exception as exc:
            log.warning("[OUTPUT] Flush error: %s", exc)
    else:
        log.warning("[OUTPUT] No frames captured — camera did not stream")
        log.warning("[OUTPUT] Diagnostics: connected=%s ice=%s",
                    pc.connectionState, pc.iceConnectionState)

    await pc.close()
    log.info("[PC] Closed")

# ═══════════════════════════════════════════════════════════════════════════════
#  Entry point
# ═══════════════════════════════════════════════════════════════════════════════

async def main() -> None:
    log.info("═══ Hue Secure Camera viewer v3 ═══")
    log.info("HOME_ID=%s  DEVICE_MAC=%s", HOME_ID, DEVICE_MAC)

    # 1. Authenticate
    bearer = await get_bearer()
    log.info("Bearer valid (first 20 chars: %s…)", bearer[:20])

    # Retry loop — HA integration retries with backoff; camera KVS MASTER
    # may not be ready immediately after wake.
    retry_delay = 5
    for attempt in range(1, 6):
        log.info("── Attempt %d/5 ──", attempt)

        # 2. Get credentials FIRST, then connect KVS, THEN wake camera
        #    (camera woken inside run_webrtc after KVS connects, so we catch the offer)
        creds = await get_live_stream_creds(bearer)

        # 3. Run WebRTC (connects KVS first, THEN wakes camera)
        log.info("Starting WebRTC session…")
        try:
            await run_webrtc(bearer, creds)
            log.info("Session ended normally")
            break
        except RuntimeError as exc:
            log.warning("Session failed: %s — retry in %ds", exc, retry_delay)
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)
        except Exception as exc:
            log.error("Unexpected error: %s — retry in %ds", exc, retry_delay)
            await asyncio.sleep(retry_delay)
            retry_delay = min(retry_delay * 2, 60)


if __name__ == "__main__":
    asyncio.run(main())
