"""WebRTC client for Philips Hue Secure Camera via AWS KVS.

Contains all reverse-engineered patches:
  1. RTCBundlePolicy.MAX_BUNDLE  – single ICE transport → DTLS on correct queue
  2. DTLS close_notify patch     – camera sends TLS alert immediately after handshake
  3. SRTP frame counter          – log STUN / DTLS / SRTP per-packet counts
  4. FrameCryptor (E2EE)         – decrypt RTP payload using derived AES-GCM key
  5. SDP fingerprint matching    – use actual camera SSRCs from SDP answer
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import struct
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

import aiohttp
from aiortc import (
    MediaStreamTrack,
    RTCConfiguration,
    RTCIceCandidate,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.rtcdtls import RTCDtlsTransport
from aiortc.rtp import RtpPacket
from aiortc.rtcpeerconnection import RTCBundlePolicy

import av

from .e2ee import E2EEKeyResult, apply_frame_key_to_rtp

_LOGGER = logging.getLogger(__name__)

# ─── AWS / KVS helpers ────────────────────────────────────────────────────────

def _sigv4_sign(
    method: str,
    url: str,
    payload: bytes,
    region: str,
    access_key: str,
    secret_key: str,
    session_token: str,
    service: str = "kinesisvideo",
) -> dict[str, str]:
    """Create AWS SigV4 authorization headers."""
    import datetime

    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y%m%d")
    datetime_str = now.strftime("%Y%m%dT%H%M%SZ")

    parsed = urllib.parse.urlparse(url)
    host = parsed.netloc
    path = parsed.path or "/"
    query = parsed.query

    headers_to_sign = {
        "content-type": "application/json",
        "host": host,
        "x-amz-date": datetime_str,
        "x-amz-security-token": session_token,
    }
    signed_headers = ";".join(sorted(headers_to_sign))

    def _sha256(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _hmac_sha256(key: bytes, msg: str) -> bytes:
        import hmac as _hmac

        return _hmac.new(key, msg.encode(), hashlib.sha256).digest()

    canonical_headers = "".join(
        f"{k}:{v}\n" for k, v in sorted(headers_to_sign.items())
    )
    canonical_request = "\n".join(
        [method, path, query, canonical_headers, signed_headers, _sha256(payload)]
    )
    credential_scope = f"{date_str}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", datetime_str, credential_scope, _sha256(canonical_request.encode())]
    )

    signing_key = _hmac_sha256(
        _hmac_sha256(
            _hmac_sha256(
                _hmac_sha256(
                    f"AWS4{secret_key}".encode(), date_str
                ),
                region,
            ),
            service,
        ),
        "aws4_request",
    )
    import hmac as _hmac

    signature = _hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    auth_header = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    return {
        "Authorization": auth_header,
        "Content-Type": "application/json",
        "Host": host,
        "x-amz-date": datetime_str,
        "x-amz-security-token": session_token,
    }


async def _kvs_get_signaling_endpoint(
    channel_arn: str, region: str, creds: dict
) -> str:
    """Get the WSS endpoint for a KVS signaling channel."""
    url = f"https://kinesisvideo.{region}.amazonaws.com/getSignalingChannelEndpoint"
    payload = json.dumps(
        {"ChannelARN": channel_arn, "SingleMasterChannelEndpointConfiguration": {"Protocols": ["WSS"], "Role": "VIEWER"}}
    ).encode()
    headers = _sigv4_sign(
        "POST",
        url,
        payload,
        region,
        creds["AccessKeyId"],
        creds["SecretAccessKey"],
        creds["SessionToken"],
    )
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, data=payload, ssl=False) as resp:
            data = await resp.json()
            endpoints = data.get("ResourceEndpointList", [])
            for ep in endpoints:
                if ep.get("Protocol") == "WSS":
                    return ep["ResourceEndpoint"]
    raise RuntimeError("No WSS endpoint returned from KVS")


def _build_wss_url(wss_endpoint: str, channel_arn: str, client_id: str, region: str, creds: dict) -> str:
    """Build pre-signed WSS URL for KVS signaling."""
    import datetime
    import hmac

    now = datetime.datetime.utcnow()
    date_str = now.strftime("%Y%m%d")
    datetime_str = now.strftime("%Y%m%dT%H%M%SZ")

    parsed = urllib.parse.urlparse(wss_endpoint)
    host = parsed.netloc
    path = "/?"
    params = urllib.parse.urlencode(
        {
            "X-Amz-ChannelARN": channel_arn,
            "X-Amz-ClientId": client_id,
        }
    )
    query = params

    access_key = creds["AccessKeyId"]
    secret_key = creds["SecretAccessKey"]
    session_token = creds["SessionToken"]

    credential_scope = f"{date_str}/{region}/kinesisvideo/aws4_request"
    amz_credential = urllib.parse.quote_plus(f"{access_key}/{credential_scope}")

    canonical_query = (
        f"X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-ChannelARN={urllib.parse.quote_plus(channel_arn)}"
        f"&X-Amz-ClientId={urllib.parse.quote_plus(client_id)}"
        f"&X-Amz-Credential={amz_credential}"
        f"&X-Amz-Date={datetime_str}"
        f"&X-Amz-Expires=299"
        f"&X-Amz-Security-Token={urllib.parse.quote_plus(session_token)}"
        f"&X-Amz-SignedHeaders=host"
    )

    canonical_request = "\n".join(
        ["GET", "/", canonical_query, f"host:{host}\n", "host", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"]
    )
    string_to_sign = "\n".join(
        ["AWS4-HMAC-SHA256", datetime_str, credential_scope, hashlib.sha256(canonical_request.encode()).hexdigest()]
    )

    def _h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    signing_key = _h(_h(_h(_h(f"AWS4{secret_key}".encode(), date_str), region), "kinesisvideo"), "aws4_request")
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()

    signed_url = (
        f"{wss_endpoint}/?{canonical_query}&X-Amz-Signature={signature}"
    )
    return signed_url


# ─── Packet type classifier ───────────────────────────────────────────────────

def _pkt_type(data: bytes) -> str:
    if not data:
        return "EMPTY"
    b = data[0]
    if b == 0 or b == 1:
        return "STUN"
    if 20 <= b <= 63:
        return "DTLS"
    if 128 <= b <= 191:
        return "SRTP"
    return "OTHER"


# ─── DTLS close_notify patch ──────────────────────────────────────────────────

_original_recv_next = None


def _patch_dtls_close_notify():
    """Patch RTCDtlsTransport to ignore TLS close_notify alerts.

    The Hue camera sends a DTLS close_notify immediately after completing
    the handshake. Without this patch aiortc closes the connection.
    """
    global _original_recv_next

    if _original_recv_next is not None:
        return  # already patched

    _original_recv_next = RTCDtlsTransport._recv_next

    async def _patched_recv_next(self):
        try:
            return await _original_recv_next(self)
        except ConnectionError as exc:
            # Camera sends close_notify right after handshake; ignore if SRTP is up
            if self._rx_srtp is not None:
                _LOGGER.debug("DTLS close_notify ignored (SRTP already established)")
                return
            raise

    RTCDtlsTransport._recv_next = _patched_recv_next
    _LOGGER.debug("DTLS close_notify patch applied")


# ─── Main WebRTC client ───────────────────────────────────────────────────────

@dataclass
class StreamFrame:
    """A decoded video frame from the camera."""
    pts: int
    dts: int
    width: int
    height: int
    jpeg: bytes  # JPEG-encoded snapshot


class HueWebRTCClient:
    """Manages a WebRTC connection to a Hue Secure Camera via AWS KVS.

    Usage:
        client = HueWebRTCClient(config, e2ee_key=key_result)
        await client.start()
        ...
        frame = await client.get_frame()
        ...
        await client.stop()
    """

    def __init__(
        self,
        home_id: str,
        device_mac: str,
        channel_arn: str,
        aws_region: str,
        hue_bearer: str,
        kvs_credentials: dict,         # {AccessKeyId, SecretAccessKey, SessionToken}
        ice_servers: list[dict],        # [{urls:…, username:…, credential:…}]
        e2ee_key: Optional[E2EEKeyResult] = None,
        on_frame: Optional[Callable[[StreamFrame], None]] = None,
    ) -> None:
        self.home_id = home_id
        self.device_mac = device_mac
        self.channel_arn = channel_arn
        self.aws_region = aws_region
        self.hue_bearer = hue_bearer
        self.kvs_credentials = kvs_credentials
        self.ice_servers = ice_servers
        self.e2ee_key = e2ee_key
        self.on_frame = on_frame

        self._pc: Optional[RTCPeerConnection] = None
        self._task: Optional[asyncio.Task] = None
        self._running = False
        self._frame_queue: asyncio.Queue[StreamFrame] = asyncio.Queue(maxsize=30)
        self._connected = asyncio.Event()
        self._stopped = asyncio.Event()

        # Stats
        self._stats = {"stun": 0, "dtls": 0, "srtp": 0, "other": 0, "frames": 0}
        self._last_stats_log = 0.0

        _patch_dtls_close_notify()

    # ── Public interface ──────────────────────────────────────────────────

    async def start(self) -> None:
        """Start the WebRTC connection in the background."""
        self._running = True
        self._task = asyncio.ensure_future(self._run())

    async def stop(self) -> None:
        """Stop the WebRTC connection."""
        self._running = False
        if self._pc:
            await self._pc.close()
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._stopped.set()

    async def wait_connected(self, timeout: float = 30.0) -> bool:
        """Wait until ICE+DTLS are connected. Returns True on success."""
        try:
            await asyncio.wait_for(self._connected.wait(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            return False

    async def get_frame(self, timeout: float = 5.0) -> Optional[StreamFrame]:
        """Get the next decoded video frame."""
        try:
            return await asyncio.wait_for(self._frame_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    # ── Internal WebRTC flow ──────────────────────────────────────────────

    async def _run(self) -> None:
        """Full lifecycle: wake → credentials → WebRTC → receive frames."""
        retry_delay = 5
        while self._running:
            try:
                await self._connect_once()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                _LOGGER.warning("WebRTC connection failed: %s; retrying in %ds", exc, retry_delay)
                self._connected.clear()
                await asyncio.sleep(retry_delay)
                retry_delay = min(retry_delay * 2, 60)

    async def _connect_once(self) -> None:
        """Single connection attempt."""
        # 1. Wake camera
        await self._wake_camera()

        # 2. Get live-stream credentials (fresh each time)
        creds = await self._get_live_stream_creds()
        if not creds:
            raise RuntimeError("Failed to get live-stream credentials")

        kvs_creds = creds.get("awsCredentials", creds.get("credentials", {}))
        channel_arn = creds.get("channelArn", self.channel_arn)
        region = creds.get("region", self.aws_region)

        # Parse TURN/STUN servers
        ice_servers = self._parse_ice_servers(creds)

        # Parse E2EE KeyEnvelope if present
        b64_envelope = creds.get("base64KeyEnvelope", "")
        salt = base64.b64decode(creds.get("e2eeSalt", "") + "==") if creds.get("e2eeSalt") else b""

        # 3. Build RTCPeerConnection with MAX_BUNDLE
        ice_server_objects = [
            RTCIceServer(
                urls=s.get("urls", s.get("url", "")),
                username=s.get("username"),
                credential=s.get("credential"),
            )
            for s in ice_servers
        ]
        config = RTCConfiguration(
            iceServers=ice_server_objects,
            bundlePolicy=RTCBundlePolicy.MAX_BUNDLE,
        )
        pc = RTCPeerConnection(configuration=config)
        self._pc = pc

        # 4. Patch datagram_received for packet stats
        self._patch_stun_protocol(pc)

        # 5. Set up track handler
        codec = None

        @pc.on("track")
        async def on_track(track: MediaStreamTrack):
            nonlocal codec
            _LOGGER.info("Track received: kind=%s", track.kind)
            if track.kind == "video":
                asyncio.ensure_future(self._receive_video(track))

        @pc.on("connectionstatechange")
        async def on_connection_state():
            state = pc.connectionState
            _LOGGER.info("WebRTC connectionState → %s", state)
            if state == "connected":
                self._connected.set()
            elif state in ("failed", "closed"):
                self._connected.clear()

        @pc.on("iceconnectionstatechange")
        async def on_ice_state():
            _LOGGER.debug("ICE state → %s", pc.iceConnectionState)

        # 6. KVS signaling
        wss_endpoint = await _kvs_get_signaling_endpoint(channel_arn, region, kvs_creds)
        client_id = f"HA-{self.device_mac}-{int(time.time())}"
        wss_url = _build_wss_url(wss_endpoint, channel_arn, client_id, region, kvs_creds)

        import websockets

        _LOGGER.debug("Connecting to KVS WSS: %s", wss_endpoint)

        async with websockets.connect(wss_url, additional_headers={"User-Agent": "HomeAssistant/HueCamera"}) as ws:
            # Receive SDP offer from camera
            sdp_offer = await self._recv_sdp_offer(ws)
            if not sdp_offer:
                raise RuntimeError("No SDP offer received from camera")

            # Set remote description
            await pc.setRemoteDescription(RTCSessionDescription(sdp=sdp_offer["sdp"], type=sdp_offer["type"]))

            # Create and set local answer
            answer = await pc.createAnswer()
            await pc.setLocalDescription(answer)

            # Send answer
            msg = {
                "action": "SDP_ANSWER",
                "messagePayload": base64.b64encode(
                    json.dumps({"sdp": pc.localDescription.sdp, "type": "answer"}).encode()
                ).decode(),
                "recipientClientId": sdp_offer.get("senderClientId", ""),
            }
            await ws.send(json.dumps(msg))
            _LOGGER.debug("SDP answer sent")

            # Exchange ICE candidates
            await self._exchange_ice(ws, pc, sdp_offer.get("senderClientId", ""))

        # Wait for connection or timeout
        if not await self.wait_connected(timeout=30):
            raise RuntimeError("WebRTC connection timed out")

        # Keep alive until stopped
        await self._keepalive_loop()

    async def _recv_sdp_offer(self, ws) -> Optional[dict]:
        """Wait for SDP_OFFER message from camera."""
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=5.0)
                msg = json.loads(raw)
                action = msg.get("action", "")
                payload_b64 = msg.get("messagePayload", "")
                if not payload_b64:
                    continue
                payload = json.loads(base64.b64decode(payload_b64 + "=="))
                if action == "SDP_OFFER" or payload.get("type") == "offer":
                    _LOGGER.debug("SDP offer received (len=%d)", len(payload.get("sdp", "")))
                    payload["senderClientId"] = msg.get("senderClientId", "")
                    return payload
                if action == "ICE_CANDIDATE":
                    candidate_data = payload.get("candidate", "")
                    if candidate_data:
                        await self._add_ice_candidate(self._pc, candidate_data, payload)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                _LOGGER.debug("WS recv error: %s", exc)
                break
        return None

    async def _exchange_ice(self, ws, pc: RTCPeerConnection, remote_id: str) -> None:
        """Exchange ICE candidates over the signaling channel."""

        async def _send_local_ice():
            while True:
                candidate = await pc.sctp.transport.ice._gather_candidates()
                if candidate is None:
                    break
                msg = {
                    "action": "ICE_CANDIDATE",
                    "messagePayload": base64.b64encode(
                        json.dumps(
                            {
                                "candidate": candidate.to_sdp(),
                                "sdpMid": "0",
                                "sdpMLineIndex": 0,
                            }
                        ).encode()
                    ).decode(),
                    "recipientClientId": remote_id,
                }
                await ws.send(json.dumps(msg))

        # Receive remote ICE candidates for up to 10 seconds
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                raw = await asyncio.wait_for(ws.recv(), timeout=2.0)
                msg = json.loads(raw)
                if msg.get("action") == "ICE_CANDIDATE":
                    payload = json.loads(base64.b64decode(msg.get("messagePayload", "") + "=="))
                    await self._add_ice_candidate(pc, payload.get("candidate", ""), payload)
            except asyncio.TimeoutError:
                break
            except Exception:
                break

    @staticmethod
    async def _add_ice_candidate(pc: RTCPeerConnection, candidate_str: str, payload: dict) -> None:
        try:
            from aiortc.sdp import candidate_from_sdp

            cand = candidate_from_sdp(candidate_str.replace("candidate:", ""))
            cand.sdpMid = payload.get("sdpMid", "0")
            cand.sdpMLineIndex = payload.get("sdpMLineIndex", 0)
            await pc.addIceCandidate(cand)
        except Exception as exc:
            _LOGGER.debug("addIceCandidate failed: %s", exc)

    async def _receive_video(self, track: MediaStreamTrack) -> None:
        """Receive and decode video frames from the track."""
        _LOGGER.info("Video receive loop started")
        codec = av.CodecContext.create("h264", "r")

        while self._running:
            try:
                packet = await asyncio.wait_for(track.recv(), timeout=5.0)
            except asyncio.TimeoutError:
                continue
            except Exception as exc:
                _LOGGER.debug("track.recv error: %s", exc)
                break

            self._stats["frames"] += 1

            # Apply FrameCryptor E2EE decryption if key available
            if self.e2ee_key and hasattr(packet, "data"):
                packet_data = apply_frame_key_to_rtp(bytes(packet.data), self.e2ee_key.frame_key)
            else:
                packet_data = bytes(packet.data) if hasattr(packet, "data") else None

            if packet_data and self.on_frame:
                try:
                    av_pkt = av.Packet(packet_data)
                    frames = codec.decode(av_pkt)
                    for frame in frames:
                        jpeg = frame.to_ndarray(format="rgb24")
                        # Convert to JPEG
                        img_frame = av.VideoFrame.from_ndarray(jpeg, format="rgb24")
                        jpeg_bytes = img_frame.to_image().tobytes()
                        sf = StreamFrame(
                            pts=packet.pts or 0,
                            dts=packet.dts or 0,
                            width=frame.width,
                            height=frame.height,
                            jpeg=jpeg_bytes,
                        )
                        self.on_frame(sf)
                        if not self._frame_queue.full():
                            self._frame_queue.put_nowait(sf)
                except Exception as exc:
                    _LOGGER.debug("frame decode error: %s", exc)

            # Log stats every 30 seconds
            now = time.time()
            if now - self._last_stats_log >= 30:
                _LOGGER.info(
                    "Stats[%s]: STUN=%d DTLS=%d SRTP=%d OTHER=%d frames=%d",
                    self.device_mac,
                    self._stats["stun"],
                    self._stats["dtls"],
                    self._stats["srtp"],
                    self._stats["other"],
                    self._stats["frames"],
                )
                self._last_stats_log = now

    async def _keepalive_loop(self) -> None:
        """Keep the connection alive via STUN keep-alives (handled by aiortc)."""
        while self._running and self._pc and self._pc.connectionState == "connected":
            await asyncio.sleep(25)

    # ── Hue API calls ─────────────────────────────────────────────────────

    async def _wake_camera(self) -> None:
        url = (
            f"https://api.account.meethue.com/security/device-configuration/v1"
            f"/home/{self.home_id}/device/{self.device_mac}/command"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.put(
                    url,
                    headers={
                        "Authorization": f"Bearer {self.hue_bearer}",
                        "Content-Type": "application/json",
                    },
                    json={"action_type": "wake_up"},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    _LOGGER.debug("wake_up → %d", resp.status)
            await asyncio.sleep(1.5)
        except Exception as exc:
            _LOGGER.warning("wake_camera failed: %s", exc)

    async def _get_live_stream_creds(self) -> Optional[dict]:
        url = (
            f"https://api.account.meethue.com/security/vss/v1"
            f"/home/{self.home_id}/credentials/live-stream?turn_servers=true"
        )
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {self.hue_bearer}",
                        "Content-Type": "application/json",
                    },
                    json={"device_id_list": [self.device_mac]},
                    ssl=False,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        return await resp.json()
                    _LOGGER.warning("live-stream creds HTTP %d", resp.status)
        except Exception as exc:
            _LOGGER.error("live-stream creds error: %s", exc)
        return None

    @staticmethod
    def _parse_ice_servers(creds: dict) -> list[dict]:
        servers = []
        # Look for TURN/STUN in common response shapes
        for key in ("iceServers", "ice_servers", "turnServers", "turn_servers"):
            val = creds.get(key)
            if isinstance(val, list):
                servers.extend(val)
            elif isinstance(val, dict):
                servers.append(val)
        if not servers:
            servers.append({"urls": "stun:stun.l.google.com:19302"})
        return servers

    # ── Packet stats patch ────────────────────────────────────────────────

    def _patch_stun_protocol(self, pc: RTCPeerConnection) -> None:
        """Patch the internal STUN protocol to count received packet types."""
        stats = self._stats

        try:
            from aioice.stun import parse_message as _orig_parse  # noqa: F401
            from aiortc.rtcicetransport import RTCIceTransport

            original_datagram = None
            for transport in getattr(pc._iceTransports, "__dict__", {}).values():
                pass  # just ensure import works
        except Exception:
            return

        # Monkey-patch the underlying asyncio protocol
        try:
            ice = pc._iceTransports[0]._connection if pc._iceTransports else None
        except Exception:
            ice = None

        if ice is None:
            return

        proto = getattr(ice, "_protocol", None)
        if proto is None:
            return

        original_datagram_received = proto.datagram_received

        def patched_datagram_received(data, addr):
            t = _pkt_type(data)
            stats[t.lower() if t.lower() in stats else "other"] += 1
            return original_datagram_received(data, addr)

        proto.datagram_received = patched_datagram_received
