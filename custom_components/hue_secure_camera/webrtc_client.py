"""Native WebRTC client for Hue Secure cameras (aiortc, no browser).

The camera only streams when the offer looks like a browser offer: it needs the
full codec/feedback/extension set of libwebrtc. We therefore take a captured
browser offer as template and only swap ICE credentials, DTLS fingerprints and
candidates. Media is decoded by aiortc and delivered as JPEG frames.
"""
from __future__ import annotations

import asyncio
import base64
import io
from concurrent.futures import ThreadPoolExecutor
import logging
import re
import time
from typing import Any, Awaitable, Callable, Optional

import aiohttp
from aiortc import (
    RTCConfiguration,
    RTCIceServer,
    RTCPeerConnection,
    RTCSessionDescription,
)
from aiortc.rtcpeerconnection import RTCBundlePolicy
from aiortc.rtp import RtcpPsfbPacket, RTCP_PSFB_PLI
from aiortc.rtcrtpreceiver import RTCRtpReceiver

from . import api, signal
from .e2ee import apply_frame_key_to_rtp, derive_frame_key

_LOGGER = logging.getLogger(__name__)

# The camera sends a DTLS close_notify right after the handshake. Without this
# patch aiortc tears the whole transport down.
from aiortc.rtcdtlstransport import RTCDtlsTransport as _RTCDtlsTransport

if not getattr(_RTCDtlsTransport, "_hue_tolerant", False):
    _orig_recv_next = _RTCDtlsTransport._recv_next

    async def _recv_next_tolerant(self) -> None:
        # After the DTLS shutdown the SRTP keys stay valid: keep reading and
        # routing RTP without touching OpenSSL again.
        if getattr(self, "_hue_dtls_closed", False):
            data = await self.transport._recv()
            first = data[0]
            if 127 < first < 192 and self._rx_srtp:
                from aiortc.rtp import is_rtcp
                from aiortc import clock

                try:
                    if is_rtcp(data):
                        await self._handle_rtcp_data(self._rx_srtp.unprotect_rtcp(data))
                    else:
                        await self._handle_rtp_data(
                            self._rx_srtp.unprotect(data), arrival_time_ms=clock.current_ms()
                        )
                except Exception:
                    pass
            return

        try:
            await _orig_recv_next(self)
        except ConnectionError:
            if getattr(self, "_rx_srtp", None) is None:
                raise
            self._hue_dtls_closed = True  # type: ignore[attr-defined]
            _LOGGER.debug("DTLS closed, switching to SRTP-only receive")

    _RTCDtlsTransport._recv_next = _recv_next_tolerant  # type: ignore[assignment]
    _RTCDtlsTransport._hue_tolerant = True  # type: ignore[attr-defined]

OFFER_TEMPLATE = """v=0
o=hue-ha 0 1 IN IP4 0.0.0.0
s=-
t=0 0
a=sendrecv
a=extmap-allow-mixed
a=fingerprint:sha-256 {{FP256}}
a=group:BUNDLE 0 1
a=ice-options:trickle
a=msid-semantic:WMS *
m=video 9 UDP/TLS/RTP/SAVPF 120 124 121 125 126 127 97 98 105 106 103 104 99 100 123 122 119
c=IN IP4 0.0.0.0
a=recvonly
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:4 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time
a=extmap:5 urn:ietf:params:rtp-hdrext:toffset
a=extmap:6/recvonly http://www.webrtc.org/experiments/rtp-hdrext/playout-delay
a=extmap:7 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=extmap:8 urn:3gpp:video-orientation
a=extmap:9/recvonly https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension
a=fmtp:126 profile-level-id=42e01f;level-asymmetry-allowed=1;packetization-mode=1;max-fs=12288;max-fr=30
a=fmtp:97 profile-level-id=42e01f;level-asymmetry-allowed=1;max-fs=12288;max-fr=30
a=fmtp:105 profile-level-id=42001f;level-asymmetry-allowed=1;packetization-mode=1;max-fs=12288;max-fr=30
a=fmtp:103 profile-level-id=42001f;level-asymmetry-allowed=1;max-fs=12288;max-fr=30
a=fmtp:99 profile=0;level-idx=9;tier=0
a=fmtp:120 max-fs=12288;max-fr=60
a=fmtp:124 apt=120
a=fmtp:121 max-fs=12288;max-fr=60
a=fmtp:125 apt=121
a=fmtp:127 apt=126
a=fmtp:98 apt=97
a=fmtp:106 apt=105
a=fmtp:104 apt=103
a=fmtp:100 apt=99
a=fmtp:119 apt=122
a=ice-pwd:{{PWD}}
a=ice-ufrag:{{UF}}
a=mid:0
a=rtcp-fb:120 nack
a=rtcp-fb:120 nack pli
a=rtcp-fb:120 ccm fir
a=rtcp-fb:120 goog-remb
a=rtcp-fb:120 transport-cc
a=rtcp-fb:121 nack
a=rtcp-fb:121 nack pli
a=rtcp-fb:121 ccm fir
a=rtcp-fb:121 goog-remb
a=rtcp-fb:121 transport-cc
a=rtcp-fb:126 nack
a=rtcp-fb:126 nack pli
a=rtcp-fb:126 ccm fir
a=rtcp-fb:126 goog-remb
a=rtcp-fb:126 transport-cc
a=rtcp-fb:97 nack
a=rtcp-fb:97 nack pli
a=rtcp-fb:97 ccm fir
a=rtcp-fb:97 goog-remb
a=rtcp-fb:97 transport-cc
a=rtcp-fb:105 nack
a=rtcp-fb:105 nack pli
a=rtcp-fb:105 ccm fir
a=rtcp-fb:105 goog-remb
a=rtcp-fb:105 transport-cc
a=rtcp-fb:103 nack
a=rtcp-fb:103 nack pli
a=rtcp-fb:103 ccm fir
a=rtcp-fb:103 goog-remb
a=rtcp-fb:103 transport-cc
a=rtcp-fb:99 nack
a=rtcp-fb:99 nack pli
a=rtcp-fb:99 ccm fir
a=rtcp-fb:99 goog-remb
a=rtcp-fb:99 transport-cc
a=rtcp-fb:123 nack
a=rtcp-fb:123 nack pli
a=rtcp-fb:123 ccm fir
a=rtcp-fb:123 goog-remb
a=rtcp-fb:123 transport-cc
a=rtcp-fb:122 nack
a=rtcp-fb:122 nack pli
a=rtcp-fb:122 ccm fir
a=rtcp-fb:122 goog-remb
a=rtcp-fb:122 transport-cc
a=rtcp-mux
a=rtcp-rsize
a=rtpmap:120 VP8/90000
a=rtpmap:124 rtx/90000
a=rtpmap:121 VP9/90000
a=rtpmap:125 rtx/90000
a=rtpmap:126 H264/90000
a=rtpmap:127 rtx/90000
a=rtpmap:97 H264/90000
a=rtpmap:98 rtx/90000
a=rtpmap:105 H264/90000
a=rtpmap:106 rtx/90000
a=rtpmap:103 H264/90000
a=rtpmap:104 rtx/90000
a=rtpmap:99 AV1/90000
a=rtpmap:100 rtx/90000
a=rtpmap:123 ulpfec/90000
a=rtpmap:122 red/90000
a=rtpmap:119 rtx/90000
a=setup:actpass
m=audio 0 UDP/TLS/RTP/SAVPF 109 9 0 8 101
c=IN IP4 0.0.0.0
a=bundle-only
a=recvonly
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level
a=extmap:2/recvonly urn:ietf:params:rtp-hdrext:csrc-audio-level
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:mid
a=extmap:7 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01
a=fmtp:109 maxplaybackrate=48000;stereo=1;useinbandfec=1
a=fmtp:101 0-15
a=ice-pwd:{{PWD}}
a=ice-ufrag:{{UF}}
a=mid:1
a=rtcp-fb:109 transport-cc
a=rtcp-fb:9 transport-cc
a=rtcp-fb:0 transport-cc
a=rtcp-fb:8 transport-cc
a=rtcp-mux
a=rtpmap:109 opus/48000/2
a=rtpmap:9 G722/8000/1
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=setup:actpass"""


def _encode_jpeg(frame) -> bytes:
    image = frame.to_image()
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=60)
    return buf.getvalue()


class HueWebRTCClient:
    """Maintains one camera session in the background."""

    def __init__(
        self,
        hass,
        token_provider: Callable[[], Awaitable[str]],
        home_id: str,
        device_mac: str,
        on_frame: Callable[[bytes], None],
        on_connected: Callable[[bool], None],
        on_ice_servers: Callable[[list], None],
        passphrase: str = "",
    ) -> None:
        self.hass = hass
        self._token_provider = token_provider
        self._home_id = home_id
        self._device_mac = device_mac
        self._on_frame = on_frame
        self._on_connected = on_connected
        self._on_ice_servers = on_ice_servers
        self._passphrase = passphrase
        self._frame_key: Optional[bytes] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._pc: Optional[RTCPeerConnection] = None
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._last_frame = 0.0
        self._connected_at = 0.0
        self._got_frames = False
        self._pending_frame = None
        self._pumping = False
        self._enc_ms = 0.0
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="hue_jpeg")

    # ── lifecycle ────────────────────────────────────────────────────────

    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._task = self.hass.async_create_background_task(
            self._run(), f"hue stream {self._device_mac}"
        )
        self._enc_task = asyncio.ensure_future(self._encoder_loop())

    async def stop(self) -> None:
        self._running = False
        if self._pc:
            try:
                await self._pc.close()
            except Exception:
                pass
            self._pc = None
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass
            self._ws = None
        if getattr(self, "_enc_task", None):
            self._enc_task.cancel()
            self._enc_task = None
        if self._task:
            self._task.cancel()
            self._task = None
        self._on_connected(False)

    @property
    def is_alive(self) -> bool:
        return self._running and time.monotonic() - self._last_frame < 10

    async def restart(self) -> None:
        """Force the current session to end; the run loop reconnects."""
        if self._ws:
            try:
                await self._ws.close()
            except Exception:
                pass

    async def _run(self) -> None:
        delay = 2.0
        failures = 0
        while self._running:
            self._got_frames = False
            try:
                await self._connect_once()
            except asyncio.CancelledError:
                return
            except Exception as exc:
                _LOGGER.debug("Hue stream error: %s", exc)
                if getattr(exc, "status", None) == 400:
                    delay = max(delay, 45)
            if not self._running:
                return
            if self._got_frames:
                # session was healthy – reconnect quickly
                delay = 0.5
                failures = 0
            else:
                failures += 1
                delay = min(delay * 2, 20)
                if failures == 4:
                    _LOGGER.warning("Camera stuck, rebooting it")
                    try:
                        await api.async_reboot(
                            self.hass, await self._token_provider(),
                            self._home_id, self._device_mac,
                        )
                    except Exception:
                        pass
                    await asyncio.sleep(45)
                    failures = 0
            await asyncio.sleep(delay)

    # ── single session ───────────────────────────────────────────────────

    async def _connect_once(self) -> None:
        token = await self._token_provider()
        creds = await api.async_live_stream_creds(
            self.hass, token, self._home_id, self._device_mac
        )

        raw = creds.get("credentials") or creds.get("awsCredentials") or {}
        kvs = {
            "AccessKeyId": raw.get("AccessKeyId", ""),
            "SecretAccessKey": raw.get("SecretAccessKey", ""),
            "SessionToken": raw.get("SessionToken", ""),
        }
        arn = creds.get("channelArn") or creds["signaling_channels"][0]["arn"]
        region = arn.split(":")[3] if arn.count(":") >= 3 else "eu-west-1"

        ice_servers: list[RTCIceServer] = []
        for entry in creds.get("turn_servers", []):
            for srv in entry.get("ice_servers", []):
                urls = srv.get("urls") or []
                if isinstance(urls, str):
                    urls = [urls]
                urls = [u.split("?")[0] for u in urls if "transport=tcp" in u] or urls
                ice_servers.append(
                    RTCIceServer(
                        urls=urls,
                        username=srv.get("username"),
                        credential=srv.get("password"),
                    )
                )
        for stun in creds.get("stun_servers", []):
            ice_servers.append(RTCIceServer(urls=stun))
        try:
            self._on_ice_servers(
                [
                    {"urls": s.urls, "username": s.username, "credential": s.credential}
                    for s in ice_servers
                ]
            )
        except Exception:
            pass

        self._pumping = False
        self._pending_frame = None
        pc = RTCPeerConnection(
            RTCConfiguration(iceServers=ice_servers, bundlePolicy=RTCBundlePolicy.MAX_BUNDLE)
        )
        self._pc = pc
        pc.addTransceiver("video", direction="recvonly")
        pc.addTransceiver("audio", direction="recvonly")

        await self._setup_e2ee(pc, creds)
        if self._frame_key:
            for receiver in pc.getReceivers():
                self._patch_receiver(receiver, self._frame_key)

        offer = await pc.createOffer()
        sdp = self._build_offer(offer.sdp)
        await pc.setLocalDescription(RTCSessionDescription(sdp=sdp, type="offer"))

        @pc.on("track")
        async def on_track(track) -> None:
            if track.kind == "video" and not self._pumping:
                self._pumping = True
                await self._pump(track)

        endpoint = await api.async_signaling_endpoint(self.hass, arn, region, kvs)
        client_id = f"HA-{self._device_mac}-{int(time.time())}"
        url = api.presign_wss(
            endpoint, arn, client_id, region,
            kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"],
        )
        from homeassistant.helpers.aiohttp_client import async_get_clientsession

        session = async_get_clientsession(self.hass, verify_ssl=False)
        ws = await session.ws_connect(url, headers={"User-Agent": "HomeAssistant/HueCamera"})
        self._ws = ws

        await api.async_wake(self.hass, token, self._home_id, self._device_mac)

        answered = asyncio.Event()
        remote_id = ""
        offer_sent = False

        async def send_offer() -> None:
            nonlocal offer_sent
            await ws.send_str(signal.encode_kvs("SDP_OFFER", {"sdp": sdp, "type": "offer"}))
            offer_sent = True

        async def keep_offering() -> None:
            while self._running and not answered.is_set():
                try:
                    if offer_sent:
                        await api.async_wake(
                            self.hass, token, self._home_id, self._device_mac
                        )
                        await send_offer()
                    await asyncio.wait_for(answered.wait(), 8)
                    if answered.is_set():
                        break
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    pass

        async def send_candidates() -> None:
            for _ in range(50):
                if pc.iceGatheringState == "complete":
                    break
                await asyncio.sleep(0.2)
            local = pc.localDescription.sdp if pc.localDescription else ""
            cands = list(
                dict.fromkeys(
                    line[2:] for line in local.splitlines() if line.startswith("a=candidate:")
                )
            )
            for cand in cands:
                await ws.send_str(
                    signal.encode_kvs(
                        "ICE_CANDIDATE",
                        {"candidate": cand, "sdpMid": "0", "sdpMLineIndex": 0},
                    )
                )

        async def frame_watchdog() -> None:
            while not ws.closed:
                await asyncio.sleep(5)
                if self._last_frame:
                    if time.monotonic() - self._last_frame > 20:
                        _LOGGER.debug("No frames for 20s, reconnecting")
                        try:
                            await ws.close()
                        except Exception:
                            pass
                        return
                elif self._connected_at and time.monotonic() - self._connected_at > 60:
                    _LOGGER.debug("No frames for 20s, reconnecting")
                    try:
                        await ws.close()
                    except Exception:
                        pass
                    return

        try:
            await send_offer()
            asyncio.ensure_future(send_candidates())
            asyncio.ensure_future(keep_offering())
            asyncio.ensure_future(frame_watchdog())

            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                action, payload, sender = signal.decode_kvs(msg.data)
                if action == "SDP_ANSWER" or payload.get("type") == "answer":
                    if answered.is_set():
                        continue
                    remote_id = sender or remote_id
                    answered.set()
                    await pc.setRemoteDescription(
                        RTCSessionDescription(sdp=payload["sdp"], type="answer")
                    )
                    self._on_connected(True)
                    self._connected_at = time.monotonic()
                elif action == "ICE_CANDIDATE" and payload.get("candidate"):
                    cand = payload["candidate"]
                    try:
                        from aiortc.sdp import candidate_from_sdp

                        c = candidate_from_sdp(cand.replace("candidate:", ""))
                        c.sdpMid = payload.get("sdpMid", "0")
                        c.sdpMLineIndex = payload.get("sdpMLineIndex", 0)
                        await pc.addIceCandidate(c)
                    except Exception:
                        pass
        finally:
            self._on_connected(False)
            try:
                await ws.close()
            except Exception:
                pass
            self._ws = None
            try:
                await pc.close()
            except Exception:
                pass
            self._pc = None

    async def _setup_e2ee(self, pc: RTCPeerConnection, creds: dict[str, Any]) -> None:
        self._frame_key = None
        envelope = creds.get("base64KeyEnvelope", "")
        if not self._passphrase or not envelope:
            return
        salt_b64 = creds.get("e2eeSalt", "")
        salt = (
            base64.b64decode(salt_b64 + "==")
            if salt_b64
            else self._home_id.encode()[:16].ljust(16, b"\x00")
        )
        result = await self.hass.async_add_executor_job(
            derive_frame_key, self._passphrase, salt, envelope
        )
        if result:
            self._frame_key = result.frame_key
            _LOGGER.debug("E2EE key derived")
        else:
            _LOGGER.warning("E2EE key derivation failed")

    @staticmethod
    def _patch_receiver(receiver: RTCRtpReceiver, key: bytes) -> None:
        if getattr(receiver, "_hue_fc", False):
            return
        receiver._hue_fc = True  # type: ignore[attr-defined]
        original = receiver._handle_rtp_packet

        async def handler(packet, arrival_time_ms: int) -> None:
            try:
                packet.payload = apply_frame_key_to_rtp(packet.payload, key)
            except Exception:
                pass
            await original(packet, arrival_time_ms)

        receiver._handle_rtp_packet = handler  # type: ignore[assignment]

    # ── media ────────────────────────────────────────────────────────────

    async def _encoder_loop(self) -> None:
        last_count = 0
        last_t = time.monotonic()
        loop = asyncio.get_running_loop()
        while self._running:
            frame = self._pending_frame
            if frame is None:
                await asyncio.sleep(0.005)
                continue
            self._pending_frame = None
            try:
                if frame.width > 960:
                    frame = frame.reformat(
                        width=960, height=round(frame.height * 960 / frame.width),
                        format="rgb24",
                    )
                _t0 = time.monotonic()
                jpeg = await loop.run_in_executor(self._executor, _encode_jpeg, frame)
                self._enc_ms += (time.monotonic() - _t0) * 1000
                self._last_frame = time.monotonic()
                self._got_frames = True
                last_count += 1
                self._on_frame(jpeg)
            except asyncio.CancelledError:
                return
            except Exception as exc:
                _LOGGER.debug("JPEG encode failed: %s", exc)
            now = time.monotonic()
            if last_count >= 50 and now - last_t >= 1:
                _LOGGER.debug("fps=%.1f enc=%.0fms", last_count / (now - last_t),
                              self._enc_ms / max(last_count, 1))
                self._enc_ms = 0.0
                last_count = 0
                last_t = now

    async def _pump(self, track) -> None:
        async def pli_loop() -> None:
            remote = self._pc.remoteDescription.sdp if self._pc and self._pc.remoteDescription else ""
            match = re.search(r"a=ssrc:(\d+)", remote)
            media_ssrc = int(match.group(1)) if match else 0
            started = time.monotonic()
            while self._running:
                await asyncio.sleep(1)
                stale = self._last_frame and time.monotonic() - self._last_frame > 2
                if time.monotonic() - started > 10 and not stale:
                    continue
                for receiver in self._pc.getReceivers() if self._pc else []:
                    try:
                        await receiver._send_rtcp(
                            RtcpPsfbPacket(
                                fmt=RTCP_PSFB_PLI,
                                ssrc=receiver._RTCRtpReceiver__rtcp_ssrc,
                                media_ssrc=media_ssrc,
                            )
                        )
                    except Exception:
                        pass

        pli = asyncio.ensure_future(pli_loop())
        try:
            while self._running:
                try:
                    frame = await asyncio.wait_for(track.recv(), timeout=15)
                except asyncio.TimeoutError:
                    continue
                except Exception:
                    break
                self._pending_frame = frame
                self._got_frames = True
        finally:
            pli.cancel()
            self._pumping = False

    # ── SDP ──────────────────────────────────────────────────────────────

    @staticmethod
    def _build_offer(aiortc_sdp: str) -> str:
        ufrag = re.search(r"a=ice-ufrag:(\S+)", aiortc_sdp).group(1)
        pwd = re.search(r"a=ice-pwd:(\S+)", aiortc_sdp).group(1)
        fps = dict(re.findall(r"a=fingerprint:(sha-\d+) (\S+)", aiortc_sdp))
        sdp = OFFER_TEMPLATE
        sdp = sdp.replace("{{UF}}", ufrag).replace("{{PWD}}", pwd)
        sdp = sdp.replace("{{FP256}}", fps.get("sha-256", ""))
        sdp = sdp.replace("{{FP384}}", fps.get("sha-384", ""))
        sdp = sdp.replace("{{FP512}}", fps.get("sha-512", ""))
        return sdp
