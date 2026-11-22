#!/usr/bin/env python3
"""Offerer + DataChannel test: viewer sends offer, opens DC, sends streaming:true."""
import asyncio, base64, json, re, sys, time
sys.path.insert(0, "/tmp")
import hue_viewer3 as V
from aiortc.rtcsctptransport import RTCSctpTransport as _SCTP
_SCTP.is_server = property(V._orig_is_server)  # undo v3 patch: we are the offerer/SCTP client
import av, aiohttp
from aiortc import RTCPeerConnection, RTCConfiguration, RTCIceServer, RTCSessionDescription
from aiortc.rtcpeerconnection import RTCBundlePolicy
import aiortc.rtcdtlstransport as _dtls
_orig_recv = _dtls.RTCDtlsTransport._recv_next
async def _rr(self):
    try:
        d = await _orig_recv(self)
        try:
            if d:
                log.info("[DTLS<-] len=%d fb=%d", len(d), d[0])
        except Exception:
            pass
        return d
    except Exception:
        raise
_dtls.RTCDtlsTransport._recv_next = _rr
_orig_w = _dtls.RTCDtlsTransport._write_ssl
async def _ww(self):
    before = None
    try:
        import OpenSSL.SSL as _S
        before = self._ssl.bio_length() if hasattr(self._ssl,'bio_length') else None
    except Exception: pass
    r = await _orig_w(self)
    try:
        log.info("[DTLS tx?] state=%s", self._state)
    except Exception: pass
    return r
_dtls.RTCDtlsTransport._write_ssl = _ww
import aiortc.rtcsctptransport as _sctp
_orig_init = _sctp.RTCSctpTransport._init
async def _init_log(self):
    from aiortc.rtcsctptransport import InitChunk
    c = InitChunk(); c.initiate_tag = self._local_verification_tag
    c.advertised_rwnd = self._advertised_rwnd
    c.outbound_streams = self._outbound_streams_count
    c.inbound_streams = self._inbound_streams_max
    c.initial_tsn = self._local_tsn
    self._set_extensions(c.params)
    log.info("[SCTP INIT] %s", bytes(c).hex())
    await self._send_chunk(c)
    self._t1_start(c); self._set_state(self.State.COOKIE_WAIT)
_sctp.RTCSctpTransport._init = _init_log

log = V.log
DURATION = 30


def decode(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    try:
        m = json.loads(raw)
    except Exception:
        return "", {}, ""
    a = m.get("action") or m.get("messageType") or ""
    pl = {}
    if m.get("messagePayload"):
        try:
            pl = json.loads(base64.b64decode(m["messagePayload"] + "=="))
        except Exception:
            pass
    return a, pl, m.get("senderClientId", "")


async def main():
    bearer = await V.get_bearer()
    creds = await V.get_live_stream_creds(bearer)
    raw = creds.get("credentials") or creds.get("awsCredentials") or {}
    kvs = {"AccessKeyId": raw.get("AccessKeyId", ""), "SecretAccessKey": raw.get("SecretAccessKey", ""),
           "SessionToken": raw.get("SessionToken", "")}
    arn = creds.get("channelArn") or creds["signaling_channels"][0]["arn"]
    region = arn.split(":")[3]
    ice = []
    for ts in creds.get("turn_servers", []):
        for s in ts.get("ice_servers", []):
            ice.append(RTCIceServer(urls=s.get("urls"), username=s.get("username"),
                                   credential=s.get("password")))
    for s in creds.get("stun_servers", []):
        ice.append(RTCIceServer(urls=s))
    my_id = f"HA-{V.DEVICE_MAC}-{int(time.time())}"
    ep = await V.get_wss_endpoint(arn, region, kvs)
    url = V._wss_presign(ep, arn, my_id, region, kvs["AccessKeyId"], kvs["SecretAccessKey"], kvs["SessionToken"])

    pc = RTCPeerConnection(RTCConfiguration(iceServers=ice, bundlePolicy=RTCBundlePolicy.MAX_BUNDLE))
    stats = {"frames": 0, "dc_open": False}
    done = asyncio.Event()
    remote_id = ""
    answered = asyncio.Event()

    @pc.on("connectionstatechange")
    async def _cs():
        log.info("[PC] %s", pc.connectionState)
        if pc.connectionState in ("failed", "closed"):
            done.set()

    @pc.on("datachannel")
    async def _ondc(ch):
        log.info("[DC event] %s", ch.label)

    dc = pc.createDataChannel("hue-camera")
    dc.on("open", lambda: (stats.__setitem__("dc_open", True), log.info("[DC] OPEN"), dc.send('{"streaming":true}')))
    dc.on("message", lambda m: log.info("[DC msg] %s", str(m)[:200]))
    dc.on("close", lambda: log.info("[DC] closed"))

    @pc.on("track")
    async def _ontrack(track):
        log.info("[TRACK] %s", track.kind)
        if track.kind != "video":
            return
        codec = av.CodecContext.create("h264", "r")
        t0 = time.time()
        while True:
            try:
                pkt = await asyncio.wait_for(track.recv(), timeout=5)
            except Exception as e:
                log.warning("[TRACK] end %s", e)
                break
            stats["frames"] += 1
            for f in codec.decode(pkt):
                pass
            if int(time.time() - t0) % 5 == 0:
                log.info("[FPS] %d frames in %.0fs = %.1f fps  dc=%s",
                         stats["frames"], time.time() - t0, stats["frames"] / (time.time() - t0), stats["dc_open"])

    async with aiohttp.ClientSession() as http, http.ws_connect(url, headers={"User-Agent": "HA"}) as ws:
        await V.wake_camera(bearer)
        await ws.send_str(V._encode_kvs_msg("VIEWER_HELLO", {"viewerClientId": my_id, "type": "hello"}))

        async def resend():
            while not answered.is_set():
                offer = await pc.createOffer()
                sdp = re.sub(r"a=setup:active", "a=setup:actpass", offer.sdp)
                await pc.setLocalDescription(RTCSessionDescription(sdp=sdp, type="offer"))
                log.info("[SDP] offer (%d bytes), DC=%s", len(sdp),
                         any(l.startswith("m=application") for l in sdp.splitlines()))
                await ws.send_str(V._encode_kvs_msg("SDP_OFFER", {"sdp": sdp, "type": "offer"}, recipient=""))
                for _ in range(40):
                    if pc.iceGatheringState == "complete":
                        break
                    await asyncio.sleep(0.2)
                cands = list(dict.fromkeys(
                    l[2:] for l in (pc.localDescription.sdp or "").splitlines() if l.startswith("a=candidate:")))
                log.info("[ICE] sending %d local candidates", len(cands))
                for c in cands:
                    await ws.send_str(V._encode_kvs_msg("ICE_CANDIDATE", {
                        "candidate": c, "sdpMid": "0", "sdpMLineIndex": 0}, recipient=""))
                try:
                    await asyncio.wait_for(answered.wait(), 5)
                except asyncio.TimeoutError:
                    log.info("[SDP] no answer, retry")

        rt = asyncio.create_task(resend())
        try:
            async for msg in ws:
                action, pl, sender = decode(msg.data)
                if action == "SDP_ANSWER" or pl.get("type") == "answer":
                    remote_id = sender or remote_id
                    if not answered.is_set():
                        answered.set()
                        await pc.setRemoteDescription(RTCSessionDescription(sdp=pl["sdp"], type="answer"))
                        log.info("[SDP] answer set")
                elif action == "ICE_CANDIDATE":
                    if pl.get("candidate"):
                        await V._add_ice_candidate(pc, pl["candidate"], pl)
        finally:
            rt.cancel()

    log.info("[MAIN] connected wait")
    for _ in range(30):
        if pc.connectionState == "connected":
            break
        await asyncio.sleep(1)
    log.info("[MAIN] state=%s dc=%s", pc.connectionState, stats["dc_open"])
    st = await pc.getStats()
    for v in st.values():
        if getattr(v, "type", "") in ("transport", "candidate-pair") and getattr(v, "state", "succeeded") in ("succeeded", "completed"):
            log.info("[PSTAT] %s sent=%s recv=%s", v.type, getattr(v, "bytesSent", "?"), getattr(v, "bytesReceived", "?"))
    await asyncio.sleep(DURATION)
    log.info("[RESULT] frames=%d fps=%.1f dc_open=%s", stats["frames"], stats["frames"] / (DURATION + 1), stats["dc_open"])
    await pc.close()

asyncio.run(main())
