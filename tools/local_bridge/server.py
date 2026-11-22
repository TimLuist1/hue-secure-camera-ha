#!/usr/bin/env python3
"""
Hue Secure Camera local live bridge.

The BROWSER is the WebRTC offerer (like the Hue app / viewer2). It creates the
DataChannel, sends the offer; the camera answers. Chrome/Firefox libwebrtc does
the real SCTP handshake, so we don't fight aiortc's SCTP limits.

Server only: Hue auth, KVS credentials, KVS signaling relay, wake-up, MJPEG.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
import time
import webbrowser
from typing import Optional

import aiohttp
from aiohttp import web

sys.path.insert(0, "/tmp")
import hue_viewer3 as V  # noqa: E402

V.TOKEN_FILE = os.path.expanduser("~/Library/Application Support/hue_camera/tokens.json")

HOME_ID = V.HOME_ID
DEVICE_MAC = V.DEVICE_MAC
PORT = 8777

ACTIVE: Optional[web.WebSocketResponse] = None
LATEST_JPEG: bytes = b""
MJPEG_CLIENTS: set[asyncio.Queue] = set()

log = V.log


def decode_kvs(raw) -> tuple[str, dict, str]:
    import base64 as _b64
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8", "replace")
    if not raw:
        return "", {}, ""
    try:
        m = json.loads(raw)
    except Exception:
        return "", {}, ""
    action = m.get("action") or m.get("messageType") or ""
    sender = m.get("senderClientId", "") or m.get("senderClientID", "")
    pl_b64 = m.get("messagePayload", "")
    pl = {}
    if pl_b64:
        try:
            pl = json.loads(_b64.b64decode(pl_b64 + "=="))
        except Exception:
            pl = {}
    return action, pl, sender


async def session(ws_browser: web.WebSocketResponse) -> None:
    bearer = await V.get_bearer()
    creds = await V.get_live_stream_creds(bearer)

    raw_creds = creds.get("credentials") or creds.get("awsCredentials") or {}
    kvs_creds = {
        "AccessKeyId": raw_creds.get("AccessKeyId", raw_creds.get("accessKeyId", "")),
        "SecretAccessKey": raw_creds.get("SecretAccessKey", raw_creds.get("secretAccessKey", "")),
        "SessionToken": raw_creds.get("SessionToken", raw_creds.get("sessionToken", "")),
    }
    sig_channels = creds.get("signaling_channels", [])
    channel_arn = creds.get("channelArn") or (sig_channels[0].get("arn", "") if sig_channels else "")
    region = "eu-west-1"
    if channel_arn and len(channel_arn.split(":")) >= 4:
        region = channel_arn.split(":")[3]

    ice_servers = []
    for ts in creds.get("turn_servers", []):
        for srv in ts.get("ice_servers", []):
            ice_servers.append({
                "urls": srv.get("urls", srv.get("url", "")),
                "username": srv.get("username"),
                "credential": srv.get("password", srv.get("credential")),
            })
    for stun in creds.get("stun_servers", []):
        ice_servers.append({"urls": stun})

    my_id = f"HA-{DEVICE_MAC}-{int(time.time())}"
    wss_endpoint = await V.get_wss_endpoint(channel_arn, region, kvs_creds)
    wss_url = V._wss_presign(
        wss_endpoint, channel_arn, my_id, region,
        kvs_creds["AccessKeyId"], kvs_creds["SecretAccessKey"], kvs_creds["SessionToken"],
    )

    await ws_browser.send_json({"type": "config", "iceServers": ice_servers})

    async with aiohttp.ClientSession() as http, http.ws_connect(
        wss_url, headers={"User-Agent": "HomeAssistant/HueCamera"}
    ) as ws_kvs:
        log.info("[BRIDGE] KVS signaling connected")
        await V.wake_camera(bearer)
        log.info("[BRIDGE] camera woken, waiting for browser offer")

        remote_id = ""
        last_offer: Optional[str] = None
        answered = asyncio.Event()

        def enc(action, payload, recipient=""):
            m = {"action": action,
                 "messagePayload": V._encode_kvs_msg(action, payload, recipient)}
            # _encode returns full json already; rebuild cleanly instead:
            import base64
            return json.dumps({
                "action": action,
                "messagePayload": base64.b64encode(json.dumps(payload).encode()).decode(),
                "recipientClientId": recipient,
                "senderClientId": my_id,
            })

        async def keep_waking() -> None:
            # camera boot can take a while and the cloud wake / signaling offer
            # gets lost while the camera is still connecting to KVS.
            nonlocal bearer
            tick = 0
            while True:
                await asyncio.sleep(8)
                tick += 1
                try:
                    bearer = await V.get_bearer()  # refresh token when needed
                    if answered.is_set() and tick % 8:
                        continue
                    await V.wake_camera(bearer)
                    if answered.is_set():
                        log.info("[BRIDGE] keep-alive wake")
                        continue
                    log.info("[BRIDGE] re-wake / re-offer")
                    await ws_kvs.send_str(enc("VIEWER_HELLO", {"viewerClientId": my_id, "type": "hello"}))
                    if last_offer:
                        await ws_kvs.send_str(enc("SDP_OFFER", {"sdp": last_offer, "type": "offer"}))
                except Exception:
                    pass

        wake_task = asyncio.create_task(keep_waking())

        async def kvs_to_browser() -> None:
            nonlocal remote_id
            async for msg in ws_kvs:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                action, pl, sender = decode_kvs(msg.data)
                log.info("[KVS→] raw=%r action=%r sender=%s", str(msg.data)[:300], action, sender)
                if not action:
                    continue
                if action == "SDP_ANSWER" or pl.get("type") == "answer":
                    remote_id = sender or remote_id
                    answered.set()
                    log.info("[BRIDGE] ANSWER from camera (%d bytes) sender=%s", len(pl.get("sdp", "")), sender)
                    await ws_browser.send_json({"type": "answer", "sdp": pl.get("sdp", "")})
                elif action == "ICE_CANDIDATE":
                    await ws_browser.send_json({
                        "type": "ice", "candidate": pl.get("candidate", ""),
                        "sdpMid": pl.get("sdpMid", "0"),
                        "sdpMLineIndex": pl.get("sdpMLineIndex", 0),
                    })
                elif action == "SDP_OFFER":
                    remote_id = sender or remote_id
                    log.info("[BRIDGE] unexpected OFFER from camera")
                    await ws_browser.send_json({"type": "offer", "sdp": pl.get("sdp", "")})

        async def browser_to_kvs() -> None:
            nonlocal last_offer
            async for msg in ws_browser:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    continue
                m = json.loads(msg.data)
                t = m.get("type")
                if t == "offer":
                    last_offer = m.get("sdp", "")
                    log.info("[BRIDGE] browser OFFER (%d bytes) → camera", len(last_offer))
                    log.info("[BRIDGE] offer m-lines: %s",
                             [l for l in last_offer.splitlines() if l.startswith("m=")])
                    await ws_kvs.send_str(enc("VIEWER_HELLO", {"viewerClientId": my_id, "type": "hello"}))
                    await ws_kvs.send_str(enc("SDP_OFFER", {"sdp": last_offer, "type": "offer"}))
                elif t == "answer":
                    log.info("[BRIDGE] browser ANSWER → camera")
                    await ws_kvs.send_str(enc("SDP_ANSWER", {"sdp": m["sdp"], "type": "answer"}, recipient=remote_id))
                elif t == "ice":
                    await ws_kvs.send_str(enc("ICE_CANDIDATE", {
                        "candidate": m.get("candidate", ""),
                        "sdpMid": m.get("sdpMid", "0"),
                        "sdpMLineIndex": m.get("sdpMLineIndex", 0),
                    }, recipient=remote_id))

        tasks = [asyncio.create_task(kvs_to_browser()), asyncio.create_task(browser_to_kvs())]
        try:
            await asyncio.gather(*tasks)
        finally:
            for t in tasks + [wake_task]:
                t.cancel()


async def index(request: web.Request) -> web.StreamResponse:
    return web.FileResponse(os.path.join(os.path.dirname(__file__), "index.html"))


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    global ACTIVE
    ws = web.WebSocketResponse(heartbeat=20)
    await ws.prepare(request)
    if ACTIVE is not None and not ACTIVE.closed:
        try:
            await ws.send_json({"type": "busy"})
            await ws.close()
        except Exception:
            pass
        return ws
    ACTIVE = ws
    try:
        await session(ws)
    except Exception as exc:
        log.exception("session error: %s", exc)
        try:
            await ws.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass
    return ws


async def push_frame(request: web.Request) -> web.Response:
    global LATEST_JPEG
    data = await request.read()
    if data:
        LATEST_JPEG = data
        for q in list(MJPEG_CLIENTS):
            if q.full():
                try:
                    q.get_nowait()
                except Exception:
                    pass
            try:
                q.put_nowait(data)
            except Exception:
                pass
    return web.Response(text="ok")


async def stats(request: web.Request) -> web.Response:
    body = await request.text()
    log.info("[STATS] %s", body)
    return web.Response(text="ok")


async def snapshot(request: web.Request) -> web.Response:
    return web.Response(body=LATEST_JPEG or b"", content_type="image/jpeg",
                        headers={"Cache-Control": "no-store"})


async def mjpeg(request: web.Request) -> web.StreamResponse:
    resp = web.StreamResponse(headers={
        "Content-Type": "multipart/x-mixed-replace; boundary=frame",
        "Cache-Control": "no-store",
    })
    await resp.prepare(request)
    q: asyncio.Queue = asyncio.Queue(maxsize=5)
    MJPEG_CLIENTS.add(q)
    try:
        while True:
            frame = await q.get()
            await resp.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                             + str(len(frame)).encode() + b"\r\n\r\n" + frame + b"\r\n")
    finally:
        MJPEG_CLIENTS.discard(q)
    return resp


async def main() -> None:
    app = web.Application()
    app.router.add_get("/", index)
    app.router.add_get("/ws", ws_handler)
    app.router.add_post("/frame", push_frame)
    app.router.add_post("/stats", stats)
    app.router.add_get("/snapshot.jpg", snapshot)
    app.router.add_get("/stream.mjpg", mjpeg)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", PORT).start()
    log.info("Open http://127.0.0.1:%d/", PORT)
    if os.environ.get("HUE_BRIDGE_OPEN", "1") != "0":
        try:
            webbrowser.open(f"http://127.0.0.1:{PORT}/")
        except Exception:
            pass
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
