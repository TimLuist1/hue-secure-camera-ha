/* Hue Secure Camera live card.
 * The browser is the WebRTC peer (libwebrtc handles SCTP/DTLS); Home Assistant
 * only relays SDP/ICE and stores the latest JPEG for snapshots.
 */
const TAG = "hue-camera-card";

class HueCameraCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._unsub = null;
    this._pc = null;
    this._dc = null;
    this._retry = null;
    this._stopped = false;
    this._gotFrame = false;
    this._connectedAt = 0;
    this._lastFrame = 0;
    this._lastPost = 0;
    this._lastStats = 0;
    this._fpsFrames = 0;
    this._fpsAt = 0;
  }

  setConfig(config) {
    if (!config.entity) throw new Error("entity fehlt");
    this._config = config;
    this._render();
    this._connect();
  }

  set hass(hass) {
    this._hass = hass;
    if (!this._connectedOnce && this._config) {
      this._connectedOnce = true;
      this._connect();
    }
  }

  getCardSize() {
    return 6;
  }

  _entryId() {
    const state = this._hass?.states?.[this._config.entity];
    return state?.attributes?.entry_id;
  }

  _render() {
    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; }
        .wrap { position:relative; background:#000; border-radius:12px; overflow:hidden; aspect-ratio:16/9; }
        video { width:100%; height:100%; object-fit:contain; display:block; background:#000; }
        .bar { position:absolute; inset:0 0 auto 0; display:flex; gap:8px; align-items:center;
               padding:6px 10px; font:12px/1.4 system-ui,sans-serif; color:#e8eef5;
               background:linear-gradient(#000000aa, #00000000); }
        .dot { width:8px; height:8px; border-radius:50%; background:#888; }
        .dot.on { background:#27c46b; box-shadow:0 0 8px #27c46b; }
        .fps { margin-left:auto; font-variant-numeric:tabular-nums; color:#9fc3e6; }
        .overlay { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
                   color:#9fb2c8; font:14px system-ui,sans-serif; text-align:center; white-space:pre-line; }
        .hidden { display:none; }
      </style>
      <div class="wrap">
        <video autoplay muted playsinline></video>
        <div class="bar"><span class="dot"></span><span class="label">Hue Kamera</span><span class="fps">0 fps</span></div>
        <div class="overlay">verbinde…</div>
      </div>
      <canvas hidden></canvas>`;
    this._video = this.shadowRoot.querySelector("video");
    this._overlay = this.shadowRoot.querySelector(".overlay");
    this._dot = this.shadowRoot.querySelector(".dot");
    this._fpsEl = this.shadowRoot.querySelector(".fps");
    this._canvas = this.shadowRoot.querySelector("canvas");
    this._ctx = this._canvas.getContext("2d", { alpha: false });
  }

  _state(text, on) {
    if (this._overlay && text) this._overlay.textContent = text;
    if (this._dot) this._dot.classList.toggle("on", !!on);
  }

  async _connect() {
    if (!this._hass || !this._config || this._stopped) return;
    const entryId = this._entryId();
    if (!entryId) {
      this._state("Kamera noch nicht bereit…", false);
      clearTimeout(this._retry);
      this._retry = setTimeout(() => this._connect(), 3000);
      return;
    }
    await this._teardown();
    this._entryIdValue = entryId;
    this._state("warte auf Kamera…", false);
    try {
      this._unsub = await this._hass.connection.subscribeMessage(
        (ev) => this._onEvent(ev),
        { type: "hue_secure_camera/session", entry_id: entryId }
      );
    } catch (err) {
      this._state(`Fehler: ${err?.message || err}`, false);
      this._scheduleRetry();
    }
    clearInterval(this._watchdog);
    this._watchdog = setInterval(() => this._check(), 2500);
  }

  _scheduleRetry() {
    clearTimeout(this._retry);
    this._retry = setTimeout(() => this._connect(), 4000);
  }

  _check() {
    if (!this._pc || this._pc.connectionState !== "connected") return;
    const now = Date.now();
    const limit = this._gotFrame ? 12000 : 35000;
    const base = this._gotFrame ? this._lastFrame : this._connectedAt;
    if (base && now - base > limit) {
      this._state("Neu verbinden…", false);
      this._connect();
    }
  }

  async _onEvent(ev) {
    if (!ev || this._stopped) return;
    if (ev.type === "ready") return this._createPeer(ev.iceServers || []);
    if (!this._pc) return;
    try {
      if (ev.type === "offer") {
        if (this._pc.signalingState === "stable" && !this._offered) {
          await this._pc.setRemoteDescription({ type: "offer", sdp: ev.sdp });
          const answer = await this._pc.createAnswer();
          await this._pc.setLocalDescription(answer);
          await this._hass.connection.sendMessagePromise({
            type: "hue_secure_camera/answer", entry_id: this._entryIdValue, sdp: this._pc.localDescription.sdp,
          });
        }
      } else if (ev.type === "answer") {
        await this._pc.setRemoteDescription({ type: "answer", sdp: ev.sdp });
      } else if (ev.type === "ice") {
        await this._pc.addIceCandidate({
          candidate: ev.candidate, sdpMid: ev.sdpMid ?? "0", sdpMLineIndex: ev.sdpMLineIndex ?? 0,
        });
      }
    } catch (err) {
      console.debug("hue-card event error", err);
    }
  }

  async _createPeer(iceServers) {
    if (this._pc) return;
    const pc = new RTCPeerConnection({ iceServers, bundlePolicy: "max-bundle" });
    this._pc = pc;

    pc.onicecandidate = (e) => {
      if (e.candidate && this._hass) {
        this._hass.connection.sendMessagePromise({
          type: "hue_secure_camera/ice", entry_id: this._entryIdValue,
          candidate: e.candidate.candidate, sdpMid: e.candidate.sdpMid,
          sdpMLineIndex: e.candidate.sdpMLineIndex,
        }).catch(() => {});
      }
    };
    pc.onconnectionstatechange = () => {
      this._state(pc.connectionState, pc.connectionState === "connected");
      if (pc.connectionState === "connected") this._connectedAt = Date.now();
      if (["failed", "disconnected", "closed"].includes(pc.connectionState)) this._scheduleRetry();
    };
    pc.ontrack = (e) => {
      if (e.track.kind !== "video") return;
      this._video.srcObject = e.streams[0] || new MediaStream([e.track]);
      this._overlay.classList.add("hidden");
      this._video.requestVideoFrameCallback?.(() => this._onFrame());
    };

    this._dc = pc.createDataChannel("hue-camera", { ordered: true });
    this._dc.onopen = () => { try { this._dc.send('{"streaming":true}'); } catch (e) {} };

    pc.addTransceiver("video", { direction: "recvonly" });
    pc.addTransceiver("audio", { direction: "recvonly" });

    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    this._offered = true;
    await this._hass.connection.sendMessagePromise({
      type: "hue_secure_camera/offer", entry_id: this._entryIdValue, sdp: pc.localDescription.sdp,
    });
  }

  _onFrame() {
    if (!this._pc) return;
    const now = performance.now();
    this._gotFrame = true;
    this._lastFrame = Date.now();
    this._fpsFrames += 1;
    if (now - this._fpsAt >= 1000) {
      this._fpsEl.textContent = `${Math.round((this._fpsFrames * 1000) / (now - this._fpsAt))} fps`;
      this._fpsFrames = 0;
      this._fpsAt = now;
    }
    if (now - this._lastPost >= 120) {
      this._lastPost = now;
      this._pushFrame();
    }
    this._video.requestVideoFrameCallback?.(() => this._onFrame());
  }

  _pushFrame() {
    const v = this._video;
    if (!v.videoWidth) return;
    this._canvas.width = 1280;
    this._canvas.height = Math.round((1280 * v.videoHeight) / v.videoWidth) || 720;
    this._ctx.drawImage(v, 0, 0, this._canvas.width, this._canvas.height);
    const data = this._canvas.toDataURL("image/jpeg", 0.7).split(",", 2)[1];
    this._hass.connection
      .sendMessagePromise({
        type: "hue_secure_camera/frame", entry_id: this._entryIdValue, jpeg: data,
      })
      .catch(() => {});
  }

  async _teardown() {
    clearInterval(this._watchdog);
    this._offered = false;
    this._gotFrame = false;
    if (this._unsub) {
      try { await this._unsub(); } catch (e) {}
      this._unsub = null;
    }
    if (this._dc) { try { this._dc.close(); } catch (e) {} this._dc = null; }
    if (this._pc) { try { this._pc.close(); } catch (e) {} this._pc = null; }
    if (this._hass && this._entryIdValue) {
      this._hass.connection.sendMessagePromise({
        type: "hue_secure_camera/stop", entry_id: this._entryIdValue,
      }).catch(() => {});
    }
  }

  disconnectedCallback() {
    this._stopped = true;
    this._teardown();
  }

  connectedCallback() {
    if (this._stopped) {
      this._stopped = false;
      this._connect();
    }
  }
}

if (!customElements.get(TAG)) customElements.define(TAG, HueCameraCard);

window.customCards = window.customCards || [];
window.customCards.push({
  type: TAG,
  name: "Hue Secure Camera",
  description: "Live-Bild einer Hue Secure Kamera (Browser übernimmt WebRTC)",
  preview: true,
});
