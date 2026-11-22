/* Hue Secure Camera card – shows the integration's MJPEG stream.
 * WebRTC/decoding happen server-side, the browser only displays <img>.
 */
const TAG = "hue-camera-card";

class HueCameraCard extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._retry = null;
  }

  setConfig(config) {
    if (!config.entity) throw new Error("entity fehlt");
    this._config = config;
    this.shadowRoot.innerHTML = `
      <style>
        :host { display:block; }
        .wrap { position:relative; background:#000; border-radius:12px; overflow:hidden; aspect-ratio:16/9; }
        img { width:100%; height:100%; object-fit:contain; display:block; cursor:zoom-in; }
        .wrap:fullscreen img { object-fit:contain; background:#000; }
        .bar { position:absolute; inset:0 0 auto 0; display:flex; gap:8px; align-items:center;
               padding:6px 10px; font:12px/1.4 system-ui,sans-serif; color:#e8eef5;
               background:linear-gradient(#000000aa,#00000000); }
        .dot { width:8px; height:8px; border-radius:50%; background:#888; }
        .dot.on { background:#27c46b; box-shadow:0 0 8px #27c46b; }
        .msg { position:absolute; inset:0; display:flex; align-items:center; justify-content:center;
               color:#9fb2c8; font:14px system-ui,sans-serif; }
        .fs { position:absolute; right:8px; bottom:8px; border:0; border-radius:8px;
              background:#000000aa; color:#fff; width:34px; height:34px; cursor:pointer; font-size:16px; }
      </style>
      <div class="wrap">
        <img alt="Hue Kamera">
        <div class="bar"><span class="dot"></span><span>Hue Kamera</span></div>
        <div class="msg">verbinde…</div>
        <button class="fs" title="Vollbild">⛶</button>
      </div>`;
    this._img = this.shadowRoot.querySelector("img");
    this._dot = this.shadowRoot.querySelector(".dot");
    this._msg = this.shadowRoot.querySelector(".msg");
    this._img.addEventListener("load", () => {
      this._dot.classList.add("on");
      this._msg.style.display = "none";
    });
    this._img.addEventListener("click", () => {
      this.dispatchEvent(new CustomEvent("hass-more-info", {
        detail: { entityId: this._config.entity }, bubbles: true, composed: true,
      }));
    });
    this.shadowRoot.querySelector(".fs").addEventListener("click", (ev) => {
      ev.stopPropagation();
      const wrap = this.shadowRoot.querySelector(".wrap");
      if (this.shadowRoot.fullscreenElement || document.fullscreenElement) {
        document.exitFullscreen?.();
      } else {
        (wrap.requestFullscreen ? wrap : this._img).requestFullscreen?.();
      }
    });
    this._img.addEventListener("error", () => {
      this._dot.classList.remove("on");
      this._msg.style.display = "flex";
      this._msg.textContent = "Stream getrennt – neu verbinden…";
      this._restart();
    });
  }

  set hass(hass) {
    this._hass = hass;
    const url = hass?.states?.[this._config?.entity]?.attributes?.stream_url;
    if (url && url !== this._url) {
      this._url = url;
      this._start();
    }
  }

  _start() {
    clearTimeout(this._retry);
    this._img.src = `${this._url}?t=${Date.now()}`;
  }

  _restart() {
    clearTimeout(this._retry);
    this._retry = setTimeout(() => {
      if (this._url) this._start();
    }, 4000);
  }

  getCardSize() {
    return 6;
  }

  disconnectedCallback() {
    clearTimeout(this._retry);
    this._img?.removeAttribute("src");
  }
}

if (!customElements.get(TAG)) customElements.define(TAG, HueCameraCard);
window.customCards = window.customCards || [];
window.customCards.push({
  type: TAG,
  name: "Hue Secure Camera",
  description: "Live-Ansicht einer Hue Secure Kamera (Server-seitiges WebRTC)",
});
