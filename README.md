# Philips Hue Secure Camera — Home Assistant Integration

Diese Custom Component streamt live Video von Philips Hue Secure Kameras (z.B. CMW002 Floodlight) direkt in Home Assistant über AWS Kinesis Video Streams (KVS) WebRTC.

---

## Voraussetzungen

- Home Assistant 2023.6+
- HACS (optional, aber empfohlen)
- Python-Pakete werden automatisch installiert: `aiortc`, `boto3`, `websockets`, `cryptography`, `av`

---

## Installation

### Variante A — HACS (empfohlen)

1. HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories
2. URL: `https://github.com/timluis/hue-secure-camera-ha`, Typ: `Integration`
3. Integration "Philips Hue Secure Camera" suchen und installieren
4. HA neu starten

### Variante B — Manuell

```bash
# SSH in dein HA-System
scp -r hue_camera/custom_components/hue_secure_camera \
       admin@192.168.0.105:/config/custom_components/
```

Dann HA neu starten.

---

## Einrichtung

### Schritt 1 — Bearer Token beschaffen

Du musst einmalig einen gültigen Bearer Token aus der Hue App extrahieren.

**Option A: mitmproxy (empfohlen)**

1. mitmproxy auf Mac installieren:  
   ```bash
   brew install mitmproxy
   mitmproxy --listen-port 8080
   ```
2. Handy → WLAN → Proxy → Mac-IP:8080
3. Browser: `http://mitm.it` → Zertifikat installieren
4. Hue App öffnen → Kamera antippen (Live View)
5. Im mitmproxy-Terminal: Request zu `api.account.meethue.com` suchen
6. Header `Authorization: Bearer eyJ...` kopieren

**Option B: Charles Proxy / HTTP Toolkit** — funktioniert analog

Der Token läuft typischerweise **7 Tage** ab. Falls du auch den **Refresh Token** findest, verlängert sich die Nutzung automatisch unbegrenzt.

---

### Schritt 2 — Integration hinzufügen

1. HA → Einstellungen → Geräte & Dienste → + Integration hinzufügen
2. "Philips Hue Secure Camera" suchen
3. **Bearer Token** einfügen (aus Schritt 1)
4. **Refresh Token** einfügen (optional, für automatische Verlängerung)
5. Home-ID wird automatisch ermittelt — oder manuell eingeben (14-stellige Zahl)
6. Kamera aus der Liste wählen (oder MAC-Adresse manuell eingeben, z.B. `C4299615410E`)
7. **E2EE-Passphrase** eingeben (falls in der Hue App unter  
   Einstellungen → Sicherheit → Videoüberwachung → E2EE-Passphrase gesetzt)

---

### Schritt 3 — Fertig!

Die Kamera erscheint als `camera.hue_camera_<mac>` in HA.

**Lovelace-Karte:**
```yaml
type: picture-entity
entity: camera.hue_camera_c4299615410e
show_state: false
```

---

## Funktionsweise (technisch)

```
HA                    Hue Cloud                AWS KVS               Kamera
 │                        │                       │                    │
 ├─ Bearer Token ─────────┤                       │                    │
 ├─ POST /live-stream ────►│                       │                    │
 │◄── KVS creds + E2EE ───┤                       │                    │
 │                        │                       │                    │
 ├─ PUT /wake_up ─────────►│──────────────────────►│                   │
 │                        │                       │                    │
 ├──── WSS connect ───────────────────────────────►│                   │
 │◄─── SDP offer ─────────────────────────────────┤◄── SDP offer ─────┤
 ├──── SDP answer ────────────────────────────────►│──── SDP answer ───►
 │                        │                       │                    │
 │◄──────────────────── DTLS handshake ────────────────────────────────┤
 │◄──────────────────── H264 SRTP (E2EE) ─────────────────────────────┤
 │                        │                       │                    │
 ├─ Kyber768.dec(envelope) → AES-GCM key           │                    │
 ├─ FrameCryptor.decrypt(payload, key) → H264       │                    │
 ├─ av.decode(H264) → JPEG                         │                    │
 └─ async_camera_image() ─► HA Frontend            │                    │
```

### Bekannte Herausforderungen

| Problem | Status | Lösung |
|---------|--------|--------|
| DTLS `close_notify` nach Handshake | ✅ Gepatcht | `_recv_next` ignoriert Alert wenn SRTP aktiv |
| Falsche DTLS-Queue ohne MAX_BUNDLE | ✅ Gepatcht | `RTCBundlePolicy.MAX_BUNDLE` |
| FrameCryptor E2EE auf SRTP-Payload | ⚠️ Partiell | PBKDF2 → Kyber768 Key-Ableitung implementiert |
| Token-Ablauf nach 7 Tagen | ✅ Auto-Refresh | Refresh Token Flow + Hintergrund-Task |

---

## Token manuell aktualisieren

Einstellungen → Geräte → Kamera → ⚙ Optionen → Bearer Token aktualisieren.

---

## Debugging

```yaml
# configuration.yaml
logger:
  default: warning
  logs:
    custom_components.hue_secure_camera: debug
```

Logs zeigen: `STUN=X DTLS=Y SRTP=Z OTHER=W frames=N` alle 30 Sekunden.

---

## Bekannte Einschränkungen

- ARM64 `libml_kem.so` (aus der Hue APK) läuft nicht nativ auf x86-HA — stattdessen wird `kyber-py` (Pure Python) als Fallback genutzt: `pip install kyber-py`
- Die genauen PBKDF2-Parameter (Salt-Quelle, Iterationen) der Hue-App wurden aus `libapp.so` (Dart AOT) reverse-engineered — weitere Anpassungen sind möglich
- Kamera überträgt ausschließlich verschlüsselt (FrameCryptor E2EE) — ohne korrekte Passphrase kein Bild
