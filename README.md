# Hue Secure Camera — Home Assistant Integration

Live-Bild in 1080p, Snapshots und Vollbild-Stream von Philips Hue Secure
Kameras in Home Assistant — **rein serverseitig** (kein Browser, kein
Chromium, kein Cloud-Abo).

[![Open your Home Assistant instance and open a repository inside HACS.](https://my.home-assistant.io/badges/hacs_repository.svg)](https://my.home-assistant.io/redirect/hacs_repository/?owner=TimLuist1&repository=hue-secure-camera-ha&category=integration)
[![HACS](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://hacs.xyz)
![Version](https://img.shields.io/badge/version-0.4.0-blue)
![HA](https://img.shields.io/badge/Home%20Assistant-2024.6%2B-41BDF5)

> ⚠️ Experimentell, reverse-engineered. Nutzung auf eigene Verantwortung.
>
> **Kein Bearer-Token / mitmproxy nötig** – der Login läuft per OAuth-Button
> direkt im Einrichtungsdialog. Alte Anleitungen mit `mitmproxy` sind veraltet.


---

## Funktionen

- Live-Stream (H.264 → HLS/MJPEG) und Vollbild über die normale Kamera-Ansicht
- Snapshots für Automationen, Benachrichtigungen und Dashboard-Karten
- Automatischer Reconnect, Watchdog, Kamera-Reboot bei Hänger
- OAuth2-PKCE-Login, automatische Token-Erneuerung
- Alles lokal auf dem HA-Server, nur die Hue-Cloud als Signaling

## Installation (HACS)

1. HACS → Integrationen → ⋮ → **Benutzerdefinierte Repositories**
2. `https://github.com/TimLuist1/hue-secure-camera-ha`, Typ `Integration`
3. Installieren, Home Assistant neu starten
4. `aiortc` wird beim ersten Start automatisch nachinstalliert

## Einrichtung

[![Open your Home Assistant instance and start setting up this integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=hue_secure_camera)

Oder manuell:

1. Einstellungen → Geräte & Dienste → **Integration hinzufügen** →
   „Philips Hue Secure Camera“
2. Login-Link öffnen, mit dem Hue-Konto anmelden, komplette Redirect-URL
   (`https://account.meethue.com/?code=...`) einfügen
3. **Home-ID** (16-stellig) eingeben – Anleitung inkl. Link steht im Dialog
4. Kamera auswählen

### Home-ID finden

Die Home-ID ist eine **16-stellige Zahl** deines Hue-Kontos (nicht Bridge-ID,
nicht MAC):

1. [Hue-Konto-Portal](https://account.meethue.com/homes) öffnen und anmelden
2. Dein Zuhause anklicken
3. Die 16 Ziffern stehen in der Adresszeile hinter `/homes/`

### ⚠️ Wichtig: E2EE in der Hue-App ausschalten

**Bitte zuerst in der Hue-App unter Einstellungen → Sicherheit →
Videoüberwachung die E2EE-/Verschlüsselte-Live-Ansicht deaktivieren.**
Die Entschlüsselung ist vorbereitet, aber noch nicht zuverlässig getestet –
mit aktivem E2EE bleibt das Bild sonst grün/verrauscht.

## Nutzung

- **Vollbild:** Kamera öffnen (More-Info) → Player geht auf Vollbild, oder
  Karte anklicken und ⛶ nutzen
- **Dashboard-Karte:**

```yaml
type: custom:hue-camera-card
entity: camera.abfahrt_garage
```

- **Automation / Snapshot:** `camera.snapshot` bzw.
  `camera.abfahrt_garage` als `entity_id`
- MJPEG-URL steht als Attribut `stream_url` bereit

## Roadmap

- [ ] E2EE-Passphrase (Kyber768/ECIES) zuverlässig entschlüsseln
- [ ] Zwei-Wege-Audio
- [ ] Sirene / Alarm und Flutlicht steuern
- [ ] Bewegungssensor (Binary Sensor)
- [ ] Ereignis-Clips

## Bekannte Grenzen

- Nur Cloud-Signaling (Kamera ist nicht lokal erreichbar)
- Ein Stream pro Kamera, kein Mehrfach-Viewer
- Kein Audio, keine Sirene, kein Flutlicht (siehe Roadmap)
- Token wird per Refresh-Token verlängert; schlägt das fehl:
  Optionen → neuer Login

## Technische Notizen

- OAuth2 PKCE. Die Client-ID `xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ` ist die
  **öffentliche App-Client-ID der Hue-App**, nicht personenbezogen
- Live-Credentials: `POST /security/vss/v1/home/{home}/credentials/live-stream`
- KVS-Signaling: SigV4-presigned WSS, `SDP_OFFER/ANSWER`, `ICE_CANDIDATE`
  (neuere Firmware: Feld `messageType`)
- Kamera ist immer DTLS-Client (`a=setup:active`) → Angebot mit `actpass`
- **Kritisch:** Die Kamera streamt nur bei einem vollständigen
  libwebrtc-SDP (Codec-, RTCP-Feedback- und Extmap-Set). Ein minimales
  aiortc-Angebot führt zu DTLS-Aufbau und danach Stille. Deshalb dient ein
  mitgeschnittenes Browser-Angebot als Vorlage
  (`tools/local_bridge/offer_template.sdp`)
- `tools/local_bridge/` enthält Mac-Referenz und Experimente

## Debug

```yaml
logger:
  logs:
    custom_components.hue_secure_camera: debug
```

## Lizenz

MIT (Integration). Hue-Firmware/App-Code wurde für Reverse-Engineering
analysiert.
