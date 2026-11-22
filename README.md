# Philips Hue Secure Camera — Home Assistant Custom Integration

Live-Bild und Snapshots von Philips Hue Secure Kameras in Home Assistant.
Diese Integration ist **reverse-engineered** und wird über HACS verteilt.

> Status: experimentell. Das Live-Bild läuft über einen Browser-WebRTC-Client
> (libwebrtc = gleiche Engine wie die Hue-App). Snapshots werden für
> Automationen gespeichert.

---

## Warum dieser Umweg?

Die Kamera streamt ausschließlich per WebRTC über AWS Kinesis Video Streams.
Eine Besonderheit des Kamera-Stacks: Er verweigert den SCTP/DataChannel-Aufbau
gegenüber reinen Python-Clients (`aiortc`), liefert das H.264-Bild aber
trotzdem. Echte Browser (Chrome/Firefox/Safari) funktionieren dagegen sofort.

Deshalb übernimmt der Browser des Nutzers den WebRTC-Teil:

```
HA Frontend (Karte)  ⇄  HA Integration  ⇄  Hue Cloud / AWS KVS  ⇄  Kamera
        │                   (Token, SDP/ICE-Relay)
        └── WebRTC direkt zur Kamera (DTLS/SRTP), JPEG-Frames → HA
```

Vorteile: kein Chromium/ffmpeg auf dem Server, kein Cloud-Abo, 1080p live.
Der Server braucht nur `aiohttp` (in HA enthalten).

E2EE (Passphrase) wird gespeichert, aber noch nicht entschlüsselt – nur nötig,
wenn in der Hue-App „Verschlüsselte Live-Ansicht“ aktiv ist.

---

## Installation (HACS)

1. HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories
2. `https://github.com/TimLuist1/hue-secure-camera-ha`, Typ `Integration`
3. Installieren, HA neu starten

## Einrichtung

1. Einstellungen → Geräte & Dienste → Integration hinzufügen →
   „Philips Hue Secure Camera“
2. Login-Link öffnen, mit dem Hue-Konto anmelden, danach die komplette
   Redirect-URL (`https://account.meethue.com/?code=...`) einfügen
3. **Home-ID** eingeben (16-stellig). Sie steckt z. B. in der
   Hue-App-Konfiguration; für dieses Konto: `4618484926709760`
4. Kamera auswählen

## Live-Bild in Lovelace

Die Integration registriert die Karte automatisch:

```yaml
type: custom:hue-camera-card
entity: camera.abfahrt_garage
```

Beim Öffnen des Dashboards verbindet sich der Browser mit der Kamera.
Der Tab muss geöffnet bleiben, solange Livebild/Snapshots gebraucht werden.
Weitere Tabs derselben Kamera teilen sich die Verbindung (HA-Session).

Snapshots (`camera.snapshot` / `async_camera_image`) liefern das letzte
Browser-Frame (max. 15 s alt, sonst letztes bekanntes).

## Bekannte Grenzen

- Livebild nur bei geöffneter HA-Oberfläche (Browser-Engine nötig)
- Zwei-Wege-Audio, Sirene, Flutlicht noch nicht umgesetzt
- E2EE-Entschlüsselung noch nicht aktiv
- Token läuft nach ~24 h ab, wird per Refresh-Token automatisch erneuert;
  bei Fehlschlag: Optionen → neuer Login

## Reverse-Engineering-Notizen

- OAuth2 PKCE, Client-ID `xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ` (aus der App)
- Live-Stream-Credentials: `POST /security/vss/v1/home/{home}/credentials/live-stream`
- KVS-Signaling: SigV4-presigned WSS, Nachrichten `SDP_OFFER/ANSWER`,
  `ICE_CANDIDATE` (Feld `messageType` in neueren Firmwares)
- Kamera ist immer DTLS-Client (`a=setup:active`) → Offer mit `actpass`
- `tools/local_bridge/` enthält die Mac-Referenzstrecke (Python-Server +
  Browser-Seite) mit ausführlicher Problemdokumentation

## Debug

```yaml
logger:
  logs:
    custom_components.hue_secure_camera: debug
```
