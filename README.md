# Philips Hue Secure Camera — Home Assistant Custom Integration

Live-Bild, Snapshots und MJPEG-Stream von Philips Hue Secure Kameras in Home
Assistant — **rein serverseitig**, ohne Browser/Chromium und ohne Cloud-Abo.

> Status: experimentell (reverse-engineered), HACS-Installation.

---

## Hintergrund

Die Kamera überträgt per WebRTC über AWS Kinesis Video Streams, ausschließlich
verschlüsselt (DTLS/SRTP). Der Kamera-Stack akzeptiert nur SDP-Angebote, die
dem vollständigen libwebrtc-Format entsprechen. Ein minimales aiortc-Angebot
führt dazu, dass die Kamera zwar DTLS aufbaut, danach aber stumm bleibt.

Diese Integration nimmt deshalb ein mitgeschnittenes Browser-Angebot als
Vorlage, ersetzt nur ICE-Credentials, DTLS-Fingerprints und Kandidaten und
lässt `aiortc` das Medien-Handling übernehmen. Ergebnis: 1080p, ~15 fps,
stabil mit automatischem Reconnect.

```
HA (aiortc) ⇄ Hue Cloud/AWS KVS ⇄ Kamera
        └── H.264/SRTP → JPEG → Entity, MJPEG, Automationen
```

E2EE (Passphrase) wird gespeichert, aber noch nicht entschlüsselt – nur nötig,
wenn in der Hue-App „Verschlüsselte Live-Ansicht“ aktiv ist.

## Installation (HACS)

1. HACS → Integrationen → ⋮ → Benutzerdefinierte Repositories
2. `https://github.com/TimLuist1/hue-secure-camera-ha`, Typ `Integration`
3. Installieren, Home Assistant neu starten

`aiortc` wird beim ersten Start automatisch von HA nachinstalliert.

## Einrichtung

1. Einstellungen → Geräte & Dienste → Integration hinzufügen →
   „Philips Hue Secure Camera“
2. Login-Link öffnen, mit dem Hue-Konto anmelden, danach die komplette
   Redirect-URL (`https://account.meethue.com/?code=...`) einfügen
3. **Home-ID** eingeben (16-stellig). Beispiel für dieses Konto:
   `4618484926709760`
4. Kamera auswählen

## Nutzung

- Entity: `camera.<name>` – Snapshots über `camera.snapshot` bzw. Dashboard
- Lovelace-Karte (wird automatisch registriert, MJPEG):

```yaml
type: custom:hue-camera-card
entity: camera.abfahrt_garage
```

- MJPEG-URL steht als Attribut `stream_url` an der Entity
- Der Stream startet bei Bedarf und stoppt nach ~2 Minuten Inaktivität

## Bekannte Grenzen

- Zwei-Wege-Audio, Sirene, Flutlicht, Bewegungssensor noch nicht umgesetzt
- E2EE-Entschlüsselung noch nicht aktiv
- Livebild im HA-Dashboard läuft über MJPEG (kein HLS/WebRTC-Player)
- Token wird per Refresh-Token erneuert; bei Fehlschlag: Optionen → neuer Login

## Technische Notizen

- OAuth2 PKCE, Client-ID `xOFEN65uPEwp0aMlJ6JA1CK2slFyZtGQ` (aus der Hue-App)
- Live-Credentials: `POST /security/vss/v1/home/{home}/credentials/live-stream`
- KVS-Signaling: SigV4-presigned WSS, `SDP_OFFER/ANSWER`, `ICE_CANDIDATE`
  (neuere Firmware nutzt das Feld `messageType`)
- Kamera ist immer DTLS-Client (`a=setup:active`) → Angebot mit `actpass`
- `tools/local_bridge/` enthält die Mac-Referenzstrecke und aiortc-Experimente

## Debug

```yaml
logger:
  logs:
    custom_components.hue_secure_camera: debug
```
