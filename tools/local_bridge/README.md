# Hue Secure Camera — lokaler Live-Bridge (macOS)

Ziel: Live-Bild der Hue Secure Kamera auf dem Mac, ~15 fps, dauerhaft stabil.
Das ist die Forschungs-/Referenzstrecke, bis die HA-Integration denselben Weg
(SCTP-DataChannel + `{"streaming":true}`) nativ beherrscht.

## Warum nicht aiortc?

Reverse-Engineering und Tests (Mai 2026) haben gezeigt:

* Die Kamera ist **DTLS-Client** (`a=setup:active`) und damit laut RFC 8832
  auch **SCTP-Client**.
* Die Kamera (AWS KVS WebRTC C SDK) legt ihre SCTP-Session erst an, wenn sie
  DTLS-Applikationsdaten bekommt, und ruft dann selbst `usrsctp_connect()` auf
  (simultaneous open).
* aiortcs SCTP-Stack kommt mit dieser Reihenfolge nicht zurecht: entweder
  Deadlock (kein INIT) oder INIT wird mit falschem Tag/State verworfen.
  Ergebnis: 0–1 fps ohne funktionierenden DataChannel.

Deshalb macht hier ein echter Browser (libwebrtc, dieselbe Engine wie
`flutter_webrtc` in der Hue-App) das WebRTC. Der Browser öffnet den
DataChannel und sendet beim Öffnen `{"streaming": true}` — das ist der
Schalter, der die Kamera vom 1-fps-Trickle auf normales Streaming bringt.
Der Python-Server macht nur Auth + KVS-Signaling und liefert MJPEG/Snapshot.

## Dateien

| Datei | Zweck |
|---|---|
| `server.py` | Auth, KVS-Credentials, WSS-Signaling-Relay, Wake-Up, `/stream.mjpg`, `/snapshot.jpg` |
| `index.html` | WebRTC-Client (Offerer, DataChannel, Video, Auto-Reconnect, Frame-Push) |
| `hue_viewer3.py` | Reverse-Engineered Helper (OAuth PKCE, KVS-Presign, Wake, Creds) |

## Starten

```bash
python3 -m pip install aiohttp
cd tools/local_bridge
python3 server.py          # öffnet http://127.0.0.1:8777/
```

Beim ersten Start ohne gültiges Token: interaktiver Auth0-PKCE-Login im
Terminal (Redirect-URL einfügen). Tokens liegen in
`~/Library/Application Support/hue_camera/tokens.json` (0600) und werden
automatisch per Refresh-Token verlängert.

## Dauerbetrieb (launchd)

`~/Library/LaunchAgents/com.tim.huebridge.plist` startet `run.sh` beim Login und
hält den Prozess am Leben:

```bash
launchctl load   ~/Library/LaunchAgents/com.tim.huebridge.plist
launchctl unload ~/Library/LaunchAgents/com.tim.huebridge.plist
```

Nur **ein** Browser-Tab aktiv halten. Weitere Tabs bekommen `busy` und warten;
schließt man den aktiven Tab, übernimmt der nächste automatisch.

## Endpunkte

* `http://127.0.0.1:8777/` — Live-Ansicht
* `http://127.0.0.1:8777/stream.mjpg` — MJPEG (für HA `generic`/`mjpeg`-Kamera)
* `http://127.0.0.1:8777/snapshot.jpg` — letztes JPEG

## Gemessene Werte (LAN, TURN-Relay)

* 1920×1080, 15–18 fps, 0 Paketverlust, ~1,2 Mbit/s, RTT 65–135 ms
* 10+ Minuten Dauerlauf ohne Abbruch (Auto-Reconnect bei DTLS-Timeout)

## Nächste Schritte Richtung offizielle HA-Integration

1. Den DataChannel-Weg in `webrtc_client.py` nachbauen: eigener SCTP-Stack
   oder aiortc-Patch, der als DTLS-Server zuerst ein SCTP-INIT sendet und
   simultanes Open korrekt beantwortet.
2. `{"streaming":true}` senden, sobald der Kanal offen ist.
3. Danach `async_camera_image()`/MJPEG aus dem Track speisen (aktuell schon
   über die Bridge möglich).
