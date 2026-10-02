# Fissure browser extension

A toolbar button that scans the page you're on using your **local** Fissure
service — the reliable, reframed version of the "floating scan button" idea. The
extension reads the active tab's URL directly (no screenshot/OCR), and **every
scan requires an explicit authorization click** before it runs.

## Use it

1. Start the local server (prints a bearer token):
   ```bash
   python -m fissure.server        # or: fissure-server
   ```
2. Load the extension (once):
   - Chrome/Edge → `chrome://extensions` → enable **Developer mode** →
     **Load unpacked** → select this `extension/` folder.
3. Click the **Fissure** toolbar button on a page you are authorized to test:
   - paste the bearer token from the server console (remembered after the first time),
   - tick **"I am authorized to security-test this target"**,
   - click **Scan this page**.
4. When it finishes, click **Open report** for the full HTML findings report.

## Notes / safety

- The server refuses public targets unless the scan is started with
  `allow_public` — by default it only scans `localhost`/private hosts.
- The authorization checkbox is mandatory; the server also re-validates scope
  server-side (the extension's claim is not trusted).
- The server binds to `127.0.0.1` only and requires the bearer token on every
  request. The report link carries the token as a query param so a normal tab
  can open it; this is a localhost-only convenience.
- Icons are intentionally omitted to keep the unpacked extension minimal; add
  `icons` to `manifest.json` if you want a custom toolbar icon.
