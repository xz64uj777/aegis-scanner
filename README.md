# Aegis

On-device scanner for Android. **Do not install v1.0.8** — that APK is a WebView and shows `https://localhost` / ERR_CONNECTION_REFUSED.

Use the **newest** Release after **v1.0.8**. The screen must say **AEGIS · NATIVE** and **This phone**. If you still see a webpage error, you installed the old file.

## Install on a Galaxy S24

1. Uninstall the old Aegis (Settings → Apps → Aegis → Uninstall).
2. Delete `app-debug.apk` from Downloads.
3. Open [Releases](https://github.com/xz64uj777/aegis-scanner/releases) — pick the **latest** tag, not v1.0.8.
4. Download `app-debug.apk`.
5. Files → Downloads → install. Allow unknown apps if Samsung asks.
6. Open Aegis → Allow all files → turn the switch on → Scan allowed storage.

## What it scans

Shared storage only: Downloads, Documents, DCIM, Telegram, WhatsApp media.

Not scanned without root: other apps’ private data (`/data`), `/system`, boot.

## License

Use on devices you own.
