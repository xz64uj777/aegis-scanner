# Aegis

On-device file scanner for Android. Install the APK, grant **All files access**, then scan shared storage. Nothing is uploaded.

## Install on a Galaxy phone

1. Open **[Releases](https://github.com/xz64uj777/aegis-scanner/releases)** on the phone.
2. Download **Aegis.apk** (the latest `app-debug.apk`).
3. Open **Files → Downloads → Aegis.apk**.
4. If Samsung blocks it: **Settings → Security and privacy → Install unknown apps** → allow **Files** (or Chrome).
5. Open **Aegis → Allow all files**. On the system screen, turn Aegis **on**. Go back.
6. Tap **Scan allowed storage**.

GitHub Actions builds a new APK on every push to `main`.

## What All files access actually sees

- Yes: Downloads, Documents, DCIM, Movies, Telegram, WhatsApp media, and the rest of shared storage (`/storage/emulated/0`).
- No: other apps’ private data (`/data/data`), `/system`, or boot/firmware.

That last group is **Linux root**. Installing this APK does **not** root the phone. Rooting an S24 trips Knox and is a separate, risky choice.

## License

Use on devices you own.
