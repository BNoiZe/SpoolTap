# SpoolTap

A small tray app that connects a USB NFC reader to [Spoolman](https://github.com/Donkie/Spoolman).
Tap a spool's tag and SpoolTap shows the spool; tap an unknown tag and you can create a spool from
Spoolman's filament database and link the tag in one step. It can also write
[Creality CFS](https://github.com/DnG-Crafts/K2-RFID) data to MIFARE Classic tags.

Built with Rust and [Tauri 2](https://tauri.app); runs on macOS, Windows and Linux.

## Features

- **Tap to look up** – the tag's UID is reported to Spoolman (`POST /api/v1/tag/scan`); a known tag
  opens an info window with material, remaining weight, location, tags and CFS data.
- **Create & link in one step** – for an unknown tag, search your filaments or the SpoolmanDB
  catalog, then create the spool (importing vendor and filament if needed) and link the tag.
- **Link to an existing spool**, with the number of tags each spool already has.
- **Weigh** – enter the gross weight from a scale; Spoolman computes the remaining filament.
- **Second tag** – give the other side of a spool a tag with the same data.
- **Creality CFS** – read, write and erase CFS records (MIFARE Classic 1K) so a K1/K2 CFS
  recognises the spool. Writing after weighing updates the length on the tag.
- **Delete** – wipe a tag and unlink it, optionally marking the spool empty and archived.
- **Spoolman update check** in the tray menu and settings.

## Download

Installers for macOS (Apple Silicon + Intel), Windows and Linux are on the
[Releases](https://github.com/BNoiZe/SpoolTap/releases) page. The macOS app is not notarized:
open it the first time with right-click → *Open*.

## Requirements

- Spoolman **0.27 or newer** (tag scanning API).
- A PC/SC NFC reader, tested with the **ACS ACR122U**.
  - macOS: works out of the box.
  - Windows: usually works out of the box (vendor driver if not).
  - Linux: `pcscd` running (`sudo apt install pcscd`).
- For CFS data: **MIFARE Classic 1K** tags. Other tags (e.g. NTAG) can be linked, but carry no CFS data.

## Build

```bash
npm install
npx tauri build
```

The bundle ends up in `src-tauri/target/release/bundle/`. Build on the platform you are targeting.
Linux additionally needs `libpcsclite-dev`, `libwebkit2gtk-4.1-dev` and `libayatana-appindicator3-dev`.

Run the tests with `cargo test` in `src-tauri/`.

Pushing a version tag (`git tag v1.2.3 && git push --tags`) builds all platforms in GitHub Actions
and uploads them to a draft release.

## Notes

- SpoolTap sends an explicit `User-Agent: SpoolTap/1.0`. The default macOS agent of an unversioned
  app (`… (unknown version) … Darwin/…`) together with a JSON POST matches the Suricata rule
  *ET MALWARE BlueNoroff APT Related Activity M1* (sid 2049882), which made IPS-enabled routers
  block the machine.
- Debug builds open sample windows with `SPOOLTAP_DEMO=1` (info) or `SPOOLTAP_DEMO=settings`.

## Credits

- [Spoolman](https://github.com/Donkie/Spoolman) by Donkie.
- CFS tag format, keys and material database from [K2-RFID](https://github.com/DnG-Crafts/K2-RFID) by DnG-Crafts.

## License

MIT
