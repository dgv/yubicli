# Changelog

## [2.0.0]

### Removed
- **PC/SC support is gone.** No more `libpcsclite` link, no `pcscd` daemon,
  no CCID driver needed — at build time or at runtime.

### Added
- Native USB CCID transport (`src/usb_ccid.rs`) built on pure-Rust `nusb`:
  direct `IccPowerOn` / `XfrBlock` / `IccPowerOff` messaging with the YubiKey.
- Zero system dependencies: the static musl binary builds with plain
  `cargo build` (not even kernel headers are needed).
- Actionable USB errors (device missing, permission denied, interface busy).
- `CHANGELOG.md`.

## [1.0.0]

- Initial release: YubiKey OATH CLI (list, code, add, delete, access, info, reset).
- PC/SC transport via the `pcsc` crate, statically linked against vendored
  `pcsc-lite` on `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`.
- GitHub releases with signed static binaries for x86_64 and aarch64.
