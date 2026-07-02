# Changelog

All notable changes to this project will be documented in this file.

## 2026.07.02 (API 03.00)

### Added
- `server_cert`: path to the server certificate (`.crt` file).
- `client_cert`: tuple of paths to the client certificate and key (`.crt`, `.key`), used for TLS mutual authentication.
- Warning when devices with unsupported API versions are found.

### Changed
- Supported device API version changed from `02.00` to `03.00`.

## 2026.06.02 (API 02.00)

### Added
- `CANSUB_ROOT_CERT`: path to the CANsub root certificate.

### Changed
- Transmit sequences (on the device) are deleted on bus open.

## 2026.06.01 (API 02.00)

### Fixed
- `CyclicSendTask` with `duration=None` now working.