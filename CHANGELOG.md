# Changelog

All notable changes to this project will be documented in this file.

## 2026.08.17 (API 04.00)

### Added
- `max_device_time_skew`: device/host clock skew (s) tolerated before setting the device clock on open (`None`=never).
- `receive_own_messages`: receive the messages transmitted by the bus itself (default `False`).

### Changed
- Supported device API version changed from `03.00` to `04.00`.
- The device hostname is now resolved only once on bus open, reducing connection time.
- `data_bitrate` is now optional. When omitted, transmissions of FD frames are rejected.
- Updated shutdown sequence (using `DELETE` on the websocket resource after `shutdown_timeout` timeout).

### Removed
- `server_cert`: the server certificate is now always verified against the built-in CANsub root certificate.
  When connecting via an IP address, certificate hostname verification is automatically disabled
  (certificate chain verification remains active).

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