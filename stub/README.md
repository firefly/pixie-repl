Stub Flasher
============

This is based (very) heavily on the
[ESPTool stub](https://github.com/espressif/esptool), which is an
in-memory-only application that is installed to a device to
provide additional capabilities beyond what the built-in ROM
REPL provides, such as uploading compressed binary images to be
flashed to the device.

The changes included in this Stub are:

- on-device RSA keypair generation
- eFuse burning

The main purpose is to facilitate provisioning new Firefly devices:

- Burn eFuses for the serial number and model number
- Generate a secure, on-device RSA attestion key
- Write the attestion public key and cipher data to flash
- Burn the attestation key hash to eFuses
- Write the attestation proof signature to flash
- Write the Recovery App to the factory partition
- Write and configure the shipped firmware to OTA-1

In the future it will also have support for configuring secure-boot.


License
-------

GPL License. See LICENSE.md.
