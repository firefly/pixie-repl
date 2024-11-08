Stub Flasher
============

This is based (very) heavily on the
[ESPTool stub](https://github.com/espressif/esptool), which is an
in-memory-only application that is installed to a device (via the
ROM repl `CMD_MEM_*` commands) to provide additional commands
beyond what the built-in ROM REPL provides, such as uploading
compressed binary images to be flashed to the device.

The commands provided (in additional to the ESPTool Stub) include:

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


Building
--------

To build the stub, simply run `make` from this folder.

The Makefile generates the stub file for the ESP32-C3 which is used
by the Firefly at `build/stub_flasher.json`, which is used by the
JavaScript library.



License
-------

GPL License. See LICENSE.md.
