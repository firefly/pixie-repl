Stub Flasher
============

This is based (very) heavily on the
[ESPTool stub](https://github.com/espressif/esptool), which is an
in-memory-only application that is installed to a device (via the
ROM repl `CMD_MEM_*` commands) to provide additional commands
beyond what the built-in ROM REPL provides, such as uploading
compressed binary images to be flashed to the device.


Building
--------

To build the stub, simply run `make` from this folder.

The Makefile generates the stub file for the ESP32-C3 which is used
by the Firefly at `build/stub_flasher.json`, which is used by the
JavaScript library.

The standard ESP-IDF compiler tool-chain must be present in the `PATH`.


License
-------

GPL License. See LICENSE.md.
