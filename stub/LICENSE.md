Licenses
========

This package is comprised of several other projects, each with their
own license.

This tool is designed as a provisioning tool to be used during the
manufacturing process, so distilling the relevant license
restrictions on various sections is not a priority.

Any portions of the "glue" I have written may be freely used under
the MIT License.

Otherwise, please see each project for their license restrictions:


ESPTool
-------

The base stub, configuration and build details are all directly
from the ESPTool. It was also instrumental in understanding the
ROM communications protocol.

Repo: https://github.com/espressif/esptool
License: (see LICENCE-esptool.md)


ESP-IDF
-------

Much of the hardware optimization code (including headers, SOC
registers and defines) come directly from the ESP-IDF mbedtls
port.

- Repo: https://github.com/espressif/esp-idf
- License: Apache 2 (see LICENSE-espidf.md)
