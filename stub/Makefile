# Makefile to compile the flasher stub program
#
# Note that YOU DO NOT NEED TO COMPILE THIS IN ORDER TO JUST USE
# esptool.py - a precompiled version is embedded in esptool.py,
# so if you don't want to modify the stub code then you are good to go.
#
# See the comments in the top of the Makefile for parameters that
# you probably want to override.
#
# Copyright (c) 2016 Cesanta Software Limited & Angus Gratton
# All rights reserved
#
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
# Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Adapted from Cesanta's original Makefile at
# https://github.com/cesanta/fnc/tree/master/common/platforms/esp8266/stubs

# Override these variables on the command line
# or set them in a local.mk
-include local.mk

# Prefix for each cross compiler (can include a directory path)
# These can be overriden via environment variables or on the make command line
CROSS_32C3 ?= riscv32-esp-elf-

# Python command to invoke wrap_stub.py
WRAP_STUB ?= ./wrap_stub.py

# Pass V=1 to see the commands being executed by make
ifneq ("$(V)","1")
Q = @
endif

STUB = stub_flasher
SRCS = stub_flasher.c slip.c stub_commands.c stub_write_flash.c stub_io.c \
  mbedtls/rsa.c mbedtls/rsa_alt_helpers.c \
  mbedtls/bignum.c mbedtls/bignum_alt.c mbedtls/bignum_core.c \
    mbedtls/esp_bignum.c \
  mbedtls/mpi_hal.c mbedtls/mpi_periph.c \
  mbedtls/platform.c mbedtls/platform_util.c mbedtls/memory_buffer_alloc.c \
    mbedtls/constant_time.c

BUILD_DIR = build

STUB_ELF_32C3 = $(BUILD_DIR)/$(STUB)_32c3.elf
STUB_JSON = $(BUILD_DIR)/$(STUB).json

.PHONY: all clean embed

all: $(STUB_JSON)

$(BUILD_DIR):
	$(Q) mkdir $@

CFLAGS = -std=c99 -Wall -Werror -Os \
         -mtext-section-literals -mlongcalls -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld
CFLAGS_ESPRISCV32 = -std=c99 -Wall -Werror -Os \
		 -march=rv32imc -msmall-data-limit=0 \
         -nostdlib -fno-builtin -flto \
         -Wl,-static -g -ffunction-sections -Wl,--gc-sections -Iinclude -Lld
LDLIBS = -lgcc

$(STUB_ELF_32C3): $(SRCS) $(BUILD_DIR) ld/stub_32c3.ld
	@echo "  CC(32C3)   $^ -> $@"
	$(Q) $(CROSS_32C3)gcc $(CFLAGS_ESPRISCV32) -DESP32C3=1 -Tstub_32c3.ld -Wl,-Map=$(@:.elf=.map) -o $@ $(filter %.c, $^) $(LDLIBS)

$(STUB_JSON): $(STUB_ELF_32C3) wrap_stub.py
	@echo "  WRAP $^ -> $@"
	$(Q) $(WRAP_STUB) --out-file $@ $(filter %.elf,$^)
	$(Q) cat ./prefix-ts.txt $@ > ../src.ts/stubs/esp32-c3.ts

clean:
	$(Q) rm -rf $(BUILD_DIR)
