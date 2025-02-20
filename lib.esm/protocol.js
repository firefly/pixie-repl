/**
 *  Helpers and constants for the serial protocol used by the UART
 *  bootloader in the ESP32 ROM and ESPTool Stub loader.
 *
 *  See: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */
import { hexlify } from "./utils/data.js";
/////////////
// Commands supported by ROM and Stub
export const CMD_FLASH_BEGIN = 0x02;
export const CMD_FLASH_DATA = 0x03;
export const CMD_FLASH_END = 0x04;
export const CMD_MEM_BEGIN = 0x05;
export const CMD_MEM_END = 0x06;
export const CMD_MEM_DATA = 0x07;
export const CMD_SYNC = 0x08;
export const CMD_WRITE_REG = 0x09;
export const CMD_READ_REG = 0x0a;
export const CMD_SPI_SET_PARAMS = 0x0b;
export const CMD_SPI_ATTACH = 0x0d;
export const CMD_CHANGE_BAUDRATE = 0x0f;
export const CMD_FLASH_DEFL_BEGIN = 0x10;
export const CMD_FLASH_DEFL_DATA = 0x11;
export const CMD_FLASH_DEFL_END = 0x12;
export const CMD_SPI_FLASH_MD5 = 0x13;
////////////
// Commands supports only by Stub
export const CMD_ERASE_FLASH = 0xd0;
export const CMD_ERASE_REGION = 0xd1;
export const CMD_READ_FLASH = 0xd2;
export const CMD_RUN_USER_CODE = 0xd3;
/////////////
// Firefly extended commands
export const CMD_FFX_VERSION = 0x80;
export const CMD_FFX_BURN_EFUSE = 0x82;
export const CMD_FFX_BURN_KEY = 0x83;
export const CMD_FFX_VERIFY = 0x84;
export const CMD_FFX_READ_RLE = 0x85;
export const CMD_FFX_STIR_ENTROPY = 0x86;
export const CMD_FFX_GENKEY = 0x87;
/////////////
// SPI Commands
export const CMDSPI_RDID = 0x9f;
export function computeChecksum(data) {
    let value = 0xef;
    for (let i = 0; i < data.length; i++) {
        value ^= data[i];
    }
    return value;
}
export function syncPacket() {
    const packet = new Uint8Array(36);
    packet[0] = 0x07;
    packet[1] = 0x07;
    packet[2] = 0x12;
    packet[3] = 0x20;
    packet.fill(0x55, 4);
    return packet;
}
export function getErrorMessage(code) {
    switch (code) {
        // ROM Error codes
        case 0x05:
            return "Received message is invalid; parameters or length field is invalid";
        case 0x06:
            return "Failed to act on received message";
        case 0x07:
            return "Invalid CRC in message";
        case 0x08:
            return "Flash write error; flash checksum does not match";
        case 0x09:
            return "Flash read error; SPI read failed";
        case 0x0a:
            return "Flash read length error; SPI read request length is too long";
        case 0x0b:
            return "Deflate error";
        // Ffx Error codes
        case 0x86:
            return "Ffx Error: FFX_FAILED_KEYGEN";
        // Stub Error codes
        case 0xc0:
            return "Stub Error: ESP_BAD_DATA_LEN";
        case 0xc1:
            return "Stub Error: ESP_BAD_DATA_CHECKSUM";
        case 0xc2:
            return "Stub Error: ESP_BAD_BLOCKSIZE";
        case 0xc3:
            return "Stub Error: ESP_INVALID_COMMAND";
        case 0xc4:
            return "Stub Error: ESP_FAILED_SPI_OP";
        case 0xc5:
            return "Stub Error: ESP_FAILED_SPI_UNLOCK";
        case 0xc6:
            return "Stub Error: ESP_NOT_IN_FLASH_MODE";
        case 0xc7:
            return "Stub Error: ESP_INFLATE_ERROR";
        case 0xc8:
            return "Stub Error: ESP_NOT_ENOUGH_DATA";
        case 0xc9:
            return "Stub Error: ESP_TOO_MUCH_DATA";
        case 0xff:
            return "Stub Error: ESP_CMD_NOT_IMPLEMENTED";
    }
    return `unknown error: 0x${hexlify(code, 1)}`;
}
//# sourceMappingURL=protocol.js.map