/**
 *  Helpers and constants for the serial protocol used by the UART
 *  bootloader in the ESP32 ROM and ESPTool Stub loader.
 *
 *  See: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */
export declare const CMD_FLASH_BEGIN = 2;
export declare const CMD_FLASH_DATA = 3;
export declare const CMD_FLASH_END = 4;
export declare const CMD_MEM_BEGIN = 5;
export declare const CMD_MEM_END = 6;
export declare const CMD_MEM_DATA = 7;
export declare const CMD_SYNC = 8;
export declare const CMD_WRITE_REG = 9;
export declare const CMD_READ_REG = 10;
export declare const CMD_SPI_SET_PARAMS = 11;
export declare const CMD_SPI_ATTACH = 13;
export declare const CMD_CHANGE_BAUDRATE = 15;
export declare const CMD_FLASH_DEFL_BEGIN = 16;
export declare const CMD_FLASH_DEFL_DATA = 17;
export declare const CMD_FLASH_DEFL_END = 18;
export declare const CMD_SPI_FLASH_MD5 = 19;
export declare const CMD_ERASE_FLASH = 208;
export declare const CMD_ERASE_REGION = 209;
export declare const CMD_READ_FLASH = 210;
export declare const CMD_RUN_USER_CODE = 211;
export declare const CMD_FFX_VERSION = 128;
export declare const CMD_FFX_BURN_EFUSE = 130;
export declare const CMD_FFX_BURN_KEY = 131;
export declare const CMD_FFX_VERIFY = 132;
export declare const CMD_FFX_READ_RLE = 133;
export declare const CMD_FFX_STIR_ENTROPY = 134;
export declare const CMD_FFX_GENKEY = 135;
export declare const CMDSPI_RDID = 159;
export declare function computeChecksum(data: Uint8Array): number;
export declare function syncPacket(): Uint8Array;
export declare function getErrorMessage(code: number): string;
//# sourceMappingURL=protocol.d.ts.map