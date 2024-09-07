//import { decodeConfig } from "./config.js";
import { Device } from "./device.js";
import { assert, hexlify } from "./utils.js";
import { CMDSPI_RDID } from "./protocol.js";
import { Stub } from "./stubs/esp32-c3.js";

import type { DeviceInfo } from "./device.js";

export const Magic = [ 0x6921506f, 0x1b31506f, 0x4881606f, 0x4361606f ];

export class DeviceEsp32c3 extends Device {
    readonly chipName = "ESP32-C3"

    readonly SPI_USR_OFFS = 0x18;
    //readonly SPI_USR1_OFFS = 0x1c;
    readonly SPI_USR2_OFFS = 0x20;
    readonly SPI_W0_OFFS = 0x58;

    readonly UART_DATE_REG_ADDR = 0x6000007c;

    readonly stub = Stub;

    // @TODO: Rename to spiRegisterAddress
    registerAddress(offset: number): number {
        return SPI_REG_BASE + offset;
    }

    // @TODO: Rename? setSpiLengthRegisters
    async _setDataLengths(mosiLength: number, misoLength: number): Promise<void> {
        const SPI_MOSI_DLEN_OFFS = 0x24;
        const SPI_MISO_DLEN_OFFS = 0x28;

        if (mosiLength > 0) {
            await this.writeSpiRegister(SPI_MOSI_DLEN_OFFS, mosiLength - 1);
        }
        if (misoLength > 0) {
            await this.writeSpiRegister(SPI_MISO_DLEN_OFFS, misoLength - 1);
        }
    }

    // ESP8266 maybe?
    /*
    _setDataLength(mosiLength: number, misoLength: number): Promise<void> {
        const SPI_DATA_LEN_REG = SPI_USR1_REG;
        const SPI_MOSI_BITLEN_S = 17;
        const SPI_MISO_BITLEN_S = 8;
        const mosiMask = mosiBits === 0 ? 0 : mosiBits - 1;
        const misoMask = misoBits === 0 ? 0 : misoBits - 1;
        const val = (misoMask << SPI_MISO_BITLEN_S) | (mosiMask << SPI_MOSI_BITLEN_S);
        await this.writeRegister(SPI_DATA_LEN_REG, val);
    }
    */

    async getDeviceInfo(): Promise<DeviceInfo> {
        const EFUSE_BASE = 0x60008800;

        const readWord = async (numWord: number) => {
            const block1Addr = EFUSE_BASE + 0x044;
            const addr = block1Addr + 4 * numWord;
            return  await this.readRegister(addr);
        }

        const word3 = await readWord(3);
        const word5 = await readWord(5);

        const pkgver = Number((word3 >> 21) & 0x07);
        //const rev = Number((value >> 18) & 0x07);

        const major = (word5 >> 24) & 0x03;
        const minor = (((word5 >> 23) & 0x01) << 3) + ((word3 >> 18) & 0x07);

        const flashId = await this.spiFlashCommand(CMDSPI_RDID, new Uint8Array(0), 24);

        let pkg = `unknown:pkg=${ pkgver }`;
        if (pkgver === 0) { pkg = "ESP32-C3"; }

        const chip = `${ pkg } (rev:${ major }.${ minor }; ${ FlashSizeMap[(flashId >> 16) & 0xff] || "unknown flash size" })`;


        // Make sure we are provisioned
        const version = await this.readRegister(EFUSE_BASE + 124);
        if (version === 0) {
            return {
                chip,
                modelName: "[unprovisioned]", modelNumber: 0, serialNumber: 0
            };
        }

        assert(version === 1, `unsupported provision version`, { version });

        const modelNumber = await this.readRegister(EFUSE_BASE + 128);
        const serialNumber = await this.readRegister(EFUSE_BASE + 132);

        let modelName = `[unknown model=0x${ modelNumber }]`;
        if ((modelNumber >> 8) === 1) {
            modelName = `Firefly Pixie (rev: ${ modelNumber & 0xff })`;
        }

        return { chip, modelName, modelNumber, serialNumber };
    }

    async getMacAddress(): Promise<string> {
        const MAC_EFUSE_REG = 0x60008800 + 0x044;

        const mac0 = BigInt(((await this.readRegister(MAC_EFUSE_REG)) & 0xffffffff) >>> 0);
        const mac1 = (await this.readRegister(MAC_EFUSE_REG + 4)) & 0xffff;

        return [
            hexlify(mac1 >> 8, 1),
            hexlify(mac1 & 0xff, 1),
            hexlify(mac0 >> 24n, 1),
            hexlify((mac0 >> 16n) & 0xffn, 1),
            hexlify((mac0 >> 8n) & 0xffn, 1),
            hexlify(mac0 & 0xffn, 1),
        ].join(":");
    }

    checkMagic(magic: number) {
        return Magic.indexOf(magic) >= 0;
    }
}


const SPI_REG_BASE = 0x60002000;

const FlashSizeMap: Record<number, string> = {
    0x12: "256KB",
    0x13: "512KB",
    0x14: "1MB",
    0x15: "2MB",
    0x16: "4MB",
    0x17: "8MB",
    0x18: "16MB",
};
