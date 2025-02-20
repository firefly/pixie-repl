//import { decodeConfig } from "./config.js";
import { getModelName } from "./attest.js";
import { Device } from "./device.js";
import { concat, fromLeBytes, hexlify, toLeBytes } from "./utils/data.js";
import { assert } from "./utils/errors.js";
import { CMDSPI_RDID, CMD_WRITE_REG } from "./protocol.js";
import { Stub } from "./stubs/esp32-c3.js";
export const Magic = [0x6921506f, 0x1b31506f, 0x4881606f, 0x4361606f];
// SPI_USR register flags
const SPI_USR_COMMAND = (1 << 31) >>> 0;
const SPI_USR_MISO = 1 << 28;
const SPI_USR_MOSI = 1 << 27;
const SPI_CMD_USR = 1 << 18;
const SPI_USR2_COMMAND_LEN_SHIFT = 28;
const SPI_USR_OFFS = 0x18;
//const SPI_USR1_OFFS" = 0x1c;
const SPI_USR2_OFFS = 0x20;
const SPI_W0_OFFS = 0x58;
const UART_DATE_REG_ADDR = 0x6000007c;
function registerAddress(offset) {
    return SPI_REG_BASE + offset;
}
function countOnes(value) {
    let count = 0;
    while (value) {
        value &= value - 1;
        count++;
    }
    return count;
}
export class DeviceEsp32c3 extends Device {
    async connect() {
        const magic = await super.connect();
        assert(Magic.indexOf(magic) >= 0, `invalid magic number: 0x${magic.toString(16)}`, {
            magic
        });
        return magic;
    }
    async _getStub() { return Stub; }
    // @TODO: Rename? setSpiLengthRegisters
    async _setDataLengths(mosiLength, misoLength) {
        const SPI_MOSI_DLEN_OFFS = 0x24;
        const SPI_MISO_DLEN_OFFS = 0x28;
        if (mosiLength > 0) {
            await this._writeSpiRegister(SPI_MOSI_DLEN_OFFS, mosiLength - 1);
        }
        if (misoLength > 0) {
            await this._writeSpiRegister(SPI_MISO_DLEN_OFFS, misoLength - 1);
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
    async _spiFlashCommand(command, data, responseBits) {
        assert(responseBits <= 32, "max SPI response length is 32 bits", {
            length: responseBits
        });
        assert(data.length <= 64, "max SPI request length is 64 bytes", {
            length: data.length
        });
        const oldSpiUsr = await this._readSpiRegister(SPI_USR_OFFS);
        const oldSpiUsr2 = await this._readSpiRegister(SPI_USR2_OFFS);
        await this._setDataLengths(data.length * 8, responseBits);
        {
            let flags = SPI_USR_COMMAND;
            if (responseBits > 0) {
                flags |= SPI_USR_MISO;
            }
            if (data.length) {
                flags |= SPI_USR_MOSI;
            }
            await this._writeSpiRegister(SPI_USR_OFFS, flags);
        }
        {
            const val = (7 << SPI_USR2_COMMAND_LEN_SHIFT) | command;
            await this._writeSpiRegister(SPI_USR2_OFFS, val);
        }
        {
            let reg = SPI_W0_OFFS;
            if (data.length === 0) {
                await this._writeSpiRegister(reg, 0);
            }
            else {
                // TODO: I think this logic is wrong; copied mostly
                // from esptool-js, but the padding looks backwards
                if (data.length % 4 != 0) {
                    const padding = new Uint8Array(data.length % 4);
                    data = concat([data, padding]);
                }
                // TODO: This also looks wrong; like it stops short?
                for (let i = 0; i < data.length - 4; i += 4) {
                    await this._writeSpiRegister(reg, fromLeBytes(data.slice(i, i + 4)));
                    reg += 4;
                }
            }
        }
        await this._writeSpiRegister(0x00, SPI_CMD_USR);
        for (let i = 0; i < 11; i++) {
            const val = (await this._readSpiRegister(0x00)) & SPI_CMD_USR;
            if (val == 0) {
                break;
            }
            assert(i < 10, "SPI command did not complete in time");
        }
        const status = await this._readSpiRegister(SPI_W0_OFFS);
        await this._writeSpiRegister(SPI_USR_OFFS, oldSpiUsr);
        await this._writeSpiRegister(SPI_USR2_OFFS, oldSpiUsr2);
        return status;
    }
    async _readSpiRegister(offset) {
        return await this._readRegister(registerAddress(offset));
    }
    async _writeSpiRegister(offset, value, mask, delayUs, delayAfterUs) {
        const address = registerAddress(offset);
        if (mask == null) {
            mask = 0xffffffff;
        }
        if (delayUs == null) {
            delayUs = 0;
        }
        const fields = [address, value, mask, delayUs];
        if (delayAfterUs) {
            fields.push(UART_DATE_REG_ADDR, 0, 0, delayAfterUs);
        }
        const packet = concat(fields.map((v) => toLeBytes(v, 4)));
        await this._command(CMD_WRITE_REG, packet);
    }
    async getDeviceInfo() {
        await this._enableStub();
        const EFUSE_BASE = 0x60008800;
        const readWord = async (numWord) => {
            const block1Addr = EFUSE_BASE + 0x044;
            const addr = block1Addr + 4 * numWord;
            return await this._readRegister(addr);
        };
        const word3 = await readWord(3);
        const word5 = await readWord(5);
        const pkgver = Number((word3 >> 21) & 0x07);
        const major = (word5 >> 24) & 0x03;
        const minor = (((word5 >> 23) & 0x01) << 3) + ((word3 >> 18) & 0x07);
        const flashId = await this._spiFlashCommand(CMDSPI_RDID, new Uint8Array(0), 24);
        let pkg = `unknown:pkg=${pkgver}`;
        if (pkgver === 0) {
            pkg = "ESP32-C3";
        }
        const size = FlashSizeMap[(flashId >> 16) & 0xff] || {};
        const flashSize = size.value || 0;
        const chip = `${pkg} (v${major}.${minor}; ${size.human || "unknown flash size"})`;
        // Make sure we are provisioned
        let version = await this._readRegister(EFUSE_BASE + 124);
        if (version === 0) {
            return {
                chip, flashSize, version,
                modelName: "[unprovisioned]", model: 0, serial: 0
            };
        }
        else if (version > 1) {
            // Versions greater than 1 include a zero count; currently
            // not used, but planned for the future
            assert(!(version & 1), `invalid version encoding; lsb-set`, {
                reason: "lsb-set", version
            });
            const zeros = (version >> 1) & 0x1f;
            version >>= 6;
            assert(zeros === (32 - 6 - countOnes(version)), `invalid version encoding; bad-zero-count`, {
                reason: "bad-zero-count", version
            });
        }
        assert(version === 1, `unsupported provision version`, { version });
        const model = await this._readRegister(EFUSE_BASE + 128);
        const serial = await this._readRegister(EFUSE_BASE + 132);
        const modelName = getModelName(model);
        return {
            chip, flashSize, modelName, model, serial, version
        };
    }
    async getMacAddress() {
        const MAC_EFUSE_REG = 0x60008800 + 0x044;
        const mac0 = BigInt(((await this._readRegister(MAC_EFUSE_REG)) & 0xffffffff) >>> 0);
        const mac1 = (await this._readRegister(MAC_EFUSE_REG + 4)) & 0xffff;
        return [
            hexlify(mac1 >> 8, 1),
            hexlify(mac1 & 0xff, 1),
            hexlify(mac0 >> 24n, 1),
            hexlify((mac0 >> 16n) & 0xffn, 1),
            hexlify((mac0 >> 8n) & 0xffn, 1),
            hexlify(mac0 & 0xffn, 1),
        ].join(":");
    }
}
const SPI_REG_BASE = 0x60002000;
const FlashSizeMap = {
    0x12: { human: "256KB", value: 256 * (1 << 10) },
    0x13: { human: "512KB", value: 512 * (1 << 10) },
    0x14: { human: "1MB", value: 1 * (1 << 20) },
    0x15: { human: "2MB", value: 2 * (1 << 20) },
    0x16: { human: "4MB", value: 4 * (1 << 20) },
    0x17: { human: "8MB", value: 8 * (1 << 20) },
    0x18: { human: "16MB", value: 16 * (1 << 20) },
};
//# sourceMappingURL=device-esp32c3.js.map