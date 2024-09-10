/**
 *  A simple communication library for the ESP Devices over the
 *  Serial Protocol for the UART bootloader.
 *
 *  See:
 *    ESPTool: 
 *    ESPTool-js: 
 *    Protocol: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */

import { randomBytes } from "ethers";

import { slipDecode, slipEncode } from "./slip.js";
import {
    CMD_FFX_GENKEY, CMD_FFX_STIR_ENTROPY, CMD_FFX_VERIFY, CMD_FFX_VERSION,
    CMD_FLASH_BEGIN, CMD_FLASH_DATA, CMD_FLASH_END,
    CMD_MEM_BEGIN, CMD_MEM_DATA, CMD_MEM_END, CMD_READ_REG,
    CMD_READ_FLASH, CMD_WRITE_REG, CMD_SYNC,
    computeChecksum, getErrorMessage, syncPacket
} from "./protocol.js";
import {
    assert, concat, fromLeBytes, hexlify, md5, sha256, stall, toLeBytes
} from "./utils.js";

import type { SerialPort } from "./serial.js";
import type  { Stub } from "./stubs/stub.js";


export const Sequences: Record<string, string> = {
    Reset: "R 100 D 50 N",
    ResetUsb: "N 100 D 100 R 100 R 100 N",
    ResetHard: "R 100 N",
}

export interface DeviceInfo {
    chip: string;
    modelName: string;
    modelNumber: number;
    serialNumber: number;
}

export interface DeviceOptions {
    maxReadBuffer?: number;
    maxWriteBuffer?: number;
};

export interface ResultGenkey {
    ciphertext: Uint8Array,
    pubkeyN: Uint8Array
}

/**
 *  The **BaseDevice** class is a minimal implementation of
 *  of the Serial Protocol necessary to read/write and detect
 *  the device magic number.
 */
export abstract class Device {
    readonly serial: SerialPort;

    #readBuffer: Array<Uint8Array>;
    #writeBuffer: Array<Uint8Array>

    #maxReadBuffer: number;
    #maxWriteBuffer: number;

    #stub: string;

    constructor(serial: SerialPort, options?: DeviceOptions) {
        if (options == null) { options = { }; }

        this.serial = serial;

        this.#readBuffer = [ ];
        this.#writeBuffer = [ ];
        this.#maxReadBuffer = getValue("invalid options.maxReadBuffer", options.maxReadBuffer, 1 << 20);
        this.#maxWriteBuffer = getValue("invalid options.maxWriteBuffer", options.maxReadBuffer, 1 << 20);

        this.#stub = "";
    }

    get _maxReadBuffer(): number { return this.#maxReadBuffer; }
    get _maxWriteBuffer(): number { return this.#maxWriteBuffer; }

    get _available(): number { return sum(this.#readBuffer); }
    get _backlog(): number { return sum(this.#writeBuffer); }

    async connect(): Promise<number> {
        await this.serial.connect();

        await this._reset();
        await stall(50);
        await this._read();  // Flush

        await this._sync();
        await stall(100);
        await this._read();  // Flush

        const magic = await this._readRegister(0x40001000);

        assert(this.checkMagic(magic), `invalid magic number: ${ magic}`, {
            magic
        });

        return magic;
    }

    _debug(data: string): void {
        console.log("DEBUG", data);
    }

    /**
     *  Reads any data on the stream into the read buffer and returns
     *  the combined data.
     *
     *  Use [[_unread]] to place any data back on the read buffer
     *  to be processed in the future.
     */
    async _read(): Promise<Uint8Array> {
        const input = await this.serial.read();
        if (input.length) { this.#readBuffer.push(input); }

        const result = concat(this.#readBuffer);
        this.#readBuffer = [ ];
        return result;
    }

    /**
     *  Read a SLIP packet, optionally matching the %%op%%. Returns
     *  ``null`` if no complete matching packet is found.
     *
     *  Any stray packets or bytes at the front of the read buffer
     *  are discarded.
     */
    async _readSlipPacket(op?: number): Promise<null | Uint8Array> {
        const data = await this._read();

        const slip = slipDecode(data);

        // No packet found; maybe we need more bytes
        if (slip == null) {
            this._unread(data);
            return null;
        }

        // Place unconsumed bytes back onto the read buffer
        this._unread(slip.remaining);

        if ("debug" in slip) {
            this._debug(slip.debug);
            return null;
        }

        if (op == null) { return slip.data; }

        assert(slip.data[0] === 1, "invalid direction", {
            direction: slip.data[0],
            packet: slip.data
        });

        // @TODO: Skip unmatched operations
        if (slip.data[1] !== op) {
            console.log("unexpected command; @TODO: skip", {
                slip, op: `0x${ op.toString(16) }`
            });
        }

        if (op === CMD_READ_REG || op === CMD_FFX_VERSION) {
            return slip.data.slice(4, 8);
        }

        const result = slip.data.slice(8);
        const status = result.slice(result.length - (this.#stub ? 2: 4));

        assert(status[0] === 0, getErrorMessage(status[1]), {
            code: status[1], data: slip.data
        });

        return result.slice(0, result.length - status.length);
    }

    _unread(data: Uint8Array): void {
        this.#readBuffer.unshift(data);
    }

    async _write(data: Uint8Array): Promise<boolean> {
        return this.serial.write(data);
    }

    async _writeSlipPacket(data: Uint8Array): Promise<boolean> {
        return this._write(slipEncode(data));
    }

    /**
     *  Reset the connected device, optionally providing a reset
     *  %%sequence%% for fine control over the DTR/RTS signals.
     */
    async _reset(sequence?: string): Promise<void> {
        if (sequence == null) { sequence = Sequences.ResetUsb; }

        for (const cmd of sequence.split(/ /g)) {
            switch (cmd) {
                case "N":
                    await this.serial.signal({ });
                    break;
                case "D":
                    await this.serial.signal({ dtr: true });
                    break;
                case "R":
                    await this.serial.signal({ rts: true });
                    break;
                case "DR": case "RD":
                    await this.serial.signal({ dtr: true, rts: true });
                    break;
                default:
                    await stall(parseInt(cmd));
            }
        }
    }

    async _sync(): Promise<any> {
        return await this._command(CMD_SYNC, syncPacket());
    }

    /**
     *  Send a command to the connected device and parse the response.
     */
    async _command(op: number, data?: Array<number> | Uint8Array, checksum?: number): Promise<Uint8Array> {
        if (Array.isArray(data)) { data = new Uint8Array(data); }

        const packet = new Uint8Array(8 + (data ? data.length: 0));
        packet[0] = 0x00;
        packet[1] = op;

        if (data) {
            packet.set(toLeBytes(data.length, 2), 2);
            packet.set(data, 8);
        }

        await stall(2);
        if (checksum) { packet.set(toLeBytes(checksum, 4), 4); }

        await this._writeSlipPacket(packet);

        let waitTime = 30;

        // Generating an RSA key can take a while
        if (op === CMD_FFX_GENKEY) { waitTime = 100; }

        // Try reading up to a timeout
        for (let i = 0; i < ((waitTime * 1000) / 10); i++) {
            const result = await this._readSlipPacket(op);
            if (result) { return result; }
            await stall(10);
        }

        assert(false, `command failed to return a response`, {
            op, data, checksum
        });
    }

    async _readRegister(address: number): Promise<number> {
        const result = await this._command(CMD_READ_REG, toLeBytes(address, 4));
        return fromLeBytes(result);
    }

    async _spiFlashCommand(command: number, data: Uint8Array, responseBits: number): Promise<number> {
        assert(responseBits <= 32, "max SPI response length is 32 bits", {
            length: responseBits
        });

        assert(data.length <= 64, "max SPI request length is 64 bytes", {
            length: data.length
        });

        const oldSpiUsr = await this._readSpiRegister(this.SPI_USR_OFFS);
        const oldSpiUsr2 = await this._readSpiRegister(this.SPI_USR2_OFFS);

        await this._setDataLengths(data.length * 8, responseBits);

        {
            let flags = SPI_USR_COMMAND;
            if (responseBits > 0) { flags |= SPI_USR_MISO; }
            if (data.length) { flags |= SPI_USR_MOSI; }
            await this._writeSpiRegister(this.SPI_USR_OFFS, flags);
        }

        {
            const val = (7 << SPI_USR2_COMMAND_LEN_SHIFT) | command;
            await this._writeSpiRegister(this.SPI_USR2_OFFS, val);
        }

        {
            let reg = this.SPI_W0_OFFS;

            if (data.length === 0) {
                await this._writeSpiRegister(reg, 0);
            } else {
                // TODO: I think this logic is wrong; copied mostly
                // from esptool-js, but the padding looks backwards
                if (data.length % 4 != 0) {
                    const padding = new Uint8Array(data.length % 4);
                    data = concat([ data, padding ]);
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
            if (val == 0) { break; }
            assert(i < 10, "SPI command did not complete in time");
        }

        const status = await this._readSpiRegister(this.SPI_W0_OFFS);

        await this._writeSpiRegister(this.SPI_USR_OFFS, oldSpiUsr);
        await this._writeSpiRegister(this.SPI_USR2_OFFS, oldSpiUsr2);

        return status;
    }

    async _readSpiRegister(offset: number): Promise<number> {
        return await this._readRegister(this.registerAddress(offset));
    }

    async _writeSpiRegister(offset: number, value: number, mask?: number, delayUs?: number, delayAfterUs?: number): Promise<void> {
        const address = this.registerAddress(offset);

        if (mask == null) { mask = 0xffffffff; }
        if (delayUs == null) { delayUs = 0; }

        const fields = [ address, value, mask, delayUs ];
        if (delayAfterUs) {
            fields.push(this.UART_DATE_REG_ADDR, 0, 0, delayAfterUs);
        }

        const packet = concat(fields.map((v) => toLeBytes(v, 4)));

        await this._command(CMD_WRITE_REG, packet);
    }

    async #uploadMemory(offset: number, data: Uint8Array, entryPoint?: number): Promise<void> {
        const blockCount = Math.ceil(data.length / RAM_BLOCK_SIZE);

        await this._command(CMD_MEM_BEGIN, concat([
            toLeBytes(data.length, 4),
            toLeBytes(blockCount, 4),
            toLeBytes(RAM_BLOCK_SIZE, 4),
            toLeBytes(offset, 4),
        ]));

        // docs say to pad the blocks, but that seems to break CRC
        for (let i = 0; i < blockCount; i++) {
            const start = i * RAM_BLOCK_SIZE;

            let block = data.slice(start, start + RAM_BLOCK_SIZE);

            await this._command(CMD_MEM_DATA, concat([
                toLeBytes(block.length, 4),
                toLeBytes(i, 4),
                toLeBytes(0, 4),
                toLeBytes(0, 4),
                block
            ]), computeChecksum(block));
        }

        if (entryPoint != null) {
            await this._command(CMD_MEM_END, concat([
                toLeBytes((entryPoint === 0) ? 1: 0, 4),
                toLeBytes(entryPoint, 4),
            ]));

            // Wait for the stub to start
            let ohai: Uint8Array | null = null;
            while (ohai == null) {
                await stall(10);
                ohai = await this._readSlipPacket();
                if (ohai && hexlify(ohai) === "4f484149") { break; }
            }
        }
    }

    async _enableStub(): Promise<string> {
        if (!this.#stub) {
            await this.#uploadMemory(this.stub.text_start, Buffer.from(this.stub.text, "base64"));
            await this.#uploadMemory(this.stub.data_start, Buffer.from(this.stub.data, "base64"), this.stub.entry);

            const version = fromLeBytes(await this._command(CMD_FFX_VERSION));
            const major = version >> 24;
            const minor = (version >> 16) & 0xff;
            const patch = version & 0xffff;

            this.#stub = `${ major }.${ minor }.${ patch }`;
        }

        return this.#stub;
    }

    async verifyFlash(offset: number, length: number): Promise<string> {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });

        return hexlify(await this._command(CMD_FFX_VERIFY, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4)
        ])));
    }

    async readFlash(offset: number, length: number): Promise<Uint8Array> {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });

        const blockSize = 0x1000;

        await this._command(CMD_READ_FLASH, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4),
            toLeBytes(blockSize, 4),
            toLeBytes(1024, 4),
        ]));

        let readCount = 0;
        const blocks: Array<Uint8Array> = [ ];
        let pending: Uint8Array = new Uint8Array(0);
        while (readCount < length) {
            pending = concat([ pending, await this._read() ]);
            if (pending.length == 0) { continue; }

            while (true) {
                const block = slipDecode(pending);
                if (block == null) { break; }
                if ('debug' in block) {
                    this._debug(block.debug);
                    continue;
                }
                blocks.push(block.data);

                readCount += block.data.length;
                pending = block.remaining;

                // ACK
                await this._writeSlipPacket(toLeBytes(readCount, 4));
            }
        }

        const result = concat(blocks);
        while (true) {
            const _checksum = slipDecode(await this._read());
            if (_checksum == null) {
                await stall(5);
                continue;
            }
            if ("debug" in _checksum) {
                this._debug(_checksum.debug);
                continue;
            }
            const checksum = hexlify(_checksum.data);
            const computed = hexlify(md5(result));
            assert(checksum === computed, `checksum failed`, {
                checksum, computed
            });
            break;
        }

        return result;
    }

    async writeFlash(offset: number, data: Uint8Array, reset?: boolean): Promise<string> {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });

        const blockCount = Math.ceil(data.length / FLASH_BLOCK_SIZE);

        await this._command(CMD_FLASH_BEGIN, concat([
            toLeBytes(data.length, 4),
            toLeBytes(blockCount, 4),
            toLeBytes(FLASH_BLOCK_SIZE, 4),
            toLeBytes(offset, 4),
        ]));

        // docs say to pad the blocks, but that seems to break CRC
        for (let i = 0; i < blockCount; i++) {
            const start = i * FLASH_BLOCK_SIZE;

            let block = data.slice(start, start + FLASH_BLOCK_SIZE);

            await this._command(CMD_FLASH_DATA, concat([
                toLeBytes(block.length, 4),
                toLeBytes(i, 4),
                toLeBytes(0, 4),
                toLeBytes(0, 4),
                block
            ]), computeChecksum(block));
        }

        const checksum = await this.verifyFlash(offset, data.length);
        const expected = hexlify(sha256(data));
        assert(checksum === expected, `writeFlash failed checksum`, {
            checksum, expected
        });

        if (reset) {
            await stall(3);
            await this._command(CMD_FLASH_END, toLeBytes(0, 4));
        }

        return checksum;
    }

    async genkey(): Promise<ResultGenkey> {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });

        const getKey = (tag: string) => {
            return ({ C: 'ciphertext', P: 'pubkeyN' }[tag]) || "unknown";
        };

        // Add some extra entropy to the device
        await this._command(CMD_FFX_STIR_ENTROPY, randomBytes(32));

        // Generate an RSA keypair on-device
        const data = await this._command(CMD_FFX_GENKEY);

        // Decode the result
        const result: any = { };

        // Data encoding; [ TAG, length_hi, length_lo, data<length>, ... ]
        let offset = 0;
        while (offset < data.length) {
            const tag = String.fromCharCode(data[offset]);
            const length = (data[offset + 1] << 8) | data[offset + 2];
            result[getKey(tag)] = data.slice(offset + 3, offset + 3 + length);
            offset += 3 + length;
        }

        return result;
    }


    /**
     *  Returns true if this **Device** supports the %%magic%%
     *  number. This is used in connect to validate the expected
     *  devices matches the connected device.
     */
    abstract checkMagic(magic: number): boolean;

    abstract stub: Stub;

    abstract getDeviceInfo(): Promise<DeviceInfo>;

    abstract registerAddress(register: number): number;

    abstract readonly SPI_USR_OFFS: number;
    abstract readonly SPI_USR2_OFFS: number;
    abstract readonly SPI_W0_OFFS: number;

    abstract _setDataLengths(mosiLength: number, misoLength: number): Promise<void>;

    abstract readonly UART_DATE_REG_ADDR: number;
}

// SPI_USR register flags
const SPI_USR_COMMAND = (1 << 31) >>> 0;
const SPI_USR_MISO = 1 << 28;
const SPI_USR_MOSI = 1 << 27;

const SPI_CMD_USR = 1 << 18;

const SPI_USR2_COMMAND_LEN_SHIFT = 28;

function getValue(message: string, value: undefined | number, fallback: number): number {
    if (value == null) { return fallback; }
    assert(Number.isInteger(value), `${ message }: ${ value }`, { value });
    if (value < -1) { return -1; }
    return value;
}

function sum(values: Array<Uint8Array>): number {
    return values.reduce((accum, value) => (accum + value.length), 0);
}

export function paddedBlock(data: Uint8Array, padding: number, size: number): Uint8Array {
    if (data.length === size) { return data; }

    const result = new Uint8Array(size);
    result.fill(padding);
    result.set(data, 0);

    return result;
}

const RAM_BLOCK_SIZE = 0x1800;
const FLASH_BLOCK_SIZE = 0x4000;
