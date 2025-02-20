/**
 *  A simple communication library for the ESP Devices over the
 *  Serial Protocol for the UART bootloader.
 *
 *  See:
 *    ESPTool:
 *    ESPTool-js:
 *    Protocol: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */
import { PartitionTable } from "./partition.js";
import type { SerialPort } from "./serial.js";
import type { Stub } from "./stubs/stub.js";
export type ProgressFunc = (percent: number) => void;
export declare const Sequences: Record<string, string>;
export interface DeviceInfo {
    chip: string;
    flashSize: number;
    modelName: string;
    model: number;
    serial: number;
    version: number;
}
export interface DeviceOptions {
    maxReadBuffer?: number;
    maxWriteBuffer?: number;
}
export interface ResultGenkey {
    cipherdata: Uint8Array;
    marker: Uint8Array;
    pubkeyN: Uint8Array;
}
export type DeviceRegister = "NULL" | "SPI_USR_OFFS" | "SPI_USR2_OFFS" | "SPI_W0_OFFS";
/**
 *  The **BaseDevice** class is a minimal implementation of
 *  of the Serial Protocol necessary to read/write and detect
 *  the device magic number.
 */
export declare abstract class Device {
    #private;
    readonly serial: SerialPort;
    constructor(serial: SerialPort, options?: DeviceOptions);
    get _maxReadBuffer(): number;
    get _maxWriteBuffer(): number;
    get _available(): number;
    get _backlog(): number;
    get isBootMode(): boolean;
    /**
     *  Halts any executing code on the device and enters ROM
     *  bootmode. The stub is not loaded at this point, but
     *  any attempt to use operations that require the stub
     *  will automatically upload it to RAM and start it.
     */
    connect(): Promise<number>;
    /**
     *  Resets the device (leaving bootmode) executing any
     *  firmware flashed on the device;
     */
    reset(): Promise<void>;
    _debug(data: string): void;
    /**
     *  Reads any data on the stream into the read buffer and returns
     *  the combined data.
     *
     *  Use [[_unread]] to place any data back on the read buffer
     *  to be processed in the future.
     */
    _read(): Promise<Uint8Array>;
    /**
     *  Read a SLIP packet, optionally matching the %%op%%. Returns
     *  ``null`` if no complete matching packet is found.
     *
     *  Any stray packets or bytes at the front of the read buffer
     *  are discarded.
     */
    _readSlipPacket(op?: number): Promise<null | Uint8Array>;
    _unread(data: Uint8Array): void;
    _write(data: Uint8Array): Promise<boolean>;
    _writeSlipPacket(data: Uint8Array): Promise<boolean>;
    _sync(): Promise<any>;
    /**
     *  Send a command to the connected device and parse the response.
     */
    _command(op: number, data?: Array<number> | Uint8Array, checksum?: number): Promise<Uint8Array>;
    _readRegister(address: number): Promise<number>;
    _enableStub(): Promise<string>;
    run(stub: Stub): Promise<void>;
    verifyFlash(offset: number, length: number): Promise<string>;
    _readFlashOld(offset: number, length: number, progress?: ProgressFunc): Promise<Uint8Array>;
    readFlash(offset: number, length: number, progress?: ProgressFunc): Promise<Uint8Array>;
    eraseFlash(offset: number, length: number): Promise<void>;
    writeFlashCompressed(offset: number, data: Uint8Array, progress?: ProgressFunc): Promise<string>;
    writeFlash(offset: number, data: Uint8Array, progress?: ProgressFunc): Promise<string>;
    readPartitionTable(): Promise<PartitionTable>;
    generateKey(): Promise<ResultGenkey>;
    abstract _getStub(): Promise<Stub>;
    abstract getDeviceInfo(): Promise<DeviceInfo>;
}
export declare function paddedBlock(data: Uint8Array, padding: number, size: number): Uint8Array;
//# sourceMappingURL=device.d.ts.map