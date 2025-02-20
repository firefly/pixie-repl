import { Device } from "./device.js";
import type { DeviceInfo } from "./device.js";
export declare const Magic: number[];
export declare class DeviceEsp32c3 extends Device {
    connect(): Promise<number>;
    _getStub(): Promise<{
        text: string;
        text_start: number;
        entry: number;
        text_size: number;
        data: string;
        data_start: number;
        data_size: number;
        total_size: number;
    }>;
    _setDataLengths(mosiLength: number, misoLength: number): Promise<void>;
    _spiFlashCommand(command: number, data: Uint8Array, responseBits: number): Promise<number>;
    _readSpiRegister(offset: number): Promise<number>;
    _writeSpiRegister(offset: number, value: number, mask?: number, delayUs?: number, delayAfterUs?: number): Promise<void>;
    getDeviceInfo(): Promise<DeviceInfo>;
    getMacAddress(): Promise<string>;
}
//# sourceMappingURL=device-esp32c3.d.ts.map