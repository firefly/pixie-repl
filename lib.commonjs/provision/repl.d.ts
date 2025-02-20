import type { Device } from "../device.js";
import type { AttestedDeviceInfo } from "../attest.js";
export interface ProvisionData {
    attest: Uint8Array;
    model: number;
    serial: number;
}
export interface GenerateKeyResult {
    cipherdata: Uint8Array;
    pubkey: Uint8Array;
    marker: number;
}
export declare class REPL {
    #private;
    readonly device: Device;
    readonly logs: Array<string>;
    constructor(device: Device);
    waitReady(): Promise<void>;
    _sendCommand(command: string, arg?: number | string | Uint8Array): Promise<Record<string, any>>;
    _readLine(): Promise<string>;
    _writeLine(line: string): Promise<boolean>;
    attest(): Promise<AttestedDeviceInfo>;
    reset(): Promise<void>;
    dump(): Promise<any>;
    generateKey(): Promise<GenerateKeyResult>;
    setProvisionData(data: ProvisionData): Promise<void>;
    burn(): Promise<void>;
}
//# sourceMappingURL=repl.d.ts.map