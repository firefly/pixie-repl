import type { SerialPort as _SerialPort } from "./serial.js";
export declare class SerialPort implements _SerialPort {
    #private;
    readonly filename: string;
    constructor(filename: string);
    get name(): string;
    connect(): Promise<void>;
    reset(bootMode?: boolean): Promise<void>;
    read(): Promise<Uint8Array>;
    signal(signal: {
        dtr?: boolean;
        rts?: boolean;
    }): Promise<void>;
    write(data: Uint8Array): Promise<boolean>;
    static discover(any?: boolean): SerialPort;
}
//# sourceMappingURL=serial-node.d.ts.map