import type { SerialPort as _SerialPort } from "./serial.js";
export declare class SerialPort implements _SerialPort {
    #private;
    readonly port: any;
    _dtr: boolean;
    _data: Array<Uint8Array>;
    _dataLength: number;
    _dataStall: Promise<void>;
    constructor(port: any);
    get name(): string;
    connect(): Promise<void>;
    reset(bootMode?: boolean): Promise<void>;
    signal(signal: {
        dtr?: boolean;
        rts?: boolean;
    }): Promise<void>;
    write(data: Uint8Array): Promise<boolean>;
    read(): Promise<Uint8Array>;
    _read(): Promise<Uint8Array>;
    forget(): Promise<void>;
    static discover(): Promise<SerialPort>;
}
//# sourceMappingURL=serial-browser.d.ts.map