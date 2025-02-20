export interface SerialPort {
    readonly name: string;
    connect(): Promise<void>;
    reset(bootMode?: boolean): Promise<void>;
    read(): Promise<Uint8Array>;
    write(data: Uint8Array): Promise<boolean>;
}
//# sourceMappingURL=serial.d.ts.map