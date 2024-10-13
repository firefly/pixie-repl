
export interface SerialPort {
    readonly name: string;

    connect(): Promise<void>;
    reset(bootMode?: boolean): Promise<void>;

    read(): Promise<Uint8Array>;
    write(data: Uint8Array): Promise<boolean>;

    //signal(signal: { dtr?: boolean, rts?: boolean }): Promise<void>;
    //getSignal(): Promise<{ dtr: boolean, rts: boolean }>;
}
