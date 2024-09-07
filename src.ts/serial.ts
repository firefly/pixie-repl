
export abstract class SerialPort {
    abstract connect(): Promise<void>;

    abstract read(): Promise<Uint8Array>;
    abstract write(data: Uint8Array): Promise<boolean>;

    abstract signal(signal: { dtr?: boolean, rts?: boolean }): Promise<void>;
    abstract getSignal(): Promise<{ dtr: boolean, rts: boolean }>;
}
