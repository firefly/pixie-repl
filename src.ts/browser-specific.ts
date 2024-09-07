import { SerialPort as _SerialPort} from "./serial.js";

export class SerialPort extends _SerialPort {
    readonly port: any;

    constructor(port: any) {
        super();
        this.port = port;
    }

    async connect(): Promise<void> {
    }

    async signal(signal: { dtr?: boolean, rts?: boolean }): Promise<void> {
    }

    async getSignal(): Promise<{ dtr: boolean, rts: boolean }> {
        return { dtr: false, rts: false };
    }

    async write(data: Uint8Array): Promise<boolean> {
        return false;
    }

    async read(): Promise<Uint8Array> {
        return new Uint8Array([ ]);
    }
}
