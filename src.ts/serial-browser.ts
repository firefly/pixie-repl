
import { assert } from "./utils/errors.js";
import { concat } from "./utils/data.js";
import { stall } from "./utils/timer.js";

import type { SerialPort as _SerialPort} from "./serial.js";


interface BrowserSerialPortOpenOptions {
    baudRate: number;
    bufferSize?: number;
    dataBits?: number;
    flowControl?: "none" | "hardware";
    parity?: "none" | "even" | "odd";
    stopBits?: 1 | 2;
}

interface BrowserSerialPortSignalOptions {
    dataTerminalReady?: boolean;
    requestToSend?: boolean;
    break?: boolean;
}

interface BrowserSerialPortInfo {
    usbVendorId?: number;
    usbProductId?: number;
}

interface BrowserSerialPortSignals {
    clearToSend: boolean;
    dataCarrierDetect: boolean;
    dataSetReady: boolean;
    ringIndicator: boolean;
}

interface BrowserSerialPortReader {
    read(): Promise<{ value: Uint8Array, done: boolean }>;
    cancel(): Promise<void>;
    releaseLock(): Promise<void>;
}

interface BrowserSerialPortWriter {
    write(data: Uint8Array): Promise<void>;
    releaseLock(): Promise<void>;
}

interface BrowserSerialPortReadableStream {
    getReader(): BrowserSerialPortReader;
}

interface BrowserSerialPortWritableStream {
    getWriter(): BrowserSerialPortWriter;
}

interface BrowserSerialPort {
    readable: BrowserSerialPortReadableStream;
    writable: BrowserSerialPortWritableStream;

    open(options: BrowserSerialPortOpenOptions): Promise<void>;
    close(): Promise<void>

    forget(): Promise<void>

    getInfo(): Promise<BrowserSerialPortInfo>

    getSignal(): Promise<BrowserSerialPortSignals>
    setSignal(options?: BrowserSerialPortSignalOptions): Promise<void>
}

interface BrowserSerialFilter {
    usbVendorId?: number;
    usbProductId?: number;
};

interface BrowserSerial {
    requestPort(filters?: { filters: Array<BrowserSerialFilter> }): Promise<BrowserSerialPort>;
    getPorts(): Promise<Array<BrowserSerialPort>>;
}

function isSerial(value: any): value is BrowserSerial {
    return true;
}

export class SerialPort implements _SerialPort {
    readonly port: any;

    _dtr: boolean;
    _data: Array<Uint8Array>;
    _dataLength: number;
    _dataStall: Promise<void>;

    #isOpen?: Promise<void>;

    constructor(port: any) {
        this.port = port;
        this._dtr = false;
        this._data = [ ];
        this._dataLength = 0;
        this._dataStall = stall(1);
    }

    get name(): string { return "serial-port"; }

    async connect(): Promise<void> {
        if (this.#isOpen) { return await this.#isOpen; }

        this.#isOpen = this.port.open({ baudRate: 115200, bufferSize: 4096 * 4 });

        await this.#isOpen;

        await stall(5);

        (async () => {
            while(this.port.readable) {
                const reader = this.port.readable.getReader();

                while (true) {
                    const { value, done } = await reader.read();
                    if (value && value.length) {
                        this._data.push(value);
                        this._dataLength += value.length;
                        //await stall(1);
                        //console.log("DATA", value, this._dataLength);
                    } else {
                        this._dataStall = stall(1);
                        await this._dataStall;
                    }
                    if (done) { break; }
                }

                console.log("CLOSED!");

                await reader.releaseLock();
            }
        })().then(console.log, console.log);
    }

    async reset(bootMode?: boolean): Promise<void> {
        // For info on setting vs clearing download mode:
        // See: https://github.com/espressif/arduino-esp32/issues/6762

        await this.signal({ rts: false });
        await this.signal({ dtr: false });
        await stall(100);

        if (bootMode) {
            await this.signal({ dtr: true });
            await this.signal({ rts: false });
            await stall(100);

            await this.signal({ rts: true });
            await this.signal({ dtr: false });
            await this.signal({ rts: true });
            await stall(100);
        }

        await this.signal({ rts: true });
        await this.signal({ dtr: false });
        await stall(100);
    }

    async signal(signal: { dtr?: boolean, rts?: boolean }): Promise<void> {
        if (signal.dtr != null) {
            this._dtr = signal.dtr;
            await this.port.setSignals({ dataTerminalReady: this._dtr });
        } else if (signal.rts != null) {
            await this.port.setSignals({ requestToSend: signal.rts });
            await this.signal({ dtr: this._dtr });
        } else {
            await this.signal({ dtr: false });
        }
    }

    async write(data: Uint8Array): Promise<boolean> {
        const writer = this.port.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return true;
    }

    async read(): Promise<Uint8Array> {
        await stall(100);
        const data = concat(this._data);
        this._data = [ ];
        this._dataLength = 0;
        return data;
    }

    async _read(): Promise<Uint8Array> {

        const result = [ ];

        const reader = this.port.readable.getReader();

        let timer: any = null;
        let cancelled = false;
        const reset = (duration: number) => {
            if (timer)  { clearTimeout(timer); }
            timer = setTimeout(() => {
                //reader.cancel();
                cancelled = true;
                timer = null;
            }, duration);
        };

        let read = 0;
        while (true) {
            reset(5);
            const { value, done } = await reader.read();
            if (value && value.length) {
                result.push(value);
                //read += value.length;
                await stall(1);
            } else if (cancelled) {
                break;
            } else {
                await stall(3);
            }
            if (read > 2048 || done) { break; }
        }

        if (timer) { clearTimeout(timer); }

        await reader.releaseLock();

        const data = concat(result);
        //console.log("READ", result.length, data.length, data.length ? data: 0);
        return data;
    }

    async forget(): Promise<void> {
        await this.port.forget();
    }

    static async discover(): Promise<SerialPort> {
        assert(("serial" in navigator) && isSerial(navigator.serial),
          `no Serial API present`, { });

        let port;
        const oldPorts = await navigator.serial.getPorts();
        if (oldPorts.length) {
            port = oldPorts[0];
        } else {
            port = await navigator.serial.requestPort({
                filters: [
                    { usbProductId: 4097, usbVendorId: 12346 }
                ]
            });
        }

        if (port == null) { throw new Error("no port selected"); }

        return new SerialPort(port);
    }
}
