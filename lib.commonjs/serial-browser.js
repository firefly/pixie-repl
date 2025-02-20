"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SerialPort = void 0;
const errors_js_1 = require("./utils/errors.js");
const data_js_1 = require("./utils/data.js");
const timer_js_1 = require("./utils/timer.js");
;
function isSerial(value) {
    return true;
}
class SerialPort {
    port;
    _dtr;
    _data;
    _dataLength;
    _dataStall;
    #isOpen;
    constructor(port) {
        this.port = port;
        this._dtr = false;
        this._data = [];
        this._dataLength = 0;
        this._dataStall = (0, timer_js_1.stall)(1);
    }
    get name() { return "serial-port"; }
    async connect() {
        if (this.#isOpen) {
            return await this.#isOpen;
        }
        this.#isOpen = this.port.open({ baudRate: 115200, bufferSize: 4096 * 4 });
        await this.#isOpen;
        await (0, timer_js_1.stall)(5);
        (async () => {
            while (this.port.readable) {
                const reader = this.port.readable.getReader();
                while (true) {
                    const { value, done } = await reader.read();
                    if (value && value.length) {
                        this._data.push(value);
                        this._dataLength += value.length;
                        //await stall(1);
                        //console.log("DATA", value, this._dataLength);
                    }
                    else {
                        this._dataStall = (0, timer_js_1.stall)(1);
                        await this._dataStall;
                    }
                    if (done) {
                        break;
                    }
                }
                console.log("CLOSED!");
                await reader.releaseLock();
            }
        })().then(console.log, console.log);
    }
    async reset(bootMode) {
        // For info on setting vs clearing download mode:
        // See: https://github.com/espressif/arduino-esp32/issues/6762
        await this.signal({ rts: false });
        await this.signal({ dtr: false });
        await (0, timer_js_1.stall)(100);
        if (bootMode) {
            await this.signal({ dtr: true });
            await this.signal({ rts: false });
            await (0, timer_js_1.stall)(100);
            await this.signal({ rts: true });
            await this.signal({ dtr: false });
            await this.signal({ rts: true });
            await (0, timer_js_1.stall)(100);
        }
        await this.signal({ rts: true });
        await this.signal({ dtr: false });
        await (0, timer_js_1.stall)(100);
    }
    async signal(signal) {
        if (signal.dtr != null) {
            this._dtr = signal.dtr;
            await this.port.setSignals({ dataTerminalReady: this._dtr });
        }
        else if (signal.rts != null) {
            await this.port.setSignals({ requestToSend: signal.rts });
            await this.signal({ dtr: this._dtr });
        }
        else {
            await this.signal({ dtr: false });
        }
    }
    async write(data) {
        const writer = this.port.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return true;
    }
    async read() {
        await (0, timer_js_1.stall)(100);
        const data = (0, data_js_1.concat)(this._data);
        this._data = [];
        this._dataLength = 0;
        return data;
    }
    async _read() {
        const result = [];
        const reader = this.port.readable.getReader();
        let timer = null;
        let cancelled = false;
        const reset = (duration) => {
            if (timer) {
                clearTimeout(timer);
            }
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
                await (0, timer_js_1.stall)(1);
            }
            else if (cancelled) {
                break;
            }
            else {
                await (0, timer_js_1.stall)(3);
            }
            if (read > 2048 || done) {
                break;
            }
        }
        if (timer) {
            clearTimeout(timer);
        }
        await reader.releaseLock();
        const data = (0, data_js_1.concat)(result);
        //console.log("READ", result.length, data.length, data.length ? data: 0);
        return data;
    }
    async forget() {
        await this.port.forget();
    }
    static async discover() {
        (0, errors_js_1.assert)(("serial" in navigator) && isSerial(navigator.serial), `no Serial API present`, {});
        let port;
        const oldPorts = await navigator.serial.getPorts();
        if (oldPorts.length) {
            port = oldPorts[0];
        }
        else {
            port = await navigator.serial.requestPort({
                filters: [
                    { usbProductId: 4097, usbVendorId: 12346 }
                ]
            });
        }
        if (port == null) {
            throw new Error("no port selected");
        }
        return new SerialPort(port);
    }
}
exports.SerialPort = SerialPort;
//# sourceMappingURL=serial-browser.js.map