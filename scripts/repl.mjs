import { inspect } from "util";

import { SerialPort } from "../../firefly-js/lib.esm/node-specific.js";
import { DeviceEsp32c3 } from "../../firefly-js/lib.esm/device-esp32c3.js";

import { stall } from "./utils.mjs";

const NumericCommands = [
    "SET-MODEL",
    "SET-SERIAL",
];

const DataCommands = [
    "SET-ATTEST",
    "SET-CIPHERDATA",
    "SET-PUBKEYN",
    "STIR-ENTROPY",
    "STIR-IV",
    "STIR-KEY"
];

export class FireflyRepl {
    constructor(log) {
        this._log = log || null;
        this._ready = false;
        this._device = null;
    }

    _writeLog(message) {
        if (this._log == null) {
            console.log(inspect(message));
            return;
        }
        this._log.log(message);
    }

    async connect() {
        const serialPort = SerialPort.discover(true);
        await serialPort.connect();
        this._device = new DeviceEsp32c3(serialPort);
    }

    async waitReady() {
        if (!this._device) { throw new Error("not connected; use `await .connect()`"); }

       // Wait until the device is ready; PING to reset READY if needed
        let count = 0;
        while (true) {
            const line = await this._device.readLine();
            if (line === "<READY") { break; }
            await stall(100);
            if (count++ > 10) {
                await this._sendCommand("PING");
                count = 0;
            }
        }

        await stall(500);

        await this._sendCommand(`NOP`);

        await stall(100);

        this._ready = true;
    }

    async sendCommand(command) {
        if (!this._ready) { throw new Error("not ready; use `await .waitReady()`"); }
        return this._sendCommand(command);
    }

    async _sendCommand(command) {
        {
            const comps = command.split("=");
            if (comps.length === 2) {
                let data = comps[1];
                if (NumericCommands.indexOf(comps[0]) >= 0) {
                    data = String(parseInt(data));
                } else if (DataCommands.indexOf(comps[0]) >= 0) {
                    if (data.startsWith("0x")) {
                        data = data.substring(2);
                    }
                }
                command = `${ comps[0] }=${ data }`
            }
        }

        const result = { };
        const errors = [ ];
        this._device.writeLine(command);

        while (true) {
            const line = await this._device.readLine();

            if (line === "<OK") { break; }
            if (line === "<ERROR") {
                if (errors.length) {
                    throw new Error(errors.join("; "));
                } else {
                    throw new Error("error encountered");
                }
            }

            const match = line.match(/^<([a-zA-Z0-9._-]*)=(.*)$/);
            if (match) {
                // REPL keyed output parameter
                let value = match[2];
                if (value.match(/^(([0-9a-f][0-9a-f])*) \([0-9]+ bytes\)$/i)) {
                    value = "0x" + value.split(" ")[0];
                } else if (value.match(/^[0-9]+$/)) {
                    value = parseInt(value);
                }
                result[match[1]] = value;
            } else if (line.startsWith("?")) {
                // REPL info
                this._writeLog(`[ INFO ] ${ line.substring(1).trim() }`);
            } else if (line.startsWith("!")) {
                // REPL error
                this._writeLog(`[ ERROR ] ${ line.substring(1).trim() }`);
                errors.push(line.substring(1).trim());
            } else if (line.match(/^ *I \([0-9+]\)/)) {
                // ESP info
                this._writeLog(`[ INFO ] ${ line.trim() }`);
            } else if (line) {
                // Something else
                this._writeLog(`[ WARNING ] Unknown: ${ line }`);
            }

            await stall(100);
        }
        if (errors.length) { result.errors = errors; }
        return result;
    }
}
