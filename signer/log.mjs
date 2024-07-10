import { inspect } from "util";
import fs from "fs";
import { join } from "path";

import { hexlify, toBeArray, zeroPadValue } from "ethers";


const FOLDER = "/Volumes/FireflyProvision";

export function readFile(path) {
    return fs.readFileSync(join(FOLDER, path)).toString().trim();
}


export function pad(v, length) {
    while (v.length < length) { v = "0" + v; }
    return v;
}

export function toHex(v, length) {
    if (typeof(v) === "number") { v = hexlify(toBeArray(v)); }
    return zeroPadValue(v, length).substring(2);
}

function getDeviceInfo(model) {
}


export class Log {
    constructor(filename) {
        this._filename = filename;
        this._logs = [ ];
        this._values = { };
    }

    get filename() { return this._filename; }

    log(message) {
        console.log(message);
        inspect(message).split("\n").forEach((line) => {
            this._logs.push(line);
        });
    }

    set(key, value) { this._values[key] = value; }
    get(key) { return this._values[key]; }

    save() {
        const values = Object.assign({ }, this._values);
        values._logs = this._logs;

        fs.writeFileSync(this._filename, JSON.stringify(values));
    }

    static getFilename(model, serial) {
        return join(FOLDER, `devices/rev-${ toHex(model, 2) }-${ toHex(serial, 3) }.json`);
    }

    static getLog(model, serial) {
        const result = new Log(Log.getFilename(model, serial));
        result.set("model", model);
        result.set("serial", serial);

        try {
            const data = JSON.parse(fs.readFileSync(result.filename).toString().trim());
            result._logs = (data._logs || [ ]);
            for (const key in data) {
                if (key === "_logs") { continue; }
                result.set(key, data[key]);
            }
            return result;
        } catch (e) {
            if (e.code !== "ENOENT") { throw e; }
        }

        throw new Error(`no log found: ${ jsonPath}`);
    }

    static getNextLog(model) {
        let latest = 0;
        for (const filename of fs.readdirSync(join(FOLDER, "devices"))) {
            const match = filename.match(/^rev-([0-9A-F]+)-([0-9A-F]+).json$/i);
            if (match) {
                if (parseInt(match[1], 16) === model) {
                    const serial = parseInt(match[2], 16);
                    if (serial > latest) { latest = serial; }
                }
            }
        }

        const serial = latest + 1;

        const filename = Log.getFilename(model, serial);

        const result = new Log(filename);
        result.set("model", model);
        result.set("serial", serial);
        return result;
    }
}

/*
// Migrate legacy logs to JSON format
for (const filename of fs.readdirSync(join(FOLDER, "devices"))) {
    console.log(filename);

    const data = fs.readFileSync(join(FOLDER, "devices", filename)).toString();

    const serial = parseInt(data.match(/serial: ([0-9]*)/)[1]);
    const model = parseInt(filename.match(/rev-([0-9]*)-/)[1], 16);

    const log = new Log(Log.getFilename(model, serial));
    log.set("model", model);
    log.set("serial", serial);

    data.split("\n").forEach((l) => { log._logs.push(l); });


    try {
        const pubkeyN = data.match(/'pubkey.N': '([^' ]*)/)[1];
        const pubkeyE = data.match(/'pubkey.E': '([^' ]*)/)[1];
        const cipherData = data.match(/cipherData: '([^' ]*)/)[1];
        const attest = data.match(/attest: '([^' ]*)/)[1];
        console.log({ filename, pubkeyN, pubkeyE, cipherData, attest, serial, model });
        log.set("pubkeyN", pubkeyN);
        log.set("pubkeyE", pubkeyE);
        log.set("cipherData", cipherData);
        log.set("attest", attest);

    } catch (error) {
        console.log({ error });
    }

    log.save();
}
*/
