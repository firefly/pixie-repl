
import { readdirSync, readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

import { assert } from "../utils/errors.js";

function getTime(): number {
    return Math.floor((new Date()).getTime() / 1000);
}

function hexpad(value: number, length: number): string {
    let v = value.toString(16);
    assert(v.length <= length, `internal: value exceeds format size`, {
        value, length
    });
    while (v.length < length) { v = "0" + v; }
    return v;
}

function assertBytes(data: string, length?: number): string {
    assert(typeof(data) === "string" && data.match(/^(0x)?([0-9a-f][0-9a-f])*$/i),
      "invalid bytes value", { value: data });
    if (!data.startsWith("0x")) { data = "0x" + data; }
    assert(length == null || data.length === (2 + 2 * length),
      "invalid bytes length", { value: data, length });
    return data.toLowerCase();
}


export interface AttestEntry {
    attest: string;
    cipherdata: string;
    marker: string;
    pubkey: string;
}

export interface AttestDatabase {
    read(model: number, serial: number): null | AttestEntry;
    write(model: number, serial: number, entry: AttestEntry): void;
    getNextSerial(model: number): number;
}

export class AttestDatabaseFolder implements AttestDatabase {
    readonly path: string;

    constructor(path: string) {
        this.path = path;
    }

    read(model: number, serial: number): null | AttestEntry {
        const path = resolve(this.path, this._getFilename(model, serial));
        const info = JSON.parse(readFileSync(path).toString());

        const attest = assertBytes(info.attest, 64);
        const cipherdata = assertBytes(info.cipherdata, 1220);
        const pubkey = assertBytes(info.pubkey, 384);
        const marker = assertBytes(info.marker, 4);

        return { attest, cipherdata, marker, pubkey };
    }

    write(model: number, serial: number, entry: AttestEntry): void {
        const path = resolve(this.path, this._getFilename(model, serial));
        console.log({ path, model, serial, entry});
        writeFileSync(path, JSON.stringify(Object.assign({ }, entry, {
            model, serial, timestamp: getTime()
        })));
    }

    getNextSerial(model: number): number {
        let highest = 0;
        readdirSync(this.path).forEach((f) => {
            const match = f.match(/^rev-([0-9a-f]+)-([0-9a-f]+).json$/i);
            if (!match || parseInt(match[1], 16) !== model) { return; }
            const v = parseInt(match[2], 16);
            if (v >= highest) { highest = v; }
        });

        return highest + 1;
    }

    _getFilename(model: number, serial: number): string {
        return `rev-${ hexpad(model, 4) }-${ hexpad(serial, 6) }.json`;
    }
}

/*
(function() {
    const path = "/Volumes/FireflyProvision/devices";
    const db = new AttestDatabaseFolder(path);
    console.log(db.read(0x106, 177));

})();
*/
