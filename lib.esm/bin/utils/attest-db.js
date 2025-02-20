import { readdirSync, readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { assert } from "../../utils/errors.js";
function getTime() {
    return Math.floor((new Date()).getTime() / 1000);
}
function hexpad(value, length) {
    let v = value.toString(16);
    assert(v.length <= length, `internal: value exceeds format size`, {
        value, length
    });
    while (v.length < length) {
        v = "0" + v;
    }
    return v;
}
function assertBytes(data, length) {
    assert(typeof (data) === "string" && data.match(/^(0x)?([0-9a-f][0-9a-f])*$/i), "invalid bytes value", { value: data });
    if (!data.startsWith("0x")) {
        data = "0x" + data;
    }
    assert(length == null || data.length === (2 + 2 * length), "invalid bytes length", { value: data, length });
    return data.toLowerCase();
}
export class AttestDatabaseFolder {
    path;
    constructor(path) {
        this.path = path;
    }
    read(model, serial) {
        const path = resolve(this.path, this._getFilename(model, serial));
        const info = JSON.parse(readFileSync(path).toString());
        const attest = assertBytes(info.attest, 64);
        const cipherdata = assertBytes(info.cipherdata, 1220);
        const pubkey = assertBytes(info.pubkey, 384);
        const marker = assertBytes(info.marker, 4);
        return { attest, cipherdata, marker, pubkey };
    }
    write(model, serial, entry) {
        const path = resolve(this.path, this._getFilename(model, serial));
        console.log({ path, model, serial, entry });
        writeFileSync(path, JSON.stringify(Object.assign({}, entry, {
            model, serial, timestamp: getTime()
        })));
    }
    getNextSerial(model) {
        let highest = 0;
        readdirSync(this.path).forEach((f) => {
            const match = f.match(/^rev-([0-9a-f]+)-([0-9a-f]+).json$/i);
            if (!match || parseInt(match[1], 16) !== model) {
                return;
            }
            const v = parseInt(match[2], 16);
            if (v >= highest) {
                highest = v;
            }
        });
        return highest + 1;
    }
    _getFilename(model, serial) {
        return `rev-${hexpad(model, 4)}-${hexpad(serial, 6)}.json`;
    }
}
//# sourceMappingURL=attest-db.js.map