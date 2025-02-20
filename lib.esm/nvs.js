// NVS - Non-volatile storage
//
// See: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/storage/nvs_flash.html
import { assert } from "./utils/errors.js";
import { concat, fromLeBytes, hexlify } from "./utils/data.js";
import { extractString, toUtf8Bytes } from "./utils/strings.js";
const PageSize = 4096;
function getPageState(state) {
    switch (state) {
        case "empty": return 0xffffffff;
        case "active": return 0xfffffffe;
        case "full": return 0xfffffffc;
        case "erasing": return 0xfffffff8;
        case "corrupt": return 0;
    }
    throw new Error(`invalid PageState: ${state}`);
}
const PageStateMap = {
    0xffffffff: "empty", 0xfffffffe: "active", 0xfffffffc: "full",
    0xfffffff8: "erasing", 0: "corrupt"
};
function getEntryState(state) {
    switch (state) {
        case "empty": return 0x03;
        case "written": return 0x02;
        case "erased": return 0x00;
    }
    throw new Error(`invalid EntryState: ${state}`);
}
const EntryStateMap = {
    0x00: "erased", 0x02: "written", 0x03: "empty"
};
function getEntryType(type) {
    switch (type) {
        case "u8": return 0x01;
        case "i8": return 0x11;
        case "u16": return 0x02;
        case "i16": return 0x12;
        case "u32": return 0x04;
        case "i32": return 0x14;
        case "u64": return 0x08;
        case "i64": return 0x18;
        case "string": return 0x21;
        case "blob": return 0x41;
        case "blob_data": return 0x42;
        case "blob_index": return 0x48;
        case "any": return 0xff;
    }
    throw new Error(`invalid EntryType: ${type}`);
}
const EntryTypeMap = {
    0x01: "u8", 0x11: "i8", 0x02: "u16", 0x12: "i16",
    0x04: "u32", 0x14: "i32", 0x08: "u64", 0x18: "i64",
    0x21: "string", 0x41: "blob", 0x42: "blob_data",
    0x48: "blob_index", 0xff: "any"
};
function writeLe4(value, data, offset) {
    data[offset + 3] = (value >> 24) & 0xff;
    data[offset + 2] = (value >> 16) & 0xff;
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}
function writeLe2(value, data, offset) {
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}
// See: https://stackoverflow.com/questions/18638900/javascript-crc32
const crc32Lookup = Uint32Array.from({ length: 256 }, (_, c) => {
    for (let _ = 0; _ < 8; _++)
        c = ((c & 1) * 0xEDB88320) ^ (c >>> 1);
    return c;
});
function computeCrc(data, crc = 0) {
    crc = ~crc;
    for (let i = 0; i < data.length; i++) {
        crc = (crc >>> 8) ^ crc32Lookup[(crc ^ data[i]) & 0xff];
    }
    return ~crc >>> 0;
}
export class Header {
    #state;
    get state() { return this.#state; }
    #seqNo;
    get seqNo() { return this.#seqNo; }
    #version;
    get version() { return this.#version; }
    constructor(state, seqNo, version = 2) {
        this.#state = state;
        this.#seqNo = seqNo;
        this.#version = version;
    }
    get binary() {
        const result = new Uint8Array(32);
        result.fill(0xff);
        writeLe4(getPageState(this.state), result, 0);
        writeLe4(this.seqNo, result, 4);
        result[8] = 256 - this.version;
        if (this.state !== "empty") {
            writeLe4(computeCrc(result.slice(4, 28), 0xffffffff), result, 28);
        }
        return result;
    }
    static fromBinary(data) {
        const state = PageStateMap[fromLeBytes(data.slice(0, 4))] || "corrupt";
        const seqNo = fromLeBytes(data.slice(4, 8));
        const version = 256 - data[8];
        const checksum = data.slice(28);
        const header = new Header(state, seqNo, version);
        const computed = header.binary.slice(28);
        assert(fromLeBytes(computed) === fromLeBytes(checksum), `checksum failed`, {
            checksum, expected: computed
        });
        return header;
    }
}
export class Entry {
    #ns;
    get namespace() { return this.#ns; }
    #key;
    get key() { return this.#key; }
    #type;
    get type() { return this.#type; }
    #span;
    get span() { return this.#span; }
    #index;
    get index() { return this.#index; }
    #data;
    get data() { return new Uint8Array(this.#data); }
    #state;
    get state() { return this.#state; }
    constructor(ns, key, type, span, index, data) {
        this.#ns = ns;
        this.#key = key;
        this.#type = type;
        this.#span = span;
        this.#index = index;
        this.#state = "written";
        this.#data = data;
    }
    get binary() {
        const data = new Uint8Array(32);
        data.fill(0);
        data[0] = this.namespace;
        data[1] = getEntryType(this.type);
        data[2] = this.span;
        data[3] = this.index;
        // Add the key
        data.set(toUtf8Bytes(this.key), 8);
        // Add the data
        data.set(this.data, 24);
        // Add the checksum
        const crcData = new Uint8Array(28);
        crcData.set(data.slice(0, 4), 0);
        crcData.set(data.slice(8, 32), 4);
        writeLe4(computeCrc(crcData, 0xffffffff), data, 4);
        return data;
    }
    get checksum() {
        return 0x42424242;
        //return computeCrc(this.#data.slice(xx));
    }
    erase() {
        this.#state = "erased";
    }
    static from(ns, key, value, type) {
        switch (type) {
            case "u8":
            case "i8":
            case "u16":
            case "i16":
            case "u32":
            case "i32":
            case "u64":
            case "i64":
                return new ValueEntry(ns, key, value, type);
            case "blob":
                return new BlobEntry(ns, key, value);
            //case "string":
        }
        throw new Error(`unknown ${value} ${type}`);
    }
}
export class ValueEntry extends Entry {
    constructor(ns, key, value, _type) {
        if (typeof (value) !== "number") {
            throw new Error("");
        }
        const type = getEntryType(_type);
        const data = new Uint8Array(8);
        data.fill(0xff);
        for (let i = 0; i < (type & 0x0f); i++) {
            data[i] = value & 0xff;
            value >>= 8;
        }
        super(ns, key, _type, 1, 0xff, data);
    }
    get value() { return fromLeBytes(this.data); }
}
export class NamespaceEntry extends ValueEntry {
    #name;
    get name() { return this.#name; }
    constructor(ns, name) {
        super(0, name, ns, "u8");
        this.#name = name;
    }
}
export class BlobIndexEntry extends Entry {
    constructor(blob) {
        const data = new Uint8Array(8);
        data.fill(0xff);
        writeLe4(blob.blobData.length, data, 0);
        data[4] = 1; // Chunk count
        data[5] = 0; // Chunk start??
        super(blob.namespace, blob.key, "blob_index", 0x01, 0xff, data);
    }
}
export class BlobEntry extends Entry {
    #blobData;
    get blobData() { return new Uint8Array(this.#blobData); }
    get chunks() {
        return Math.ceil(this.#blobData.length / 32);
    }
    get blobIndex() {
        return new BlobIndexEntry(this);
    }
    constructor(ns, key, data) {
        const span = Math.ceil(data.length / 32);
        const meta = new Uint8Array(8);
        meta.fill(0xff);
        writeLe2(data.length, meta, 0);
        writeLe4(computeCrc(data, 0xffffffff), meta, 4);
        super(ns, key, "blob_data", span + 1, 0, meta);
        this.#blobData = data;
    }
    _blobs() {
        const data = this.blobData;
        const blobs = [];
        for (let i = 0; i < this.span - 1; i++) {
            const blob = new Uint8Array(32);
            blob.fill(0xff);
            blob.set(data.slice(i * 32, 32 + i * 32));
            blobs.push(blob);
        }
        return blobs;
    }
    get binary() {
        const result = this._blobs();
        result.unshift(super.binary);
        result.push(this.blobIndex.binary);
        return concat(result);
    }
}
/*
export class StringEntry extends BlobEntry {
    constructor(ns: number, key: string, data: string) {
        super(ns, key, _TextEncoder.encode(data));
    }
}
*/
export class Page {
    #seqNo;
    #state;
    #entries;
    get seqNo() { return this.#seqNo; }
    get state() { return this.#state; }
    get entries() { return this.#entries; }
    get header() {
        return new Header(this.state, this.#seqNo);
    }
    constructor(seqNo, state) {
        this.#seqNo = seqNo;
        this.#state = state;
        this.#entries = [];
    }
    addEntry(entry) {
        this.#state = "active";
        this.#entries.push(entry);
    }
    get binary() {
        const entries = this.entries;
        const stateBitmap = new Uint8Array(32);
        let i = 0;
        for (const entry of entries) {
            const state = getEntryState(entry.state);
            let span = entry.span;
            if (entry instanceof BlobEntry) {
                span++;
            }
            for (let j = 0; j < span; j++) {
                const slot = Math.trunc((i + j) / 4);
                const offset = ((i + j) % 4) * 2;
                stateBitmap[slot] |= state << offset;
            }
            i += span;
        }
        // Fill with empty entries (including the reserved final 4 bits)
        while (i < 128) {
            const slot = Math.trunc(i / 4);
            const offset = (i % 4) * 2;
            stateBitmap[slot] |= 0x03 << offset;
            i++;
        }
        const result = new Uint8Array(PageSize);
        result.fill(0xff);
        result.set(this.header.binary, 0);
        result.set(stateBitmap, 32);
        let offset = 64;
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i].binary;
            result.set(entry, offset);
            offset += entry.length;
        }
        return result;
    }
    static fromBinary(data) {
        const header = Header.fromBinary(data.slice(0, 32));
        if (header.state === "empty") {
            return new EmptyPage(header.seqNo);
        }
        const page = new Page(header.seqNo, header.state);
        const getEntry = (i) => {
            return data.slice((i + 2) * 32, (i + 3) * 32);
        };
        let nextNs = 1;
        const stateBitmap = data.slice(32, 64);
        for (let i = 0; i < 126; i++) {
            const slot = Math.trunc(i / 4);
            const offset = (i % 4) * 2;
            const s = EntryStateMap[(stateBitmap[slot] >> offset) & 0x03];
            const d = getEntry(i);
            if (s === "empty") {
                continue;
            }
            const ns = d[0];
            const type = EntryTypeMap[d[1]];
            const span = d[2];
            //const cunkIndex = d[3];
            //const crc = d.slice(4, 8);
            const key = extractString(d.slice(8, 24));
            const value = d.slice(24);
            let entry;
            if (ns === 0) {
                entry = new NamespaceEntry(nextNs++, key);
            }
            else if (type.match(/^[iu](8|16|32|64)$/)) {
                entry = new ValueEntry(ns, key, fromLeBytes(value), type);
            }
            else if (type === "blob_data") {
                const length = fromLeBytes(value.slice(0, 2));
                const blob = [];
                for (let j = 1; j < span; j++) {
                    blob.push(getEntry(++i));
                }
                entry = new BlobEntry(ns, key, concat(blob).slice(0, length));
                // @TODO: get this entry and make sure it matches the
                //        expected blob index
                i++;
            }
            else {
                throw new Error("unsupporte");
            }
            page.addEntry(entry);
        }
        return page;
    }
}
export class EmptyPage extends Page {
    constructor(seqNo) {
        super(seqNo, "empty");
    }
    get binary() {
        const result = new Uint8Array(PageSize);
        result.fill(0xff);
        return result;
    }
}
export class NVSData {
    #data;
    size;
    constructor(size) {
        this.size = size;
        this.#data = new Map();
    }
    get binary() {
        const pages = [
            new Page(0, "full"),
            new Page(1, "full"),
            new EmptyPage(2),
        ];
        // @TODO: this needs to be much more complex; currently
        //        we only support writing values to page 0
        const page = pages[0];
        let ns = 1;
        for (const [namespace, kvs] of this.#data) {
            page.addEntry(new NamespaceEntry(ns, namespace));
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                page.addEntry(Entry.from(ns, key, value, type));
            }
            ns++;
        }
        return concat(pages.map(p => p.binary));
    }
    get csv() {
        const result = ["key, type, encoding, value"];
        for (const [namespace, kvs] of this.#data) {
            result.push(`${namespace}, namespace, ,`);
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                if (value instanceof Uint8Array) {
                    result.push(`${key}, data, hex, ${hexlify(value)}`);
                }
                else {
                    result.push(`${key}, data, ${type}, ${value}`);
                }
            }
        }
        return result.join("\n");
    }
    get json() {
        const result = {};
        for (const [namespace, kvs] of this.#data) {
            const values = {};
            result[namespace] = values;
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                if (value instanceof Uint8Array) {
                    values[key] = { "type": "blob", value: hexlify(value) };
                }
                else {
                    values[key] = {
                        type: type,
                        value: value
                    };
                }
            }
        }
        return { namespaces: result };
    }
    #get(namespace, key) {
        const ns = this.#data.get(namespace);
        if (ns == null) {
            return null;
        }
        if (ns.has(key)) {
            return ns.get(key) || null;
        }
        return null;
    }
    get(namespace, key) {
        const e = this.#get(namespace, key);
        if (e) {
            return e.value;
        }
        return null;
    }
    getType(namespace, key) {
        const e = this.#get(namespace, key);
        if (e) {
            return e.type;
        }
        return null;
    }
    set(namespace, key, value, type) {
        if (type == null) {
            if (typeof (value) === "number") {
                if (value > 0) {
                    if (value > 0xffffffff) {
                        throw new Error("out of range");
                    }
                    type = "u32";
                }
                else if (value < -0x80000000) {
                    type = "i32";
                }
            }
            else if (value instanceof Uint8Array) {
                type = "blob";
            }
            else {
                throw new Error(`cannot guess: ${value}`);
            }
        }
        if (type == null) {
            throw new Error("foo");
        }
        if (!this.#data.has(namespace)) {
            this.#data.set(namespace, new Map());
        }
        this.#data.get(namespace).set(key, { type, value });
    }
    static fromValues(values) {
        throw new Error();
    }
    static fromBinary(data) {
        const nvs = new NVSData(data.length);
        let namespace = "_";
        for (let i = 0; i < data.length; i += 4096) {
            const page = Page.fromBinary(data.slice(i, i + 4096));
            for (const entry of page.entries) {
                if (entry instanceof NamespaceEntry) {
                    namespace = entry.key;
                }
                else if (entry instanceof ValueEntry) {
                    nvs.set(namespace, entry.key, entry.value, entry.type);
                }
                else if (entry instanceof BlobEntry) {
                    nvs.set(namespace, entry.key, entry.blobData, "blob");
                }
            }
        }
        return nvs;
    }
}
/*
function decode(chunk: Uint8Array): string {
    let result = "";
    for (let i = 0; i < chunk.length; i++) {
        const c = chunk[i];
        if (c >= 32 && c <= 127) {
            result += String.fromCharCode(c);
        } else {
            result += ".";
        }
    }
    return result;
}

const nvs = new NVSData(0x3000);
nvs.set("namespace", "testU8", 1, "u8");
nvs.set("namespace", "testI32", -1, "i32");
nvs.set("namespace", "testBlob", Buffer.from("00ff30313233416100ff", "hex"), "blob");
nvs.set("namespace", "testBlob2", Buffer.from("8888424242424242424242424242424242424242424242424242424242424242424242424242424288", "hex"), "blob");

function pad(v: string): string {
    while (v.length < 8) { v = "0" + v; }
    return v;
}

const expected = fs.readFileSync("obsolete/test-nvs/test0.bin");
const actual = nvs.binary;

function line(index: number, data: Uint8Array): string {
    const hex = hexlify(data).substring(2);
    const nibbles: Array<string> = [ ];
    for (let i = 0; i < 32; i += 4) {
        nibbles.push(hex.substring(i, i + 4));
    }
    return `${ pad(index.toString(16)) }: ${ nibbles.join(" ") }   ${ decode(data) }`;
}
function diff(a: string, b: string): string {
    let result = "";
    const length = Math.max(a.length, b.length);
    for (let i = 0; i < length; i++) {
        result += (a[i] === b[i]) ? " ": "^";
    }
    if (result.trim() === "") { return ""; }
    return result;
}

function dump(from: number, to: number, onlyDiff: boolean) {
    let countDiff = 0;
    for (let i = from; i < to; i += 16) {
        const a = actual.slice(i, i + 16), e = expected.slice(i, i + 16);
        const la = line(i, a), le = line(i, e);
        const ld = diff(la, le);

        if (!ld && onlyDiff) { continue; }

        if (ld && countDiff++ > 10) {
            console.log("Too many diffs; stopping");
            break;
        }

        console.log("ACTUAL:", la);
        console.log("EXPECT:", le);
        console.log("       ", diff(la, le));

    }
}

//dump(0x1000 - 32, 0x1000 + 64, false);
dump(0, actual.length, true);
*/
/*
import fs from "fs";

const nvs = NVSData.fromBinary(fs.readFileSync("./test-attest.bin"));
//console.log(nvs);
console.log(JSON.stringify(nvs.json));
*/
//# sourceMappingURL=nvs.js.map