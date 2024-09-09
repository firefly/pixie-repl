// NVS - Non-volatile storage
//
// See: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/storage/nvs_flash.html

import { hexlify } from "ethers";

import { concat, toUtf8Bytes } from "./utils.js";


const PageSize = 4096;

export type PageState = "empty" | "active" | "full" | "erasing" | "corrupt";
function getPageState(state: PageState): number {
    switch (state) {
        case "empty": return 0xffffffff;
        case "active": return 0xfffffffe;
        case "full": return 0xfffffffc;
        case "erasing": return 0xfffffff8;
        case "corrupt": return 0;
    }
    throw new Error(`invalid PageState: ${ state }`);
}

export type EntryState = "empty" | "written" | "erased";
function getEntryState(state: EntryState): number {
    switch (state) {
        case "empty": return 0x03;
        case "written": return 0x02;
        case "erased": return 0x00;
    }
    throw new Error(`invalid EntryState: ${ state }`);
}

export type EntryType = "u8" | "i8" | "u16" | "i16" | "u32" | "i32" |
  "u64" | "i64" | "string" | "blob" | "blob_data" | "blob_index" | "any";
function getEntryType(type: EntryType): number {
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
    throw new Error(`invalid EntryType: ${ type }`);
}

export type Value = number | string | Uint8Array;

interface TypedValue {
    type: EntryType;
    value: Value
}

function writeLe4(value: number, data: Uint8Array, offset: number): void {
    data[offset + 3] = (value >> 24) & 0xff;
    data[offset + 2] = (value >> 16) & 0xff;
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}

function writeLe2(value: number, data: Uint8Array, offset: number): void {
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}

// See: https://stackoverflow.com/questions/18638900/javascript-crc32
const crc32Lookup = Uint32Array.from({length: 256}, (_, c) => {
    for (let _ = 0; _ < 8; _++)
        c = ((c & 1) * 0xEDB88320) ^ (c >>> 1);
    return c;
});

function computeCrc(data: Uint8Array, crc = 0): number {
    crc = ~crc;
    for (let i = 0; i < data.length; i++) {
        crc = (crc >>> 8) ^ crc32Lookup[(crc ^ data[i]) & 0xff];
    }
    return ~crc >>> 0;
}

export class Header {
    readonly #state: PageState;
    get state(): PageState { return this.#state; }

    readonly #seqNo: number;
    get seqNo(): number { return this.#seqNo; }

    readonly #version: number;
    get version(): number { return this.#version; }

    constructor(state: PageState, seqNo: number, version = 2) {
        this.#state = state;
        this.#seqNo = seqNo;
        this.#version = version;
    }

    get binary(): Uint8Array {
        const result = new Uint8Array(32);
        result.fill(0xff);
        writeLe4(getPageState(this.state), result, 0);
        writeLe4(this.seqNo, result, 4);
        result[8] = 256 - this.version;
        writeLe4(computeCrc(result.slice(4, 28), 0xffffffff), result, 28);

        return result;
    }
}

export abstract class Entry {

    #ns: number;
    get namespace(): number { return this.#ns; }

    #key: string;
    get key(): string { return this.#key; }

    #type: EntryType;
    get type(): EntryType { return this.#type; }

    #span: number;
    get span(): number { return this.#span; }

    #index: number;
    get index(): number { return this.#index; }

    readonly #data: Uint8Array;
    get data(): Uint8Array { return new Uint8Array(this.#data); }

    #state: EntryState;
    get state(): EntryState { return this.#state; }

    constructor(ns: number, key: string, type: EntryType, span: number, index: number, data: Uint8Array) {
        this.#ns = ns;
        this.#key = key;
        this.#type = type;
        this.#span = span;
        this.#index = index;
        this.#state = "written";
        this.#data = data;
    }

    get binary(): Uint8Array {
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

    get checksum(): number {
        return 0x42424242;
        //return computeCrc(this.#data.slice(xx));
    }

    erase(): void {
        this.#state = "erased";
    }

    static from(ns: number, key: string, value: Value, type: EntryType): Entry {
        switch (type) {
            case"u8": case "i8": case "u16": case "i16":
            case "u32": case "i32": case "u64": case "i64":
                return new ValueEntry(ns, key, <number>value, type);
            case "blob":
                return new BlobEntry(ns, key, <Uint8Array><unknown>value);
            //case "string":
        }

        throw new Error(`unknown ${ value } ${ type }`);
    }
}

export class ValueEntry extends Entry {
    constructor(ns: number, key: string, value: number, _type: EntryType) {
        if (typeof(value) !== "number") {
            throw new Error("");
        }

        const type = getEntryType(_type);

        const data = new Uint8Array(8);
        data.fill(0xff);

        for(let i = 0; i < (type & 0x0f); i++) {
            data[i] = value & 0xff;
            value >>= 8;
        }

        super(ns, key, _type, 1, 0xff, data);
    }
}

export class NamespaceEntry extends ValueEntry {
    readonly #name: string;
    get name(): string { return this.#name; }

    constructor(ns: number, name: string) {
        super(0, name, ns, "u8");
        this.#name = name;
    }
}

export class BlobIndexEntry extends Entry {
    constructor(blob: BlobEntry) {
        const data = new Uint8Array(8);
        data.fill(0xff);
        writeLe4(blob.blobData.length, data, 0);
        data[4] = 1; // Chunk count
        data[5] = 0; // Chunk start??
        super(blob.namespace, blob.key, "blob_index", 0x01, 0xff, data);
    }
}


export class BlobEntry extends Entry {
    readonly #blobData: Uint8Array;
    get blobData(): Uint8Array { return new Uint8Array(this.#blobData); }

    get chunks(): number {
        return Math.ceil(this.#blobData.length / 32);
    }

    get blobIndex(): BlobIndexEntry {
        return new BlobIndexEntry(this);
    }

    constructor(ns: number, key: string, data: Uint8Array) {
        const span = Math.ceil(data.length / 32);

        const meta = new Uint8Array(8);
        meta.fill(0xff);
        writeLe2(data.length, meta, 0);
        writeLe4(computeCrc(data, 0xffffffff), meta, 4);

        super(ns, key, "blob_data", span + 1, 0, meta);
        this.#blobData = data;
    }

    _blobs(): Array<Uint8Array> {
        const data = this.blobData;

        const blobs: Array<Uint8Array> = [ ];
        for (let i = 0; i < this.span - 1; i++) {
            const blob = new Uint8Array(32);
            blob.fill(0xff);
            blob.set(data.slice(i * 32, 32 + i * 32));
            blobs.push(blob);
        }
        return blobs;
    }

    get binary(): Uint8Array {
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

    readonly #seqNo: number;
    readonly #full: boolean;
    readonly #entries: Array<Entry>;

    get entries(): Array<Entry> { return this.#entries; }
    get header(): Header {
        let state: PageState = "empty";
        if (this.#entries.length) { state = "active"; }
        if (this.#full) { state = "full"; }
        return new Header(state, this.#seqNo);
    }

    constructor(seqNo: number, full = false) {
        this.#seqNo = seqNo;
        this.#full = full;
        this.#entries = [ ];
    }

    addEntry(entry: Entry): void {
        this.#entries.push(entry);
    }


    get binary(): Uint8Array {
        const entries = this.entries;

        const stateBitmap = new Uint8Array(32);

        let i = 0;
        for (const entry of entries) {
            const state = getEntryState(entry.state);

            let span = entry.span;
            if (entry instanceof BlobEntry) { span++; }

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
            const entry = entries[i].binary
            result.set(entry, offset);
            offset += entry.length;
        }

        return result;
    }
}

export class EmptyPage extends Page {
    constructor(seqNo: number) {
        super(seqNo, false);
    }

    get binary(): Uint8Array {
        const result = new Uint8Array(PageSize);
        result.fill(0xff);
        return result;
    }

}

export class NVSData {
    #data: Map<string, Map<string, TypedValue>>;

    readonly size: number;

    constructor(size: number) {
        this.size = size;
        this.#data = new Map();
    }

    get binary(): Uint8Array {
        const pages: Array<Page> = [
            new Page(0, true),
            new Page(1, true),
            new EmptyPage(2),
        ];

        // @TODO: this needs to be much more complex; currently
        //        we only support writing values to page 0

        const page = pages[0];

        let ns = 1;
        for (const [ namespace, kvs ] of this.#data) {
            page.addEntry(new NamespaceEntry(ns, namespace));

            for (const [ key, _value ] of kvs) {
                const { value, type } = _value;
                page.addEntry(Entry.from(ns, key, value, type));
            }

            ns++;
        }

        return concat(pages.map(p => p.binary));
    }

    #get(namespace: string, key: string): null | TypedValue {
        const ns = this.#data.get(namespace);
        if (ns == null) { return null; }
        if (ns.has(key)) { return ns.get(key) || null; }
        return null;
    }

    get(namespace: string, key: string): null | Value {
        const e = this.#get(namespace, key);
        if (e) { return e.value; }
        return null;
    }

    getType(namespace: string, key: string): null | EntryType {
        const e = this.#get(namespace, key);
        if (e) { return e.type; }
        return null;
    }


    set(namespace: string, key: string, value: any, type?: EntryType) {
        if (type == null) {
            if (typeof(value) === "number") {
                if (value > 0) {
                    if (value > 0xffffffff) {
                        throw new Error("out of range");
                    }
                    type = "u32";
                } else if (value < -0x80000000) {
                    type = "i32";
                }
            } else {
                throw new Error("oops?");
            }
        }
        if (type == null) { throw new Error("foo"); }

        if (!this.#data.has(namespace)) {
            this.#data.set(namespace, new Map());
        }
        this.#data.get(namespace)!.set(key, { type, value });
    }

    static fromValues(values: Record<string, Record<string, any>>): NVSData {
        throw new Error();
    }

    static fromBinary(data: Uint8Array): NVSData {
        throw new Error();
    }
}

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

import fs from "fs";

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
