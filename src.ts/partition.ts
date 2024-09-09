import { createHash } from "crypto";

import { toLeBytes, toUtf8Bytes } from "./utils.js";



// # 3K for partition data (96 entries) leaves 1K in a 4K sector for signature
const PartitionTableSize = 0xC00

const EndMarker = new Uint8Array(16);
EndMarker.fill(0xff);
EndMarker[0] = 0xeb;
EndMarker[1] = 0xeb;
//MD5_PARTITION_BEGIN = b'\xEB\xEB' + b'\xFF' * 14

export type Type = "app" | "data";
function getType(type: Type): number {
    switch (type) {
        case "app": return 0x00;
        case "data": return 0x01;
    }
    throw new Error(`unknown Type: ${ type }`);
}

export type AppType = "factory" | "test";
function getAppType(type: AppType): number {
    switch (type) {
        case "factory": return 0x00;
        case "test": return 0x20;
    }
    throw new Error(`unknown AppType: ${ type }`);
}

export type DataType = "ota" | "phy" | "nvs" | "coredump" |
  "nvs_keys" | "efuse" | "undefined" | "esphttpd" |
  "fat" | "spiffs" | "littlefs";
function getDataType(type: DataType): number {
    switch (type) {
        case "ota": return 0x00;
        case "phy": return 0x01;
        case "nvs": return 0x02;
        case "coredump": return 0x03;
        case "nvs_keys": return 0x04;
        case "efuse": return 0x05;
        case "undefined": return 0x06;
        case "esphttpd": return 0x80;
        case "fat": return 0x81;
        case "spiffs": return 0x82;
        case "littlefs": return 0x83;
    }
    throw new Error(`invalid DataType: ${ type }`);
}

export type SubType<T extends Type> =
    T extends "app" ? AppType:
    T extends "data" ? DataType:
    never;
function getSubtype<T extends Type>(type: T, subtype: SubType<T>): number {
    switch (type) {
        case "app": return getAppType(<AppType>subtype);
        case "data": return getDataType(<DataType>subtype);
    }
    throw new Error(`invalid Subtype: ${ type }`);
}

const FlagReadOnly = 0x01;

function md5(data: Uint8Array): Uint8Array {
    const hasher = createHash("md5");
    hasher.update(data);
    return hasher.digest();
}



export class Partition<T extends Type> {

    readonly name: string;
    readonly type: T;
    readonly subtype: SubType<T>

    readonly offset: number;
    readonly size: number;

    readonly isReadonly: boolean;

    constructor(name: string, type: T, subtype: SubType<T>, offset: number, size: number, isReadonly: boolean) {
        if (toUtf8Bytes(name).length > 16) {
            throw new Error(`bad name: ${ name}`);
        }

        this.name = name;

        this.type = type;
        this.subtype = subtype;

        this.offset = offset;
        this.size = size;

        this.isReadonly = isReadonly;
    }

    get binary(): Uint8Array {
        let flags = 0;
        if (this.isReadonly) { flags |= FlagReadOnly; }

        //STRUCT_FORMAT = b'<2sBB LL 16sL'
        const result = new Uint8Array(32);
        result.set(Magic, 0);
        result[2] = getType(this.type);
        result[3] = getSubtype(this.type, this.subtype);
        result.set(toLeBytes(this.offset, 4), 4);
        result.set(toLeBytes(this.size, 4), 8);
        result.set(toUtf8Bytes(this.name), 12);
        result.set(toLeBytes(flags, 4), 28);

        return result;
    }
}

/*
00000000: aa50 0102 0090 0000 0070 0000 6174 7465  .P.......p..atte
00000010: 7374 0000 0000 0000 0000 0000 0000 0000  st..............
00000020: aa50 0000 0000 0100 0000 7000 6661 6374  .P........p.fact
00000030: 6f72 7900 0000 0000 0000 0000 0000 0000  ory.............
00000040: aa50 0102 0000 f000 0000 1000 6e76 7300  .P..........nvs.
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: ebeb ffff ffff ffff ffff ffff ffff ffff  ................
00000070: 5a00 b544 b462 80aa 58da a770 eb62 07a2  Z..D.b..X..p.b..
00000080: ffff ffff ffff ffff ffff ffff ffff ffff  ................
00000090: ffff ffff ffff ffff ffff ffff ffff ffff  ................
*/

const Magic = new Uint8Array([ 0xaa, 0x50 ]);

export class PartitionTable {
    #records: Array<Partition<Type>>;

    constructor() {
        this.#records = [ ];
    }

    addPartition<T extends Type>(name: string, type: T, subtype: SubType<T>, offset: number, size: number, isReadonly: boolean): void {
        this.#records.push(new Partition(name, type, subtype, offset, size, isReadonly));
    }

    get binary(): Uint8Array {
        const result = new Uint8Array(PartitionTableSize);
        result.fill(0xff);

        let offset = 0;
        for (const record of this.#records) {
            const bin = record.binary;
            result.set(bin, offset);
            offset += bin.length
        }

        const checksum = md5(result.slice(0, offset));

        result.set(EndMarker, offset);
        offset += EndMarker.length;

        result.set(checksum, offset);
        offset += checksum.length;

        return result;
    }
}


import { BinDiff } from "./debug.js";

import fs from "fs";

const expected = fs.readFileSync("obsolete/test-part/partition.bin");

const table = new PartitionTable();
table.addPartition("attest", "data", "nvs", 0x009000, 0x007000, false);
table.addPartition("factory", "app", "factory", 0x010000, 0x700000, false);
table.addPartition("nvs", "data", "nvs", 0xf00000, 0x100000, false);

const diff = new BinDiff(table.binary, expected);
diff.dump();//undefined, undefined, true);
