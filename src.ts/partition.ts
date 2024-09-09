import { createHash } from "crypto";

import { assert, toLeBytes, toUtf8Bytes } from "./utils.js";


// # 3K for partition data (96 entries) leaves 1K in a 4K sector for signature
const PartitionTableSize = 0xC00

// Magic header for each partition
const Magic = new Uint8Array([ 0xaa, 0x50 ]);

// End marker of partitions within the partition table
const EndMarker = new Uint8Array(16);
EndMarker.fill(0xff);
EndMarker[0] = 0xeb;
EndMarker[1] = 0xeb;

const FlagReadOnly = 0x02;


export type Type = "app" | "data";
function getType(type: Type): number {
    switch (type) {
        case "app": return 0x00;
        case "data": return 0x01;
    }
    throw new Error(`unknown Type: ${ type }`);
}

export type AppType = "factory" | "test" | "ota_0" | "ota_1";
function getAppType(type: AppType): number {
    switch (type) {
        case "factory": return 0x00;
        case "ota_0": return 0x10;
        case "ota_1": return 0x11;
        case "test": return 0x20;
    }
    throw new Error(`unknown AppType: ${ type }`);
}

export type DataType = "ota" | "phy" | "nvs" | "coredump" |
  "nvs_keys" | "efuse" | "undefined" | "esphttpd" | "fat" |
  "spiffs" | "littlefs";
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

export type SubTypes<T extends Type> =
    T extends "app" ? AppType:
    T extends "data" ? DataType:
    never;
function getSubtype<T extends Type>(type: T, subtype: SubTypes<T>): number {
    switch (type) {
        case "app": return getAppType(<AppType>subtype);
        case "data": return getDataType(<DataType>subtype);
    }
    throw new Error(`invalid Subtype: ${ type }`);
}


export class Partition<T extends Type> {

    readonly name: string;
    readonly type: T;
    readonly subtype: SubTypes<T>

    readonly offset: number;
    readonly size: number;

    readonly isReadonly: boolean;

    constructor(name: string, type: T, subtype: SubTypes<T>, offset: number, size: number, isReadonly: boolean) {
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

        // - Magic (2 bytes)
        // - type (1 byte)
        // - subtype (1 byte)
        // - offset (4 bytes; little-endian)
        // - size (4 bytes; little-endian)
        // - name (16 bytes)
        // - flags (4 bytes; read-only = 1)
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

export class PartitionTable {
    #records: Array<Partition<Type>>;

    #flashSize: number;
    get flashSize(): number { return this.#flashSize; }

    constructor(flashSize = 0) {
        this.#records = [ ];
        this.#flashSize = flashSize;
    }

    get partitions(): Array<Partition<Type>> {
        const records = this.#records.slice();
        records.sort((a, b) => (a.offset - b.offset));
        return records;
    }

    addPartition<T extends Type>(name: string, type: T, subtype: SubTypes<T>, offset: number, size: number, isReadonly: boolean): void {
        // Check the flash is large enough
        assert(this.#flashSize === 0 || offset + size <= this.#flashSize, `partition outside flash range`, {
            name, offset, size, flashSize: this.#flashSize
        });

        if (type === "data") {
            // Check ota data is exactly 0x2000 bytes
            assert(subtype != "ota" || size === 0x2000, `ota_data must be 0x2000 bytes`, {
                name, size
            });

            // Check the data partition is 4k bounrary aligned
            assert((offset & 0xfff) === 0, `data partition must be aligned on 0x10000 boundary`, {
                name, offset
            });
        }

        if (type === "app") {
            // Check the app partition is 64k boundary aligned
            assert((offset & 0xffff) === 0, `app partition must be aligned on 0x10000 boundary`, {
                name, offset
            });

            // Check the size is 4k boundary aligned
            assert((size & 0xfff) === 0, `app partition size must be aligned on 0x1000 boundary`, {
                name, size
            });
        }

        // Check the name is unique
        const partition = this.getPartition(name);
        assert(!partition, `duplicate partition name: ${ name }`, {
            name, partition
        });

        // Check the partition doesn't overlap any other partition
        const partitions = this.partitions;
        for (const partition of partitions) {
            assert(offset >= partition.offset + partition.size || offset + size < partition.offset,
                `overlapping partition: ${ name } overlaps ${ partition.name}`, {
                name, partition
            });
        }

        this.#records.push(new Partition(name, type, subtype, offset, size, isReadonly));
    }

    getPartitionAt(offset: number): null | Partition<Type> {
        for (const partition of this.partitions) {
            const o = partition.offset;
            if (offset >= o && offset < o + partition.size) {
                return partition;
            }
        }
        return null;
    }

    getPartition(name: string): null | Partition<Type> {
        for (const record of this.#records) {
            if (record.name === name) { return record; }
        }
        return null;
    }

    summary(): string {
        function toAddr(_v: number): string {
            let v = String(_v.toString(16));
            while (v.length < 7) { v = "0" + v; }
            return v;
        }

        function size(v: number): string {
            if (v < 1024) { return `${ v }b`; }
            if (v < 1024 * 1024) { return `${ (v / 1024).toFixed(1) }kb`;}
            return `${ (v / 1024 / 1024).toFixed(1) }Mb`;
        }

        function padl(text: string, width: number): string {
            while (text.length < width) { text = " " + text; }
            return text;
        }

        function padr(text: string, width: number): string {
            while (text.length < width) { text = text + " "; }
            return text;
        }

        const lines: Array<string> = [ ];

        let offset = 0;
        for (const p of this.partitions) {
            if (p.offset > offset) {
                lines.push(`  ${ toAddr(offset) }:${ toAddr(p.offset) } ${ padl(size(p.offset - offset), 10) }  [ UNUSED ]`);
            }
            lines.push(`  ${ toAddr(p.offset) }:${ toAddr(p.size) } ${ padl(size(p.size), 10) }  ${ padr(p.name, 16) }  ${ p.type }/${ p.subtype } ${ p.isReadonly ? "RO": "" }`);
            offset = p.offset + p.size;
        }

        if (this.#flashSize && offset < this.#flashSize) {
            lines.push(`  ${ toAddr(offset) }:${ toAddr(this.#flashSize) } ${ padl(size(this.#flashSize - offset), 10) }  [ UNUSED ]`);
        }

        return lines.join("\n");
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


function md5(data: Uint8Array): Uint8Array {
    const hasher = createHash("md5");
    hasher.update(data);
    return hasher.digest();
}




import { BinDiff } from "./debug.js";

import fs from "fs";

const expected = fs.readFileSync("obsolete/test-part/partition.bin");

const table = new PartitionTable(16 * 1024 * 1024);
//table.addPartition("attest", "data", "nvs", 0x009000, 0x007000, false);
//table.addPartition("factory", "app", "factory", 0x010000, 0x700000, false);
//table.addPartition("nvs", "data", "nvs", 0xf00000, 0x100000, false);
table.addPartition("attest", "data", "nvs", 0x009000, 0x005000, true);
//table.addPartition("futurekeys", "data", "nvs", 0x00c000, 0x001000, false);
table.addPartition("otadata", "data", "ota", 0x00e000, 0x002000, false);
//table.addPartition("theme", "data", "nvs", 0x00D000, 0x003000, false);
table.addPartition("factory", "app", "factory", 0x010000, 0x0e0000, false);
table.addPartition("nvs", "data", "nvs", 0x100000, 0x100000, false);
table.addPartition("ota_0", "app", "ota_0", 0x200000, 0x700000, false);
table.addPartition("ota_1", "app", "ota_1", 0x900000, 0x700000, false);

const diff = new BinDiff(table.binary, expected);
diff.dump(0, undefined, true);

console.log(table.summary());
