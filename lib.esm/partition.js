import { assert } from "./utils/errors.js";
import { fromLeBytes, toLeBytes } from "./utils/data.js";
import { toUtf8Bytes, toUtf8String } from "./utils/strings.js";
import { Md5 } from "./utils/md5.js";
// # 3K for partition data (96 entries) leaves 1K in a 4K sector for signature
const PartitionTableSize = 0xC00;
// Magic header for each partition
const Magic = new Uint8Array([0xaa, 0x50]);
// End marker of partitions within the partition table
const EndMarker = new Uint8Array(16);
EndMarker.fill(0xff);
EndMarker[0] = 0xeb;
EndMarker[1] = 0xeb;
const FlagReadOnly = 0x02;
function getType(type) {
    switch (type) {
        case "app": return 0x00;
        case "data": return 0x01;
    }
    throw new Error(`unknown Type: ${type}`);
}
const TypeMap = { 0: "app", 1: "data" };
function getAppType(type) {
    switch (type) {
        case "factory": return 0x00;
        case "ota_0": return 0x10;
        case "ota_1": return 0x11;
        case "test": return 0x20;
    }
    throw new Error(`unknown AppType: ${type}`);
}
const AppTypeMap = {
    0x00: "factory", 0x10: "ota_0", 0x11: "ota_1", 0x20: "test"
};
function getDataType(type) {
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
    throw new Error(`invalid DataType: ${type}`);
}
const DataTypeMap = {
    0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump",
    0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined",
    0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"
};
function getSubtype(type, subtype) {
    switch (type) {
        case "app": return getAppType(subtype);
        case "data": return getDataType(subtype);
    }
    throw new Error(`invalid Subtype: ${type}`);
}
;
export class Partition {
    name;
    type;
    subtype;
    offset;
    size;
    isReadonly;
    constructor(name, type, subtype, offset, size, isReadonly) {
        if (toUtf8Bytes(name).length > 16) {
            throw new Error(`bad name: ${name}`);
        }
        this.name = name;
        this.type = type;
        this.subtype = subtype;
        this.offset = offset;
        this.size = size;
        this.isReadonly = isReadonly;
    }
    get binary() {
        let flags = 0;
        if (this.isReadonly) {
            flags |= FlagReadOnly;
        }
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
    #records;
    #flashSize;
    get flashSize() { return this.#flashSize; }
    constructor(flashSize = 0) {
        this.#records = [];
        this.#flashSize = flashSize;
    }
    get partitions() {
        const records = this.#records.slice();
        records.sort((a, b) => (a.offset - b.offset));
        return records;
    }
    addPartition(name, type, subtype, offset, size, isReadonly) {
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
        assert(!partition, `duplicate partition name: ${name}`, {
            name, partition
        });
        // Check the partition doesn't overlap any other partition
        const partitions = this.partitions;
        for (const partition of partitions) {
            assert(offset >= partition.offset + partition.size || offset + size < partition.offset, `overlapping partition: ${name} overlaps ${partition.name}`, {
                name, partition
            });
        }
        this.#records.push(new Partition(name, type, subtype, offset, size, isReadonly));
    }
    getPartitionAt(offset) {
        for (const partition of this.partitions) {
            const o = partition.offset;
            if (offset >= o && offset < o + partition.size) {
                return partition;
            }
        }
        return null;
    }
    getPartition(name) {
        for (const record of this.#records) {
            if (record.name === name) {
                return record;
            }
        }
        return null;
    }
    summary() {
        function toAddr(_v) {
            let v = String(_v.toString(16));
            while (v.length < 7) {
                v = "0" + v;
            }
            return v;
        }
        function size(v) {
            if (v < 1024) {
                return `${v}b`;
            }
            if (v < 1024 * 1024) {
                return `${(v / 1024).toFixed(1)}kb`;
            }
            return `${(v / 1024 / 1024).toFixed(1)}Mb`;
        }
        function padl(text, width) {
            while (text.length < width) {
                text = " " + text;
            }
            return text;
        }
        function padr(text, width) {
            while (text.length < width) {
                text = text + " ";
            }
            return text;
        }
        const lines = [];
        let offset = 0;
        for (const p of this.partitions) {
            if (p.offset > offset) {
                lines.push(`  ${toAddr(offset)}:${toAddr(p.offset)} ${padl(size(p.offset - offset), 10)}  [ UNUSED ]`);
            }
            lines.push(`  ${toAddr(p.offset)}:${toAddr(p.size)} ${padl(size(p.size), 10)}  ${padr(p.name, 16)}  ${p.type}/${p.subtype} ${p.isReadonly ? "RO" : ""}`);
            offset = p.offset + p.size;
        }
        if (this.#flashSize && offset < this.#flashSize) {
            lines.push(`  ${toAddr(offset)}:${toAddr(this.#flashSize)} ${padl(size(this.#flashSize - offset), 10)}  [ UNUSED ]`);
        }
        return lines.join("\n");
    }
    get csv() {
        const pad = (text, length) => {
            text += ', ';
            while (text.length < length) {
                text += " ";
            }
            return text;
        };
        const addr = (_v) => {
            let v = _v.toString(16);
            while (v.length < 7) {
                v = "0" + v;
            }
            return "0x" + v + ",";
        };
        const lines = [];
        lines.push([
            pad("# Name", 16),
            pad("Type", 7),
            pad("Subtype", 9),
            pad("Offset", 10),
            pad("Size", 10),
            "Flags"
        ].join(" "));
        for (const r of this.#records) {
            let flags = "";
            if (r.isReadonly) {
                flags += "readonly";
            }
            lines.push([
                pad(r.name, 16),
                pad(r.type, 7),
                pad(r.subtype, 9),
                addr(r.offset),
                addr(r.size),
                flags
            ].join(" "));
        }
        return lines.join("\n");
    }
    get json() {
        const partitions = [];
        for (const r of this.#records) {
            partitions.push({
                name: r.name,
                type: r.type,
                subtype: r.subtype,
                offset: r.offset,
                size: r.size,
                isReadonly: r.isReadonly,
            });
        }
        return { version: "0.1", partitions };
    }
    get binary() {
        const result = new Uint8Array(PartitionTableSize);
        result.fill(0xff);
        let offset = 0;
        for (const record of this.#records) {
            const bin = record.binary;
            result.set(bin, offset);
            offset += bin.length;
        }
        const checksum = Md5.hash(result.slice(0, offset));
        result.set(EndMarker, offset);
        offset += EndMarker.length;
        result.set(checksum, offset);
        offset += checksum.length;
        return result;
    }
    static from(data, size = 0) {
        assert(data.length === 4096, `unexpected data length`, {
            data
        });
        const result = new PartitionTable(size);
        for (let i = 0; i < data.length; i += 32) {
            const d = data.slice(i, i + 32);
            if (d[0] === EndMarker[0] && d[1] === EndMarker[1]) {
                break;
            }
            assert(d[0] === Magic[0] && d[1] === Magic[1], `invalid magic number`, {
                data, offset: i
            });
            const type = TypeMap[d[2]];
            assert(type, `unknown partition type`, { data, type: d[2] });
            const subtype = (type === "app") ? AppTypeMap[d[3]] :
                DataTypeMap[d[3]];
            assert(subtype, `unknown partition subtype`, { data, subtype: d[3] });
            const offset = fromLeBytes(d.slice(4, 8));
            const size = fromLeBytes(d.slice(8, 12));
            const _name = d.slice(12, 12 + 16);
            let np = 0;
            while (np < _name.length && _name[++np])
                ;
            const name = toUtf8String(_name.slice(0, np));
            const flags = fromLeBytes(d.slice(28));
            const isReadonly = !!(flags & FlagReadOnly);
            result.addPartition(name, type, subtype, offset, size, isReadonly);
        }
        return result;
    }
}
/*
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
console.log(table.csv);
*/
//# sourceMappingURL=partition.js.map