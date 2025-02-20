"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ElfFile = void 0;
const data_js_1 = require("./utils/data.js");
const errors_js_1 = require("./utils/errors.js");
const strings_js_1 = require("./utils/strings.js");
function swapBytes(value, width) {
    let result = 0;
    for (let i = 0; i < width; i++) {
        result |= ((value >> (i << 3)) & 0xff) << ((width - i - 1) << 3);
    }
    return result;
}
const OSMap = {
    0x00: "System V",
    0x01: "HP-UX",
    0x02: "NetBSD",
    0x03: "Linux",
    0x04: "GNU Hurd",
    0x06: "Solaris",
    0x07: "AIX (Monterey)",
    0x08: "IRIX",
    0x09: "FreeBSD",
    0x0A: "Tru64",
    0x0B: "Novell Modesto",
    0x0C: "OpenBSD",
    0x0D: "OpenVMS",
    0x0E: "NonStop Kernel",
    0x0F: "AROS",
    0x10: "FenixOS",
    0x11: "Nuxi CloudABI",
    0x12: "Stratus Technologies OpenVOS"
};
const ElfTypeMap = {
    0x00: "ET_NONE",
    0x01: "ET_REL",
    0x02: "ET_EXEC",
    0x03: "ET_DYN",
    0x04: "ET_CORE",
    0xFE00: "ET_LOOS",
    0xFEFF: "ET_HIOS",
    0xFF00: "ET_LOPROC",
    0xFFFF: "ET_HIPROC"
};
const SectionTypes = {
    0x00: "SHT_NULL",
    0x01: "SHT_PROGBITS",
    0x02: "SHT_SYMTAB",
    0x03: "SHT_STRTAB",
    0x04: "SHT_RELA",
    0x05: "SHT_HASH",
    0x06: "SHT_DYNAMIC",
    0x07: "SHT_NOTE",
    0x08: "SHT_NOBITS",
    0x09: "SHT_REL",
    0x0A: "SHT_SHLIB",
    0x0B: "SHT_DYNSYM",
    0x0E: "SHT_INIT_ARRAY",
    0x0F: "SHT_FINI_ARRAY",
    0x10: "SHT_PREINIT_ARRAY",
    0x11: "SHT_GROUP",
    0x12: "SHT_SYMTAB_SHNDX",
    0x13: "SHT_NUM",
    0x60000000: "SHT_LOOS"
};
class ElfSection {
    name = "";
    data = new Uint8Array(0);
    type = 0;
    flags = 0;
    address = 0;
    offset = 0;
    link = 0;
    info = 0;
    align = 0;
    entrySize = 0;
    get typeName() {
        const result = SectionTypes[this.type];
        (0, errors_js_1.assert)(result, "unknown type", { type: this.type });
        return result;
    }
    get size() { return this.data.length; }
}
class ElfSegment {
    type = 0;
    flags = 0;
    offset = 0;
    virtualAddress = 0;
    physicalAddress = 0;
    memorySize = 0;
    align = 0;
    data = new Uint8Array(0);
    get fileSize() { return this.data.length; }
}
class ElfFile {
    endian = "little";
    wordSize = 32;
    abiVersion = 0;
    flags = 0;
    os = 0x03;
    type = 0;
    entry = 0;
    sections = [];
    segments = [];
    get osName() {
        const result = OSMap[this.os];
        (0, errors_js_1.assert)(result, "unknown OS", { os: this.os });
        return result;
    }
    get typeName() {
        const result = ElfTypeMap[this.type];
        (0, errors_js_1.assert)(result, "unknown type", { type: this.type });
        return result;
    }
    getSection(name) {
        for (const section of this.sections) {
            if (section.name === name) {
                return section;
            }
        }
        return null;
    }
    static from(data) {
        const result = new ElfFile();
        // The class is used in readValue; but set in the ident component
        let cls = 32;
        let offset = 0;
        const readValue = (length, l64) => {
            if (l64 != null && cls === 64) {
                length = l64;
            }
            (0, errors_js_1.assert)(offset + length <= data.length, "header overrun", { offset });
            const result = (0, data_js_1.fromLeBytes)(data.slice(offset, offset + length));
            offset += length;
            return result;
        };
        const seek = (_offset) => { offset = _offset; };
        // Read the ELF Header
        const magic = swapBytes(readValue(4), 4);
        (0, errors_js_1.assert)(magic === 0x7f454c46, "invalid magic number", {
            magic, magicHex: `0x${magic.toString(16)}`
        });
        const _cls = readValue(1);
        (0, errors_js_1.assert)(_cls === 1 || _cls === 2, "invalid EI_CLASS", { EI_CLASS: _cls });
        cls = (32 * _cls);
        result.wordSize = cls;
        const _endian = readValue(1);
        (0, errors_js_1.assert)(_endian === 1 || _endian === 2, "invalid EI_DATA", { EI_DATA: _endian });
        result.endian = (_endian === 1) ? "little" : "big";
        let version = readValue(1);
        (0, errors_js_1.assert)(version === 1, "invalid EI_VERSION", { EI_VERSION: version });
        result.os = readValue(1);
        result.abiVersion = readValue(1);
        // Padding
        readValue(7);
        result.type = readValue(2);
        const machine = readValue(2);
        (0, errors_js_1.assert)(machine === 0xf3, "unsupported architecture", {
            E_MACHINE: machine
        });
        version = readValue(4);
        (0, errors_js_1.assert)(version === 1, "invalid E_VERSION", { E_VERSION: version });
        result.entry = readValue(4, 8);
        const phoff = readValue(4, 8);
        const shoff = readValue(4, 8);
        result.flags = readValue(4);
        //const ehsize = 
        readValue(2);
        //const phentsize = 
        readValue(2);
        const phnum = readValue(2);
        //const shentsize = 
        readValue(2);
        const shnum = readValue(2);
        //const shstrndx = 
        readValue(2);
        // Look up strings (relies on finding an STRTAB section)
        let stringTable = null;
        const getName = (offset) => {
            if (!stringTable) {
                return "";
            }
            let end = offset;
            while (stringTable[end]) {
                end++;
            }
            return (0, strings_js_1.toUtf8String)(stringTable.slice(offset, end));
        };
        // Read sections
        seek(shoff);
        const nameOffsets = [];
        for (let i = 0; i < shnum; i++) {
            const section = new ElfSection();
            result.sections.push(section);
            // Filled in after we have processed all sections
            nameOffsets.push(readValue(4));
            section.type = readValue(4);
            section.flags = readValue(4, 8);
            section.address = readValue(4, 8);
            section.offset = readValue(4, 8);
            const size = readValue(4, 8);
            section.link = readValue(4);
            section.info = readValue(4);
            section.align = readValue(4, 8);
            section.entrySize = readValue(4, 8);
            section.data = new Uint8Array(data.slice(section.offset, section.offset + size));
            if (section.type === 0x03) {
                stringTable = section.data;
            }
        }
        // Fill in the section names from the found string table
        // @TODO: what if there is more than one (or no) string table?
        for (let i = 0; i < nameOffsets.length; i++) {
            result.sections[i].name = getName(nameOffsets[i]);
        }
        seek(phoff);
        for (let i = 0; i < phnum; i++) {
            const segment = new ElfSegment();
            result.segments.push(segment);
            segment.type = readValue(4);
            if (cls === 64) {
                segment.flags = readValue(4);
            }
            segment.offset = readValue(4, 8);
            segment.virtualAddress = readValue(4, 8);
            segment.physicalAddress = readValue(4, 8);
            const fileSize = readValue(4, 8);
            segment.memorySize = readValue(4, 8);
            if (cls === 32) {
                segment.flags = readValue(4);
            }
            segment.align = readValue(4, 8);
            segment.data = new Uint8Array(data.slice(segment.offset, segment.offset + fileSize));
        }
        return result;
    }
}
exports.ElfFile = ElfFile;
const fs_1 = __importDefault(require("fs"));
//const elf = ElfFile.from(fs.readFileSync("provision/build/pixie-provision.elf"))
const elf = ElfFile.from(fs_1.default.readFileSync("/Users/ricmoo/Development/obsolete/pixie-repl/stub/build/stub_flasher_32c3.elf"));
console.log(elf, elf.getSection(".text"), elf.getSection(".data"));
//# sourceMappingURL=elf.js.map