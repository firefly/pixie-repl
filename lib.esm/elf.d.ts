export type OS = "System V" | "HP-UX" | "NetBSD" | "Linux" | "GNU Hurd" | "Solaris" | "AIX (Monterey)" | "IRIX" | "FreeBSD" | "Tru64" | "Novell Modesto" | "OpenBSD" | "OpenVMS" | "NonStop Kernel" | "AROS" | "FenixOS" | "Nuxi CloudABI" | "Stratus Technologies OpenVOS";
export type ElfType = "ET_NONE" | "ET_REL" | "ET_EXEC" | "ET_DYN" | "ET_CORE" | "ET_LOOS" | "ET_HIOS" | "ET_LOPROC" | "ET_HIPROC";
export type ElfSectionType = "SHT_NULL" | "SHT_PROGBITS" | "SHT_SYMTAB" | "SHT_STRTAB" | "SHT_RELA" | "SHT_HASH" | "SHT_DYNAMIC" | "SHT_NOTE" | "SHT_NOBITS" | "SHT_REL" | "SHT_SHLIB" | "SHT_DYNSYM" | "SHT_INIT_ARRAY" | "SHT_FINI_ARRAY" | "SHT_PREINIT_ARRAY" | "SHT_GROUP" | "SHT_SYMTAB_SHNDX" | "SHT_NUM" | "SHT_LOOS";
declare class ElfSection {
    name: string;
    data: Uint8Array;
    type: number;
    flags: number;
    address: number;
    offset: number;
    link: number;
    info: number;
    align: number;
    entrySize: number;
    get typeName(): string;
    get size(): number;
}
declare class ElfSegment {
    type: number;
    flags: number;
    offset: number;
    virtualAddress: number;
    physicalAddress: number;
    memorySize: number;
    align: number;
    data: Uint8Array;
    get fileSize(): number;
}
export declare class ElfFile {
    endian: "little" | "big";
    wordSize: 32 | 64;
    abiVersion: number;
    flags: number;
    os: number;
    type: number;
    entry: number;
    readonly sections: Array<ElfSection>;
    readonly segments: Array<ElfSegment>;
    get osName(): OS;
    get typeName(): ElfType;
    getSection(name: string): null | ElfSection;
    static from(data: Uint8Array): ElfFile;
}
export {};
//# sourceMappingURL=elf.d.ts.map