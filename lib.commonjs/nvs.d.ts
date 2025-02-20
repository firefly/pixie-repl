export type PageState = "empty" | "active" | "full" | "erasing" | "corrupt";
export type EntryState = "empty" | "written" | "erased";
export type EntryType = "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64" | "string" | "blob" | "blob_data" | "blob_index" | "any";
export type NvsValueTypeJson = "u8" | "i8" | "u16" | "i16" | "u32" | "i32" | "u64" | "i64";
export interface NvsValueJson {
    type: NvsValueTypeJson;
    value: number;
}
export interface NvsBlobJson {
    type: "blob" | "string";
    value: string;
}
export interface NvsJson {
    namespaces: Record<string, Record<string, NvsBlobJson | NvsValueJson>>;
}
export type Value = number | string | Uint8Array;
export declare class Header {
    #private;
    get state(): PageState;
    get seqNo(): number;
    get version(): number;
    constructor(state: PageState, seqNo: number, version?: number);
    get binary(): Uint8Array;
    static fromBinary(data: Uint8Array): Header;
}
export declare abstract class Entry {
    #private;
    get namespace(): number;
    get key(): string;
    get type(): EntryType;
    get span(): number;
    get index(): number;
    get data(): Uint8Array;
    get state(): EntryState;
    constructor(ns: number, key: string, type: EntryType, span: number, index: number, data: Uint8Array);
    get binary(): Uint8Array;
    get checksum(): number;
    erase(): void;
    static from(ns: number, key: string, value: Value, type: EntryType): Entry;
}
export declare class ValueEntry extends Entry {
    constructor(ns: number, key: string, value: number, _type: EntryType);
    get value(): number;
}
export declare class NamespaceEntry extends ValueEntry {
    #private;
    get name(): string;
    constructor(ns: number, name: string);
}
export declare class BlobIndexEntry extends Entry {
    constructor(blob: BlobEntry);
}
export declare class BlobEntry extends Entry {
    #private;
    get blobData(): Uint8Array;
    get chunks(): number;
    get blobIndex(): BlobIndexEntry;
    constructor(ns: number, key: string, data: Uint8Array);
    _blobs(): Array<Uint8Array>;
    get binary(): Uint8Array;
}
export declare class Page {
    #private;
    get seqNo(): number;
    get state(): PageState;
    get entries(): Array<Entry>;
    get header(): Header;
    constructor(seqNo: number, state: PageState);
    addEntry(entry: Entry): void;
    get binary(): Uint8Array;
    static fromBinary(data: Uint8Array): Page;
}
export declare class EmptyPage extends Page {
    constructor(seqNo: number);
    get binary(): Uint8Array;
}
export declare class NVSData {
    #private;
    readonly size: number;
    constructor(size: number);
    get binary(): Uint8Array;
    get csv(): string;
    get json(): NvsJson;
    get(namespace: string, key: string): null | Value;
    getType(namespace: string, key: string): null | EntryType;
    set(namespace: string, key: string, value: any, type?: EntryType): void;
    static fromValues(values: Record<string, Record<string, any>>): NVSData;
    static fromBinary(data: Uint8Array): NVSData;
}
//# sourceMappingURL=nvs.d.ts.map