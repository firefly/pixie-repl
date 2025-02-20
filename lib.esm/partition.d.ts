export type Type = "app" | "data";
export type AppType = "factory" | "test" | "ota_0" | "ota_1";
export type DataType = "ota" | "phy" | "nvs" | "coredump" | "nvs_keys" | "efuse" | "undefined" | "esphttpd" | "fat" | "spiffs" | "littlefs";
export type SubTypes<T extends Type> = T extends "app" ? AppType : T extends "data" ? DataType : never;
export interface PartitionJson {
    name: string;
    type: string;
    subtype: string;
    offset: number;
    size: number;
    isReadonly: boolean;
}
export interface PartitionTableJson {
    version: string;
    partitions: Array<PartitionJson>;
}
export declare class Partition<T extends Type> {
    readonly name: string;
    readonly type: T;
    readonly subtype: SubTypes<T>;
    readonly offset: number;
    readonly size: number;
    readonly isReadonly: boolean;
    constructor(name: string, type: T, subtype: SubTypes<T>, offset: number, size: number, isReadonly: boolean);
    get binary(): Uint8Array;
}
export declare class PartitionTable {
    #private;
    get flashSize(): number;
    constructor(flashSize?: number);
    get partitions(): Array<Partition<Type>>;
    addPartition<T extends Type>(name: string, type: T, subtype: SubTypes<T>, offset: number, size: number, isReadonly: boolean): void;
    getPartitionAt(offset: number): null | Partition<Type>;
    getPartition(name: string): null | Partition<Type>;
    summary(): string;
    get csv(): string;
    get json(): PartitionTableJson;
    get binary(): Uint8Array;
    static from(data: Uint8Array, size?: number): PartitionTable;
}
//# sourceMappingURL=partition.d.ts.map