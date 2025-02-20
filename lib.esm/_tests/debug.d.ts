export declare class BinDiff {
    readonly actual: Uint8Array;
    readonly expected: Uint8Array;
    constructor(actual: Uint8Array, expected: Uint8Array);
    dump(from?: number, to?: number, onlyDiff?: boolean): void;
}
//# sourceMappingURL=debug.d.ts.map