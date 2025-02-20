/**
 *  Concatenate an array of %%datas%% Uint8Arrays into a single
 *  Uint8Array.
 */
export declare function concat(datas: Array<Uint8Array>): Uint8Array;
/**
 *  Create a string representation of %%value%% as a hex string. If
 *  %%width%% is a number, it will be padded (on the left) with 0
 *  nibbles and it %%width%% is ``true``, will be padded (on the left)
 *  to an even length.
 */
export declare function hexlify(value: bigint | number | Uint8Array, width?: boolean | number): string;
export declare function getBytes(hex: string): Uint8Array;
/**
 *  Convert %%bytes%% from a Little-Endian representation to a
 *  number.
 */
export declare function fromLeBytes(bytes: Array<number> | Uint8Array): number;
/**
 *  Convert %%value%% to a Little-Endian representation as a
 *  Uint8Array %%width%% bytes wide.
 */
export declare function toLeBytes(value: bigint | number, width: number): Uint8Array;
//# sourceMappingURL=data.d.ts.map