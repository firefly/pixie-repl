
/**
 *  Concatenate an array of %%datas%% Uint8Arrays into a single
 *  Uint8Array.
 */
export function concat(datas: Array<Uint8Array>): Uint8Array {
    const length = datas.reduce((a, d) => (a + d.length), 0);

    const result = new Uint8Array(length);

    let offset = 0;
    for (const data of datas) {
        result.set(data, offset);
        offset += data.length;
    }

    return result;
}

const HEX = "0123456789abcdef";

/**
 *  Create a string representation of %%value%% as a hex string. If
 *  %%width%% is a number, it will be padded (on the left) with 0
 *  nibbles and it %%width%% is ``true``, will be padded (on the left)
 *  to an even length.
 */
export function hexlify(value: bigint | number | Uint8Array, width?: boolean | number): string {

    let result = "";

    if (typeof(value) === "number" || typeof(value) === "bigint") {
        result = value.toString(16);
    } else {
        for (let i = 0; i < value.length; i++) {
            const d = value[i];
            result += HEX[d >> 4] + HEX[d & 0x0f];
        }
    }

    if (typeof(width) === "number") {
        while (result.length < 2 * width) { result = "0" + result; }
    } else if (width) {
        if (result.length % 2) { result = "0" + result; }
    }

    return result;
}

/**
 *  Convert %%bytes%% from a Little-Endian representation to a
 *  number.
 */
export function fromLeBytes(bytes: Array<number> | Uint8Array): number {
    let result = 0;
    for (let i = 0; i < bytes.length; i++) {
        result |= (bytes[i] << (i << 3));
    }
    return result >>> 0;
}

/**
 *  Convert %%value%% to a Little-Endian representation as a
 *  Uint8Array %%width%% bytes wide.
 */
export function toLeBytes(value: bigint | number, width: number): Uint8Array {
    if (typeof(value) === "bigint") { value = Number(value); }

    const result = new Uint8Array(width);
    for (let i = 0; i < width; i++) {
        result[i] = Number(value & 0xff);
        value >>= 8;
    }
    return result;
}


