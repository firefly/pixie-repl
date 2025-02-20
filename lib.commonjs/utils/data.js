"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.concat = concat;
exports.hexlify = hexlify;
exports.getBytes = getBytes;
exports.fromLeBytes = fromLeBytes;
exports.toLeBytes = toLeBytes;
/**
 *  Concatenate an array of %%datas%% Uint8Arrays into a single
 *  Uint8Array.
 */
function concat(datas) {
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
function hexlify(value, width) {
    let result = "";
    if (typeof (value) === "number" || typeof (value) === "bigint") {
        result = value.toString(16);
    }
    else {
        for (let i = 0; i < value.length; i++) {
            const d = value[i];
            result += HEX[d >> 4] + HEX[d & 0x0f];
        }
    }
    if (typeof (width) === "number") {
        while (result.length < 2 * width) {
            result = "0" + result;
        }
    }
    else if (width) {
        if (result.length % 2) {
            result = "0" + result;
        }
    }
    return result;
}
function getBytes(hex) {
    if (hex.length % 2) {
        throw new Error(`bad length`);
    }
    if (hex.startsWith("0x")) {
        hex = hex.substring(2);
    }
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substring(i, i + 2), 16));
    }
    return new Uint8Array(bytes);
}
/**
 *  Convert %%bytes%% from a Little-Endian representation to a
 *  number.
 */
function fromLeBytes(bytes) {
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
function toLeBytes(value, width) {
    if (typeof (value) === "bigint") {
        value = Number(value);
    }
    const result = new Uint8Array(width);
    for (let i = 0; i < width; i++) {
        result[i] = Number(value & 0xff);
        value >>= 8;
    }
    return result;
}
//# sourceMappingURL=data.js.map