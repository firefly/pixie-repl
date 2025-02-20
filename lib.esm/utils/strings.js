import { assert } from "./errors.js";
/**
 *  Return a string by repeating the string %%c%% to %%length%%.
 */
export function repeat(c, length) {
    assert(c.length > 0, "invalid string");
    while (c.length < length) {
        c += c;
    }
    return c.substring(0, length);
}
const _TextEncoder = new TextEncoder();
export function toUtf8Bytes(text) {
    return _TextEncoder.encode(text);
}
const _TextDecoder = new TextDecoder();
export function toUtf8String(data) {
    return _TextDecoder.decode(data);
}
export function extractString(data) {
    let i = 0;
    while (i < data.length && data[i] >= 32 && data[i] < 127) {
        i++;
    }
    return toUtf8String(data.slice(0, i));
}
//# sourceMappingURL=strings.js.map