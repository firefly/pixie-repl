"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.repeat = repeat;
exports.toUtf8Bytes = toUtf8Bytes;
exports.toUtf8String = toUtf8String;
exports.extractString = extractString;
const errors_js_1 = require("./errors.js");
/**
 *  Return a string by repeating the string %%c%% to %%length%%.
 */
function repeat(c, length) {
    (0, errors_js_1.assert)(c.length > 0, "invalid string");
    while (c.length < length) {
        c += c;
    }
    return c.substring(0, length);
}
const _TextEncoder = new TextEncoder();
function toUtf8Bytes(text) {
    return _TextEncoder.encode(text);
}
const _TextDecoder = new TextDecoder();
function toUtf8String(data) {
    return _TextDecoder.decode(data);
}
function extractString(data) {
    let i = 0;
    while (i < data.length && data[i] >= 32 && data[i] < 127) {
        i++;
    }
    return toUtf8String(data.slice(0, i));
}
//# sourceMappingURL=strings.js.map