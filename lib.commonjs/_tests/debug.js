"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BinDiff = void 0;
const data_js_1 = require("../utils/data.js");
function pad(v) {
    while (v.length < 8) {
        v = "0" + v;
    }
    return v;
}
function decode(chunk) {
    let result = "";
    for (let i = 0; i < chunk.length; i++) {
        const c = chunk[i];
        if (c >= 32 && c <= 127) {
            result += String.fromCharCode(c);
        }
        else {
            result += ".";
        }
    }
    return result;
}
function line(index, data) {
    const hex = (0, data_js_1.hexlify)(data);
    const nibbles = [];
    for (let i = 0; i < 32; i += 4) {
        nibbles.push(hex.substring(i, i + 4));
    }
    return `${pad(index.toString(16))}: ${nibbles.join(" ")}   ${decode(data)}`;
}
function diff(a, b) {
    let result = "";
    const length = Math.max(a.length, b.length);
    for (let i = 0; i < length; i++) {
        result += (a[i] === b[i]) ? " " : "^";
    }
    if (result.trim() === "") {
        return "";
    }
    return result;
}
class BinDiff {
    actual;
    expected;
    constructor(actual, expected) {
        this.actual = actual;
        this.expected = expected;
    }
    dump(from, to, onlyDiff) {
        if (from == null) {
            from = 0;
        }
        if (to == null) {
            to = Math.max(this.actual.length, this.expected.length);
        }
        let countDiff = 0;
        for (let i = from; i < to; i += 16) {
            const a = this.actual.slice(i, i + 16), e = this.expected.slice(i, i + 16);
            const la = line(i, a), le = line(i, e);
            const ld = diff(la, le);
            if (!ld && onlyDiff) {
                continue;
            }
            if (ld && countDiff++ > 10) {
                console.log("Too many diffs; stopping");
                break;
            }
            if (ld) {
                console.log("ACTUAL:", la);
                console.log("EXPECT:", le);
                console.log("       ", diff(la, le));
            }
            else {
                console.log("       ", le);
            }
        }
    }
}
exports.BinDiff = BinDiff;
//# sourceMappingURL=debug.js.map