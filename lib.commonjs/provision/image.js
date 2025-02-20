"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Magic = void 0;
exports.compress = compress;
const ethers_1 = require("ethers");
const pako_1 = require("pako");
const data_js_1 = require("../utils/data.js");
// zbin
exports.Magic = 0x7a62696e;
function compress(data) {
    return (0, data_js_1.concat)([
        (0, data_js_1.toLeBytes)(exports.Magic, 4),
        (0, data_js_1.toLeBytes)(data.length, 4),
        (0, ethers_1.getBytes)((0, ethers_1.sha256)(data)),
        (0, pako_1.deflate)(data, { level: 9 })
    ]);
}
//# sourceMappingURL=image.js.map