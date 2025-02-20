"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.assert = assert;
function assert(cond, message, info) {
    if (cond) {
        return;
    }
    const error = new Error(message);
    if (info) {
        for (const key in info) {
            error[key] = info[key];
        }
    }
    throw error;
}
//# sourceMappingURL=errors.js.map