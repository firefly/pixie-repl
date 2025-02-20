"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.stall = stall;
/**
 *  Returns a **Promise** that will resolve after %%duration%%.
 */
function stall(duration) {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}
//# sourceMappingURL=timer.js.map