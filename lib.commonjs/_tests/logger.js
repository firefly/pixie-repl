"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Logger = void 0;
const data_js_1 = require("../utils/data.js");
const errors_js_1 = require("../utils/errors.js");
const strings_js_1 = require("../utils/strings.js");
class Logger {
    printer;
    #indent;
    constructor(printer) {
        this.printer = printer || console.log;
        this.#indent = 0;
    }
    get indent() { return this.#indent; }
    data(data, title) {
        if (title == null) {
            title = "[DATA]";
        }
        if (title) {
            title += " ";
        }
        this._print(`${title}${data.length} bytes`);
        for (let i = 0; i < data.length; i += 16) {
            const chunk = data.slice(i, i + 16);
            let line = "  " + (0, data_js_1.hexlify)(chunk.slice(0, 8)) + " " + (0, data_js_1.hexlify)(chunk.slice(8));
            line += (0, strings_js_1.repeat)(" ", 37 - line.length) + "|  ";
            for (let j = 0; j < chunk.length; j++) {
                const c = chunk[j];
                if (c >= 32 && c <= 127) {
                    line += String.fromCharCode(c);
                }
                else {
                    line += ".";
                }
            }
            this._print(line);
        }
    }
    info(message) {
        this._print(message);
    }
    object(obj, title) {
        if (title == null) {
            title = "[DATA]";
        }
        if (title) {
            title += " ";
        }
        this._print(`${title}${JSON.stringify(obj)}`);
    }
    _print(message) {
        if (message.startsWith("<<|")) {
            message = message.substring(3).trim();
            this.#indent--;
        }
        let indent = message.startsWith("|>>");
        if (indent) {
            message = message.substring(3).trim();
        }
        this.printer((0, strings_js_1.repeat)(" ", this.#indent * 2) + message);
        if (indent) {
            this.#indent++;
        }
    }
    /**
     *  Asserts %%cond%%, and dedents on failure.
     */
    assertDedent(cond, message, info) {
        if (cond) {
            return;
        }
        this.#indent--;
        (0, errors_js_1.assert)(false, message, info);
    }
    /**
     *  A Logger which does not emit any output.
     */
    static voidLogger() {
        return new Logger((l) => { });
    }
    /**
     *  A Logger which logs to the console.
     */
    static logger() {
        return new Logger();
    }
}
exports.Logger = Logger;
//# sourceMappingURL=logger.js.map