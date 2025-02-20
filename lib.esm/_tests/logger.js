import { hexlify } from "../utils/data.js";
import { assert } from "../utils/errors.js";
import { repeat } from "../utils/strings.js";
export class Logger {
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
            let line = "  " + hexlify(chunk.slice(0, 8)) + " " + hexlify(chunk.slice(8));
            line += repeat(" ", 37 - line.length) + "|  ";
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
        this.printer(repeat(" ", this.#indent * 2) + message);
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
        assert(false, message, info);
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
//# sourceMappingURL=logger.js.map