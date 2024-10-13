import { hexlify } from "./utils/data.js";
import { assert } from "./utils/errors.js";
import { repeat } from "./utils/strings.js";

export type Printer = (line: string) => void;

export class Logger {
    readonly printer: Printer;

    #indent: number;

    constructor(printer?: Printer) {
        this.printer = printer || console.log;
        this.#indent = 0;
    }

    get indent(): number { return this.#indent; }

    data(data: Uint8Array, title?: string): void {
        if (title == null) { title = "[DATA]"; }
        if (title) { title += " "; }

        this._print(`${ title }${ data.length } bytes`);

        for (let i = 0; i < data.length; i += 16) {
            const chunk = data.slice(i, i + 16);
            let line = "  " + hexlify(chunk.slice(0, 8)) + " " + hexlify(chunk.slice(8));
            line += repeat(" ", 37 - line.length) + "|  ";
            for (let j = 0; j < chunk.length; j++) {
                const c = chunk[j];
                if (c >= 32 && c <= 127) {
                    line += String.fromCharCode(c);
                } else {
                    line += ".";
                }
            }
            this._print(line);
        }
    }

    info(message: string): void {
        this._print(message);
    }

    object(obj: any, title?: string): void {
        if (title == null) { title = "[DATA]"; }
        if (title) { title += " "; }

        this._print(`${ title }${ JSON.stringify(obj) }`);
    }

    _print(message: string): void {
        if (message.startsWith("<<|")) {
            message = message.substring(3).trim();
            this.#indent--;
        }

        let indent = message.startsWith("|>>");
        if (indent) {
            message = message.substring(3).trim();
        }

        this.printer(repeat(" ", this.#indent * 2) + message);

        if (indent) { this.#indent++; }
    }

    /**
     *  Asserts %%cond%%, and dedents on failure.
     */
    assertDedent(cond: any, message: string, info?: Record<string, any>): asserts cond {
        if (cond) { return; }
        this.#indent--;
        assert(false, message, info);
    }

    /**
     *  A Logger which does not emit any output.
     */
    static voidLogger(): Logger {
        return new Logger((l: string) => { });
    }

    /**
     *  A Logger which logs to the console.
     */
    static logger(): Logger {
        return new Logger();
    }
}
