export type Printer = (line: string) => void;
export declare class Logger {
    #private;
    readonly printer: Printer;
    constructor(printer?: Printer);
    get indent(): number;
    data(data: Uint8Array, title?: string): void;
    info(message: string): void;
    object(obj: any, title?: string): void;
    _print(message: string): void;
    /**
     *  Asserts %%cond%%, and dedents on failure.
     */
    assertDedent(cond: any, message: string, info?: Record<string, any>): asserts cond;
    /**
     *  A Logger which does not emit any output.
     */
    static voidLogger(): Logger;
    /**
     *  A Logger which logs to the console.
     */
    static logger(): Logger;
}
//# sourceMappingURL=logger.d.ts.map