export function assert(cond: any, message: string, info?: Record<string, any>): asserts cond {
    if (cond) { return; }
    const error: any = new Error(message);
    if (info) {
        for (const key in info) { error[key] = info[key]; }
    }
    throw error;
}
