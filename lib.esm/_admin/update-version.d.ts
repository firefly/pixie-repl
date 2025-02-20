export declare const ROOT: string;
export type GetUrlResponse = {
    statusCode: number;
    statusMessage: string;
    headers: Record<string, string>;
    body: null | Uint8Array;
};
export declare function getUrl(url: string): Promise<GetUrlResponse>;
export declare function loadJson(path: string): any;
export type SortFunc = (parent: string, a: string, b: string) => number;
export declare function saveJson(filename: string, data: any, sort?: boolean | SortFunc): any;
export declare function _getNpmPackage(name: string): Promise<any>;
export declare function resolve(...args: Array<string>): string;
export declare function atomicWrite(path: string, value: string | Uint8Array): void;
//# sourceMappingURL=update-version.d.ts.map