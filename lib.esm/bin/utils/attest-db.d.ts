export interface AttestEntry {
    attest: string;
    cipherdata: string;
    marker: string;
    pubkey: string;
}
export interface AttestDatabase {
    read(model: number, serial: number): null | AttestEntry;
    write(model: number, serial: number, entry: AttestEntry): void;
    getNextSerial(model: number): number;
}
export declare class AttestDatabaseFolder implements AttestDatabase {
    readonly path: string;
    constructor(path: string);
    read(model: number, serial: number): null | AttestEntry;
    write(model: number, serial: number, entry: AttestEntry): void;
    getNextSerial(model: number): number;
    _getFilename(model: number, serial: number): string;
}
//# sourceMappingURL=attest-db.d.ts.map