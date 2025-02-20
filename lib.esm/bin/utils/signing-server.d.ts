import type { Server } from "http";
import type { BaseWallet } from "ethers";
import type { AttestDatabase } from "./attest-db.js";
export interface Options {
    model: number;
    database: AttestDatabase;
    signer: BaseWallet;
    port?: number;
}
export declare function start(options: Options): Server;
//# sourceMappingURL=signing-server.d.ts.map