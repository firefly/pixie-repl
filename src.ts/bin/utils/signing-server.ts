import { createServer } from "http";
import { URL } from "url";

import { compute } from "../../attest.js";

import { getBytes } from "../../utils/data.js";
import { assert } from "../../utils/errors.js";


import type { Server } from "http";

import type { BaseWallet } from "ethers";

import type { AttestDatabase } from "./attest-db.js";


export interface Options {
    model: number;
    database: AttestDatabase;
    signer: BaseWallet;

    port?: number;
}

export function start(options: Options): Server {
    options = Object.assign({ }, options);
    if (options.port == null) { options.port = 8000; }
    const { database, model, signer } = options;

    const server = createServer((req, resp) => {
        const url = new URL(`http:/\/localhost${ req.url }` || "/");

        const sendResponse = (data: string, type: string) => {
           resp.writeHead(200, {
                "Content-Length": data.length,
                "Content-Type": type
            });
            resp.end(data);
        }

        try {
            // URL: /provision
            // Returns:
            //  - Serial Number
            //  - Model Number
            //  - Attestation Proof
            switch (url.pathname) {
                case "/provision": {

                    const pubkey = url.searchParams.get("pubkey") || "";
                    assert(getBytes(pubkey).length === 384, "invalid pubkey", {
                        pubkey
                    });

                    const cipherdata = url.searchParams.get("cipherdata") || "";
                    assert(getBytes(cipherdata).length === 1220, "invalid cipherdata", {
                        pubkey
                    });

                    const marker = url.searchParams.get("marker") || "";
                    assert(getBytes(marker).length === 4, "invalid marker", {
                        pubkey
                    });

                    const serial = database.getNextSerial(model);
                    const attest = compute(signer, model, serial, pubkey);

                    database.write(model, serial, {
                        attest, cipherdata, pubkey, marker
                    });

                    sendResponse(JSON.stringify({
                        model, serial, attest
                    }), "text/plain");
                    break;
                }

                default:
                    console.log("404", req.url);
                    resp.writeHead(404, { });
                    resp.end();
            }

        } catch (error) {
            console.log("ERROR", error);
            resp.writeHead(500, { });
            resp.end();
        }
    });

    server.listen(options.port, () => {
        console.log(`Server running on: http:/\/localhost:${ options.port }`);
    });

    return server;
}
