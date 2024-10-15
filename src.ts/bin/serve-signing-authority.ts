#!/usr/bin/env node

import { readFileSync } from "fs";
import { resolve } from "path";

import { HDNodeWallet, Mnemonic } from "ethers";
import { read } from 'read';

import { version } from "../_version.js";
import { getModelName } from "../attest.js";

import { assert } from "../utils/errors.js";

import { AttestDatabaseFolder } from "../provision/attest-db.js";
import { start } from "../provision/signing-server.js";


function readTextFile(path: string): string {
    return readFileSync(path).toString().trim();
}

(async function() {

    console.log(`Starting Siging Server (v${ version })...`);

    // Get the Model Information
    const _model = await read({ prompt: "  Model Number:" });
    assert(_model.match(/^([0-9]+)|(0x?[0-9a-f]+)$/i),
      `invalid model number: ${ JSON.stringify(_model) }`);
    const model = parseInt(_model);
    const modelName = getModelName(model);
    console.log(`  Model: ${ modelName }`);

    const basePath = await read({ prompt: "  Provision Base Path:" });

    // Load the signing private key
    const phrase = readTextFile(resolve(basePath, "creds/mnemonic.txt"));
    const password = await read({
        prompt: "password: ",
        silent: true,
        replace: "*"
    });

    const mnemonic = Mnemonic.fromPhrase(phrase, password);
    const signer = HDNodeWallet.fromMnemonic(mnemonic);

    // Check the mnemonic and password match
    {
        const address = readTextFile(resolve(basePath, "creds/address.txt"));
        assert(address === signer.address, `bad password; decrypted mnemonic address mismatch`, {
            expected: address, address: signer.address
        });
    }

    // Load the device DB
    const database = new AttestDatabaseFolder(resolve(basePath, "devices"));

    start({
        database, model, signer
    }).on("error", (error) => {
        console.log(error);
    });
})();

    //const phrase = "wisdom about mask net year physical sheriff inform moment energy wasp doctor";
    //const path = "/";

