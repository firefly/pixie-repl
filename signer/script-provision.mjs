import { inspect } from "util";
import fs from "fs";
import { join } from "path";

import { read } from 'read';

import {
    getNumber, hexlify, randomBytes,
    Mnemonic, HDNodeWallet
} from "ethers";

import { Log } from "./log.mjs";
import { FireflyRepl } from "./repl.mjs";
import { compute, verify } from "./attest.mjs";


const FOLDER = "/Volumes/FireflyProvision";

function readCred(filename) {
    return fs.readFileSync(join(FOLDER, "creds", filename)).toString().trim();
}

(async function() {
    const model = getNumber(await read({ prompt: "Model Number:" }));
    console.log(`MODEL: ${ model } (0x${ model.toString(16) })`);

    const phrase = readCred("mnemonic.txt");

    const password = await read({
        prompt: "password: ",
        silent: true,
        replace: "*"
    });

    const address = readCred("address.txt");

    const mnemonic = Mnemonic.fromPhrase(phrase, password);
    const wallet = HDNodeWallet.fromMnemonic(mnemonic);

    if (wallet.address != address) {
        throw new Error(`incorrect password: ${ address } (derivced ${ wallet.address }`);
    }


    while (true) {
        const log = Log.getNextLog(model);

        const serial = log.get("serial");

        await read({ prompt: `Burn Serial Number: ${ serial } [press enter]` });

        const repl = new FireflyRepl(log);

        // Get the device; errors just restart for the same serial
        try {
            await repl.connect();
        } catch (error) {
            console.log({ error });;
            continue;
        }

        try {
            await repl.waitReady();

            log.log(`READY; beginning serial=${ serial } filename=${ JSON.stringify(log.filename) }`);

            const { version } = await repl.sendCommand(`VERSION`);
            if (version !== 1) {
                throw new Error(`unsupported version: ${ version }`);
            }

            await repl.sendCommand(`SET-MODEL=${ model }`);
            await repl.sendCommand(`SET-SERIAL=${ serial }`);

            const dump = await repl.sendCommand(`DUMP`);
            log.log({ dump });

            await repl.sendCommand(`STIR-ENTROPY=${ hexlify(randomBytes(32)) }`);
            await repl.sendCommand(`STIR-IV=${ hexlify(randomBytes(32)) }`);
            await repl.sendCommand(`STIR-KEY=${ hexlify(randomBytes(32)) }`);

            const keypair = await repl.sendCommand(`GEN-KEY`);
            log.log({ keypair });
            log.set("pubkeyN", keypair["pubkey.N"]);
            log.set("cipherData", keypair["cipherdata"]);

            const attest = compute(wallet, model, serial, keypair["pubkey.N"]);
            log.log({ attest });
            log.set("attest", attest);

            log.log(await repl.sendCommand(`SET-ATTEST=${ attest.substring(2) }`));

            log.log({ write: await repl.sendCommand(`WRITE`) });

            log.log({ burn: await repl.sendCommand(`BURN`) });

            log.log({ dump: await repl.sendCommand(`DUMP`) });

            const proof = await repl.sendCommand(`ATTEST=0123456789abcdef`);
            console.log({ proof });
            console.log(verify(proof.attest));

            await repl.sendCommand(`RESET`);

        } catch (error) {
            log.log({ error });
        }

        log.save();
    }

})().catch((error) => {
    console.log(error);
});
