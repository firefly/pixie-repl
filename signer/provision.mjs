import { inspect } from "util";
import fs from "fs";
import { join } from "path";

import { read } from 'read';

//import { SerialPort } from "../../firefly-js/lib.esm/node-specific.js";
//import { DeviceEsp32c3 } from "../../firefly-js/lib.esm/device-esp32c3.js";

import {
    getNumber, hexlify, id, randomBytes, toBeArray, zeroPadValue,
    Mnemonic, Signature, HDNodeWallet
} from "ethers";

import { Log } from "./log.mjs";
import { FireflyRepl } from "./repl.mjs";
import { verify } from "./attest.mjs";


const FOLDER = "/Volumes/FireflyProvision";

(async function() {
    const model = getNumber(await read({ prompt: "Model Number:" }));
    console.log(`MODEL: ${ model } (0x${ model.toString(16) })`);

    const phrase = readFile("creds/mnemonic.txt");

    const password = await read({
        prompt: "password: ",
        silent: true,
        replace: "*"
    });

    const address = readFile("creds/address.txt");

    const mnemonic = Mnemonic.fromPhrase(phrase, password);
    const wallet = HDNodeWallet.fromMnemonic(mnemonic);

    if (wallet.address != address) {
        throw new Error(`incorrect password: ${ address } (derivced ${ wallet.address }`);
    }


    while (true) {
        const log = Log.getNextLog(model);

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

            log.log(`READY; beginning serial=${ serial } filename=${ JSON.stringify(filename) }`);

            const { version } = await sendCommand(`VERSION`);
            if (version !== "1") {
                throw new Error(`unsupported version: ${ version }`);
            }

            await sendCommand(`SET-MODEL=${ model }`);
            await sendCommand(`SET-SERIAL=${ serial }`);

            const dump = await sendCommand(`DUMP`);
            log.log({ dump });

            await sendCommand(`STIR-ENTROPY=${ hexlify(randomBytes(32)) }`);
            await sendCommand(`STIR-IV=${ hexlify(randomBytes(32)) }`);
            await sendCommand(`STIR-KEY=${ hexlify(randomBytes(32)) }`);

            const keypair = await sendCommand(`GEN-KEY`);
            log.log({ keypair });
            log.set("pubkeyN", keypair["pubkey.N"].split(" ")[0]);
            log.set("cipherData", keypair["cipherdata"].split(" ")[0]);

            const message = `model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex("0x" + N, 384) }`
            log.log({ message });

            const attest = wallet.signMessageSync(message);
            log.log({ attest });
            log.set("attest", attest);

            const sig = Signature.from(attest).compactSerialized.substring(2);
            log.log(await sendCommand(`SET-ATTEST=${ sig }`));

            log.log(await sendCommand(`WRITE`));

            log.log(await sendCommand(`BURN`));

/*
            const proof = await sendCommand(`ATTEST=0123456789abcdef`);
            console.log({ proof });
            console.log(verify(proof.attest));
*/
            log.log({ dump: await sendCommand(`DUMP`, true) });

        } catch (error) {
            log.log({ error });
        }

        log.save();
    }

})().catch((error) => {
    console.log(error);
});
