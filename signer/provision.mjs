import { inspect } from "util";
import fs from "fs";
import { join } from "path";

import { read } from 'read';

import { SerialPort } from "../../firefly-js/lib.esm/node-specific.js";
import { DeviceEsp32c3 } from "../../firefly-js/lib.esm/device-esp32c3.js";

import {
    getNumber, hexlify, id, randomBytes, toBeArray, zeroPadValue,
    Mnemonic, Signature, HDNodeWallet
} from "ethers";

import { verify } from "./attest.mjs";


const FOLDER = "/Volumes/FireflyProvision";

function readFile(path) {
    return fs.readFileSync(join(FOLDER, path)).toString().trim();
}

function pad(v, length) {
    while (v.length < length) { v = "0" + v; }
    return v;
}

function toHex(v, length) {
    if (typeof(v) === "number") { v = hexlify(toBeArray(v)); }
    return zeroPadValue(v, length).substring(2);
}

function getDeviceInfo(model) {
    let latest = 1;
    for (const filename of fs.readdirSync(join(FOLDER, "devices"))) {
        const match = filename.match(/^rev-([0-9A-F]+)-([0-9A-F]+).txt$/i);
        if (match) {
            if (parseInt(match[1], 16) === model) {
                const serial = parseInt(match[2], 16);
                if (serial > latest) { latest = serial; }
            }
        }
    }

    const serial = latest + 1;
    const filename = join(FOLDER, `devices/rev-${ toHex(model, 2) }-${ toHex(serial, 3) }.txt`);
    return { filename, serial };
}


function stall(duration) {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}

class Log {
    constructor(filename) {
        this._filename = filename;
        this._logs = [ ];
    }

    log(message) {
        console.log(message);
        inspect(message).split("\n").forEach((line) => {
            this._logs.push(line);
        });
    }

    save() {
        fs.writeFileSync(this._filename, this._logs.join("\n"));
    }
}

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

        const { filename, serial } = getDeviceInfo(model);;

        await read({ prompt: `Burn Serial Number: ${ serial } [press enter]` });

        const log = new Log(filename);

        // Get the device; errors just restart for the same serial
        let device;
        try {
            const serialPort = SerialPort.discover(true);
            await serialPort.connect();
            device = new DeviceEsp32c3(serialPort);
        } catch (error) {
            console.log({ error });;
            continue;
        }

        const sendCommand = async (line, ignoreError) => {
            const result = { };
            const errors = [ ];
            device.writeLine(line);
            while (true) {
                const line = await device.readLine();

                if (line === "<OK") { break; }
                if (line === "<ERROR") {
                    if (ignoreError) { break; }
                    if (errors.length) {
                        throw new Error(errors.join("; "));
                    } else {
                        throw new Error("error encountered");
                    }
                }

                const match = line.match(/^<([a-zA-Z0-9._-]*)=(.*)$/);
                if (match) {
                    // REPL keyed output parameter
                    result[match[1]] = match[2];
                } else if (line.startsWith("?")) {
                    // REPL info
                    log.log(`[ INFO ] ${ line.substring(1).trim() }`);
                } else if (line.startsWith("!")) {
                    // REPL error
                    log.log(`[ ERROR ] ${ line.substring(1).trim() }`);
                    errors.push(line.substring(1).trim());
                } else if (line.match(/^ *I \([0-9+]\)/)) {
                    // ESP info
                    log.log(`[ INFO ] ${ line.trim() }`);
                } else if (line) {
                    // Something else
                    log.log(`[ WARNING ] Unknown: ${ line }`);
                }

                await stall(100);
            }
            if (errors.length) { result.errors = errors; }
            return result;
        }

        try {

            // Wait until the device is ready; PING to reset READY if needed
            let count = 0;
            while (true) {
                const line = await device.readLine();
                if (line === "<READY") { break; }
                await stall(100);
                if (count++ > 10) {
                    await sendCommand("PING");
                    count = 0;
                }
            }

            await stall(500);

            await sendCommand(`NOP`, true);

            await stall(100);

            log.log(`READY; beginning serial=${ serial } filename=${ JSON.stringify(filename) }`);

            await sendCommand(`SET-MODEL=${ model }`);
            await sendCommand(`SET-SERIAL=${ serial }`);

            const dump = await sendCommand(`DUMP`);
            log.log({ dump });

            await sendCommand(`STIR-ENTROPY=${ hexlify(randomBytes(32)) }`);
            await sendCommand(`STIR-IV=${ hexlify(randomBytes(32)) }`);
            await sendCommand(`STIR-KEY=${ hexlify(randomBytes(32)) }`);

            const keypair = await sendCommand(`GEN-KEY`);
            log.log({ keypair });
            const N = keypair["pubkey.N"].split(" ")[0];

            const message = `model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex("0x" + N, 384) }`
            log.log({ message });

            const attest = wallet.signMessageSync(message);
            log.log({ attest });

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
