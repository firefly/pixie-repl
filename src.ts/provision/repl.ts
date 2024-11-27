import { randomBytes } from "crypto";

import { verify } from "../attest.js";

import { getBytes, hexlify } from "../utils/data.js";
import { assert } from "../utils/errors.js";
import { toUtf8Bytes, toUtf8String } from "../utils/strings.js";
import { stall } from "../utils/timer.js";

import type { Device } from "../device.js";
import type { AttestedDeviceInfo } from "../attest.js";

export interface ProvisionData {
    attest: Uint8Array;
    model: number;
    serial: number;
}

export interface GenerateKeyResult {
    cipherdata: Uint8Array;
    pubkey: Uint8Array;
    marker: number;
}

export class REPL {
    readonly device: Device;
    readonly logs: Array<string>;

    constructor(device: Device) {
        this.device = device;
        this.logs = [ ];
    }

    #ready?: Promise<void>;
    async waitReady(): Promise<void> {
        if (!this.#ready) {
            this.#ready = (async () => {
                await this.device.reset();

                let count = 0;

                while (true) {
                    const line = await this._readLine();
                    if (line === "<READY") { break; }
                    await stall(100);
                    if (count++ > 10) {
                        await this._sendCommand("PING");
                        count = 0;
                    }
                }

                await stall(500);

                await this._sendCommand(`NOP`);

                await stall(100);
            })();
        }
        await this.#ready;
    }

    async _sendCommand(command: string, arg?: number | string | Uint8Array): Promise<Record<string, any>> {
        if (arg) {
            if (typeof(arg) === "number") {
                command += `=${ arg }`;
            } else if (typeof(arg) === "string") {
                command += `=${ hexlify(toUtf8Bytes(arg)) }`;
            } else if (arg instanceof Uint8Array) {
                command += `=${ hexlify(arg) }`;
            } else {
                throw new Error("unknown");
            }
        }

        const result: Record<string, number | Uint8Array | null> = { };
        const errors: Array<string> = [ ];

        await this._writeLine(command);

        while(true) {
            const line = await this._readLine();
            if (line === "<OK") { break; }
            if (line === "<ERROR") {
                if (errors.length) {
                    throw new Error(errors.join("; "));
                } else {
                    throw new Error("unknown error");
                }
            }

            let match: RegExpMatchArray | null;
            if (line.startsWith("?")) {
                this.logs.push(`[ INFO ] ${ line.substring(1).trim() }`);

            } else if (line.startsWith("!")) {
                errors.push(line.substring(1).trim());

            } else if (match = line.match(/^<([^=]+)=([a-z]+):(.*)$/)) {
                const key = match[1];
                const type = match[2];
                const value = match[3];

                switch (type) {
                    case "buffer":
                        result[key] = getBytes(value.split(" ")[0]);
                        break
                    case "number":
                        result[key] = parseInt(value);
                        break
                    case "void":
                        result[key] = null;
                        break
                    default:
                        throw new Error(`unknown type: ${ type }`);
                }

            } else if (match = line.match(/^(\x1b\[[^ ]*|| *)(I.*)/)) {
                // ESP info
                this.logs.push(`[ INFO ] ${ match[2].trim() }`);

            } else if (line) {
                // Something else
                this.logs.push(`[ WARNING ] Unknown: ${ line }`);
            }
        }

        return result;
    }

    async _readLine(): Promise<string> {
        const data = await this.device._read();
        for (let i = 0; i < data.length; i++) {
            if (data[i] === 10) {
                this.device._unread(data.slice(i + 1));
                return toUtf8String(data.slice(0, i)).trim();
            }
        }
        this.device._unread(data);
        return "";
    }

    async _writeLine(line: string): Promise<boolean> {
        let data = toUtf8Bytes(line + "\n");
        while (data.length) {
            const result = await this.device._write(data.slice(0, 128));
            if (result == false) { return false; }
            await stall(5);
            data = data.slice(128);
        }
        return true;
    }

    async attest(): Promise<AttestedDeviceInfo> {
        await this.waitReady();

        await this._sendCommand("LOAD-NVS");
        await this._sendCommand("LOAD-EFUSE");

        const challenge = randomBytes(32);
        const result = await this._sendCommand("ATTEST", challenge);

        const check = verify(result.attest);
        assert(("0x" + hexlify(challenge)) === check.challenge, `challenge mismatch`, {
            expected: hexlify(challenge), got: check.challenge
        });
        return check;
    }

    async reset(): Promise<void> {
        await this.waitReady();

        await this._sendCommand("RESET");
        await stall(2000);
    }

    async dump(): Promise<any> {
        await this.waitReady();

        return await this._sendCommand("DUMP");
    }

    async generateKey(): Promise<GenerateKeyResult> {
        await this.waitReady();

        await this._sendCommand("STIR-ENTROPY", randomBytes(32));
        await this._sendCommand("STIR-IV", randomBytes(16));
        await this._sendCommand("STIR-KEY", randomBytes(32));

        const genkey = await this._sendCommand("GEN-KEY");

        assert(genkey.cipherdata instanceof Uint8Array, "invalid cipherdata", {
            result: genkey
        });
        assert(genkey.pubkey instanceof Uint8Array, "invalid pubkey", {
            result: genkey
        });
        assert(typeof(genkey.marker) === "number", "invalid marker", {
            result: genkey
        });

        return <GenerateKeyResult>genkey;
    }

    async setProvisionData(data: ProvisionData): Promise<void> {
        await this.waitReady();

        await this._sendCommand("SET-ATTEST", data.attest);
        await this._sendCommand("SET-MODEL", data.model);
        await this._sendCommand("SET-SERIAL", data.serial);
    }

    async burn(): Promise<void> {
        await this.waitReady();

        await this._sendCommand("WRITE");
        await this._sendCommand("BURN");
    }
}
