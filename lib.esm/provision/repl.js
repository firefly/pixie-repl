import { randomBytes } from "crypto";
import { verify } from "../attest.js";
import { getBytes, hexlify } from "../utils/data.js";
import { assert } from "../utils/errors.js";
import { toUtf8Bytes, toUtf8String } from "../utils/strings.js";
import { stall } from "../utils/timer.js";
export class REPL {
    device;
    logs;
    constructor(device) {
        this.device = device;
        this.logs = [];
    }
    #ready;
    async waitReady() {
        if (!this.#ready) {
            this.#ready = (async () => {
                await this.device.reset();
                let count = 0;
                while (true) {
                    const line = await this._readLine();
                    if (line === "<READY") {
                        break;
                    }
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
    async _sendCommand(command, arg) {
        if (arg) {
            if (typeof (arg) === "number") {
                command += `=${arg}`;
            }
            else if (typeof (arg) === "string") {
                command += `=${hexlify(toUtf8Bytes(arg))}`;
            }
            else if (arg instanceof Uint8Array) {
                command += `=${hexlify(arg)}`;
            }
            else {
                throw new Error("unknown");
            }
        }
        const result = {};
        const errors = [];
        await this._writeLine(command);
        while (true) {
            const line = await this._readLine();
            if (line === "<OK") {
                break;
            }
            if (line === "<ERROR") {
                if (errors.length) {
                    throw new Error(errors.join("; "));
                }
                else {
                    throw new Error("unknown error");
                }
            }
            let match;
            if (line.startsWith("?")) {
                this.logs.push(`[ INFO ] ${line.substring(1).trim()}`);
            }
            else if (line.startsWith("!")) {
                errors.push(line.substring(1).trim());
            }
            else if (match = line.match(/^<([^=]+)=([a-z]+):(.*)$/)) {
                const key = match[1];
                const type = match[2];
                const value = match[3];
                switch (type) {
                    case "buffer":
                        result[key] = getBytes(value.split(" ")[0]);
                        break;
                    case "number":
                        result[key] = parseInt(value);
                        break;
                    case "void":
                        result[key] = null;
                        break;
                    default:
                        throw new Error(`unknown type: ${type}`);
                }
            }
            else if (match = line.match(/^(\x1b\[[^ ]*|| *)(I.*)/)) {
                // ESP info
                this.logs.push(`[ INFO ] ${match[2].trim()}`);
            }
            else if (line) {
                // Something else
                this.logs.push(`[ WARNING ] Unknown: ${line}`);
            }
        }
        return result;
    }
    async _readLine() {
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
    async _writeLine(line) {
        let data = toUtf8Bytes(line + "\n");
        while (data.length) {
            const result = await this.device._write(data.slice(0, 128));
            if (result == false) {
                return false;
            }
            await stall(5);
            data = data.slice(128);
        }
        return true;
    }
    async attest() {
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
    async reset() {
        await this.waitReady();
        await this._sendCommand("RESET");
        await stall(2000);
    }
    async dump() {
        await this.waitReady();
        return await this._sendCommand("DUMP");
    }
    async generateKey() {
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
        assert(typeof (genkey.marker) === "number", "invalid marker", {
            result: genkey
        });
        return genkey;
    }
    async setProvisionData(data) {
        await this.waitReady();
        await this._sendCommand("SET-ATTEST", data.attest);
        await this._sendCommand("SET-MODEL", data.model);
        await this._sendCommand("SET-SERIAL", data.serial);
    }
    async burn() {
        await this.waitReady();
        await this._sendCommand("WRITE");
        await this._sendCommand("BURN");
    }
}
//# sourceMappingURL=repl.js.map