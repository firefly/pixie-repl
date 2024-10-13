import fs from "fs";
import { join } from "path";

import ioctl from "ioctl";

import type { SerialPort as _SerialPort } from "./serial.js"

import { concat } from "./utils/data.js";
import { stall } from "./utils/timer.js";

//const TIOCMGET = 0x4004746a, TIOCMSET = 0x8004746d;
const TIOCMSET = 0x8004746d;
const TIOCM_RTS = 4, TIOCM_DTR = 2;

export class SerialPort implements _SerialPort {
    readonly filename: string;
    #fd: null | number;

    constructor(filename: string) {
        this.filename = filename;
        this.#fd = null;
    }

    get name(): string { return this.filename; }

    async connect(): Promise<void> {
        if (this.#fd != null) { throw new Error("already connected"); }
        this.#fd = fs.openSync(this.filename, fs.constants.O_RDWR | fs.constants.O_NONBLOCK);
        await stall(5);
    }
//@TODO: Bootmode
    async reset(bootMode?: boolean): Promise<void> {
        await this.signal({ });
        await stall(100);
        await this.signal({ dtr: true });
        await stall(100);
        await this.signal({ rts: true });
        await stall(100);
        await this.signal({ rts: true });
        await stall(100);
        await this.signal({ });
    }

    async #getFd(): Promise<number> {
        if (this.#fd == null) { throw new Error("serial not connected; call connect first"); }
        return this.#fd;
    }

    async read(): Promise<Uint8Array> {
        const fd = await this.#getFd();

        const chunks = [ ];

        while (true) {
            try {
                const buffer = new Uint8Array(1024);
                const l = fs.readSync(fd, buffer);
                chunks.push(buffer.slice(0, l));
                await stall(3);
            } catch (e: any) {
                if (e.code !== "EAGAIN") {
                    console.log("ERROR READ", e);
                    throw e;
                }
                break;
            }
        }

        const result = concat(chunks);
        //console.log({ result });
        return result;
    }

    /*
    async getSignal(): Promise<{ dtr: boolean, rts: boolean }> {
        const fd = await this.#getFd();

        const result = Buffer.from([ 0 ]);
        ioctl(fd, TIOCMGET, result);
        return {
            dtr: !!(result[0] & TIOCM_DTR),
            rts: !!(result[0] & TIOCM_RTS),
        };
    }
    */

    async signal(signal: { dtr?: boolean, rts?: boolean }): Promise<void> {
        const fd = await this.#getFd();

        const arg = Buffer.from([ 0 ]);
        if (signal.dtr) { arg[0] |= TIOCM_DTR; }
        if (signal.rts) { arg[0] |= TIOCM_RTS; }
        ioctl(fd, TIOCMSET, arg)
    }

    async write(data: Uint8Array): Promise<boolean> {
        const fd = await this.#getFd();
        let failCount = 0;
        while (data.length > 0) {
            try {
                const length = fs.writeSync(fd, data);
                data = data.slice(length);
            } catch (e: any) {
                if (e.code !== "EAGAIN") {
                    console.log("ERROR READ", e);
                    throw e;
                }
                if (failCount++ > 5) { throw e; }
            }
            await stall(3);
        }
        return true;
    }

    static discover(any?: boolean): SerialPort {
        if (any == null) { any = true; }

        const devs = fs.readdirSync("/dev").filter((dev) => {
            return dev.match(/^(cu|tty)\.(usbmodem)/);
        });

        if (devs.length === 1 || (devs.length && any)) {
            return new SerialPort(join("/dev/", devs[0]));
        }

        if (devs.length) {
            throw new Error(`Found multiple devices: ${ devs.join(", ") }`);
        }

        throw new Error("no device found");
    }

}
