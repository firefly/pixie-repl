"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.SerialPort = void 0;
const fs_1 = __importDefault(require("fs"));
const path_1 = require("path");
const ioctl_1 = __importDefault(require("ioctl"));
const data_js_1 = require("./utils/data.js");
const timer_js_1 = require("./utils/timer.js");
//const TIOCMGET = 0x4004746a, TIOCMSET = 0x8004746d;
const TIOCMSET = 0x8004746d;
const TIOCM_RTS = 4, TIOCM_DTR = 2;
class SerialPort {
    filename;
    #fd;
    constructor(filename) {
        this.filename = filename;
        this.#fd = null;
    }
    get name() { return this.filename; }
    async connect() {
        if (this.#fd != null) {
            return;
        }
        for (let i = 0; i < 5; i++) {
            try {
                this.#fd = fs_1.default.openSync(this.filename, fs_1.default.constants.O_RDWR | fs_1.default.constants.O_NONBLOCK);
            }
            catch (e) {
                if (i === 4) {
                    throw e;
                }
                if (e.code !== "EBUSY") {
                    throw e;
                }
                await (0, timer_js_1.stall)(1000);
            }
        }
        await (0, timer_js_1.stall)(5);
    }
    async reset(bootMode) {
        if (bootMode) {
            await this.signal({});
            await (0, timer_js_1.stall)(100);
            await this.signal({ dtr: true });
            await (0, timer_js_1.stall)(100);
            await this.signal({ rts: true });
            await (0, timer_js_1.stall)(100);
            await this.signal({ rts: true });
            await (0, timer_js_1.stall)(100);
            await this.signal({});
        }
        else {
            await this.signal({ rts: true });
            await (0, timer_js_1.stall)(100);
            await this.signal({});
        }
    }
    async #getFd() {
        if (this.#fd == null) {
            throw new Error("serial not connected; call connect first");
        }
        return this.#fd;
    }
    async read() {
        const fd = await this.#getFd();
        const chunks = [];
        while (chunks.length < 8) {
            try {
                const buffer = new Uint8Array(1024);
                const l = fs_1.default.readSync(fd, buffer);
                chunks.push(buffer.slice(0, l));
                await (0, timer_js_1.stall)(3);
            }
            catch (e) {
                if (e.code !== "EAGAIN") {
                    console.log("ERROR READ", e);
                    throw e;
                }
                break;
            }
        }
        const result = (0, data_js_1.concat)(chunks);
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
    async signal(signal) {
        const fd = await this.#getFd();
        const arg = Buffer.from([0]);
        if (signal.dtr) {
            arg[0] |= TIOCM_DTR;
        }
        if (signal.rts) {
            arg[0] |= TIOCM_RTS;
        }
        (0, ioctl_1.default)(fd, TIOCMSET, arg);
    }
    async write(data) {
        const fd = await this.#getFd();
        let failCount = 0;
        while (data.length > 0) {
            try {
                const length = fs_1.default.writeSync(fd, data);
                data = data.slice(length);
            }
            catch (e) {
                if (e.code !== "EAGAIN") {
                    console.log("ERROR READ", e);
                    throw e;
                }
                if (failCount++ > 5) {
                    throw e;
                }
            }
            await (0, timer_js_1.stall)(3);
        }
        return true;
    }
    static discover(any) {
        if (any == null) {
            any = true;
        }
        const devs = fs_1.default.readdirSync("/dev").filter((dev) => {
            return dev.match(/^(cu|tty)\.(usbmodem)/);
        });
        if (devs.length === 1 || (devs.length && any)) {
            return new SerialPort((0, path_1.join)("/dev/", devs[0]));
        }
        if (devs.length) {
            throw new Error(`Found multiple devices: ${devs.join(", ")}`);
        }
        throw new Error("no device found");
    }
}
exports.SerialPort = SerialPort;
//# sourceMappingURL=serial-node.js.map