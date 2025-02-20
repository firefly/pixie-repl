"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const serial_node_js_1 = require("../serial-node.js");
const device_esp32c3_js_1 = require("../device-esp32c3.js");
const serial = serial_node_js_1.SerialPort.discover(); //new SerialPort("/dev/cu.usbmodem1101");
//import { sha256 } from "ethers";
const bin = fs_1.default.readFileSync("../../pixie-firmware/build/pixie.bin");
console.log({ bin });
(async function () {
    const device = new device_esp32c3_js_1.DeviceEsp32c3(serial);
    await device.connect();
    //console.log("BEFORE STUB", await device.getDeviceInfo());
    //const version = await device.enableStub();
    //console.log({ version });
    console.log("Device Info", await device.getDeviceInfo());
    //await device.flash(0x010000, bin);
    //console.log(await device.verifyFlash(0x010000, bin.length));
    //console.log("HASH", sha256(bin));
    //const flash = Buffer.from(await device.readFlash(0x010000, bin.length));
    //console.log("BIN  ", flash.toString("hex"));
    //console.log("FLASH", flash.toString("hex"));
    //console.log(flash.toString("hex") === bin.toString("hex"));
    //console.log("WRITE", await device.writeFlash(0x010000, bin, true));
    //console.log(await device.verifyFlash(0, 16 * (1 << 20)));
    console.log((await device.readPartitionTable()).summary());
    //console.log("GENKEY", await device.genkey());
})();
//# sourceMappingURL=test-esp32c3.js.map