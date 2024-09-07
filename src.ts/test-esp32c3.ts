import { SerialPort } from "./node-specific.js";
import { DeviceEsp32c3 as Device } from "./device-esp32c3.js";
import { hexlify, randomBytes } from "ethers";
import {
    CMD_FFX_GENKEY, CMD_FFX_STIR
} from "./protocol.js";

const serial = SerialPort.discover();//new SerialPort("/dev/cu.usbmodem1101");

(async function() {
    const device = new Device(serial);
    await device.connect();

    //console.log("BEFORE STUB", await device.getDeviceInfo());
    const version = await device.enableStub();
    console.log({ version });
    console.log("Device Info", await device.getDeviceInfo());

    console.log("STIR", await device.command(CMD_FFX_STIR, randomBytes(32)));

    console.log("PUBKEY", hexlify(await device.command(CMD_FFX_GENKEY)));
})();
