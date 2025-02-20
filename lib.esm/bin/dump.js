#!/usr/bin/env node
import { readFileSync } from "fs";
import { REPL } from "../provision/repl.js";
import { compress } from "../provision/image.js";
import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../serial-node.js";
import { NVSData } from "../nvs.js";
import { resolve } from "./utils/path.js";
const binRepl = compress(readFileSync(resolve("../esp-app/provision/build/pixie-provision.bin")));
console.log(binRepl);
(async function () {
    console.log("");
    const serial = SerialPort.discover();
    console.log(`Connected to ${serial.name}:`);
    const device = new Device(serial);
    await device.connect();
    const info = await device.getDeviceInfo();
    console.log(`  - Chip: ${info.chip}`);
    // Check for existing provisioning data
    if (0) {
        try {
            const ptable = await device.readPartitionTable();
            console.log(ptable.summary());
            try {
                const attest = await device.readFlash(0x9000, 0x7000);
                const nvs = NVSData.fromBinary(attest);
                console.log(nvs.csv);
            }
            catch (e) { }
        }
        catch (e) { }
    }
    // Flash REPL firmware to device
    //console.log("Flashing Provision REPL firmware...");
    //await device.writeFlashCompressed(0x10000, binRepl);
    //console.log("  Done!");
    // Reset device, booting REPL firmware
    const repl = new REPL(device);
    //console.log(await repl.dump());
    console.log("Attesting...");
    const attest = await repl.attest();
    console.log(attest);
})().catch((e) => {
    if (e.simple) {
        console.log(e.message);
        console.log("");
    }
    else {
        console.log("ERROR:");
        console.log(e);
    }
});
//# sourceMappingURL=dump.js.map