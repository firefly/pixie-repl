#!/usr/bin/env node

import { readFileSync, writeFileSync } from "fs";

import { hexlify, toBeArray } from "ethers";

import { REPL } from "../provision/repl.js";
import { compress } from "../provision/image.js";

import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../serial-node.js";
import { NVSData } from "../nvs.js";
import { PartitionTable } from "../partition.js";
import { getBytes } from "../utils/data.js";
import { assert } from "../utils/errors.js";
import { resolve } from "../utils/path.js";
import { stall } from "../utils/timer.js";

import type { GenerateKeyResult, ProvisionData } from "../provision/repl.js";

const binBootloader = compress(readFileSync(resolve("../esp-app/provision/build/bootloader/bootloader.bin")));
const binFactory = compress(readFileSync(resolve("../../pixie-firmware/build/pixie.bin")));
const binRepl = compress(readFileSync(resolve("../esp-app/provision/build/pixie-provision.bin")));


function getTime(): number {
    return (new Date()).getTime();
}


async function fetchProvision(genkey: GenerateKeyResult): Promise<ProvisionData> {
    const url = `http:/\/localhost:8000/provision?pubkey=${ hexlify(genkey.pubkey) }&cipherdata=${ hexlify(genkey.cipherdata) }&marker=${ hexlify(toBeArray(genkey.marker)) }`;
    const resp = await fetch(url);
    const { attest, model, serial } = await resp.json();

    return { attest: getBytes(attest), model, serial };
}

const t0 = getTime();
(async function() {
    console.log("");

    const serial = SerialPort.discover();
    console.log(`Connected to ${ serial.name }:`);

    const device = new Device(serial);
    await device.connect();

    const info = await device.getDeviceInfo();
    console.log(`  - Chip: ${ info.chip }`);

    assert(info.version === 0, `Already provisioned: ${ info.modelName } (S/N: ${ info.serial })`, {
        simple: true,
        info
    });

    // Check for existing provisioning data
    try {
        await device.readPartitionTable();
        console.log("  - Partition table exists (previous provision failed?)");

        try {
            const attest = await device.readFlash(0x9000, 0x7000);
            //const nvs = 
            NVSData.fromBinary(attest);
            console.log("  - Attestation data exists (previous provision failed?)");
        } catch (e) { }
    } catch (e) { }


    console.log("Flashing partition table (mutable attest NVS)...");
    {
        const table = new PartitionTable(16 * 1024 * 1024);
        table.addPartition("attest", "data", "nvs", 0x009000, 0x7000, false);
        table.addPartition("factory", "app", "factory", 0x0010000, 0x700000, false);
        table.addPartition("nvs", "data", "nvs", 0x0f00000, 0x100000, false);
        await device.writeFlash(0x8000, table.binary);
    }
    console.log("  Done!");

    console.log("Erasing attestation NVS partition...");
    await device.eraseFlash(0x009000, 0x7000);
    console.log("  Done!");

    console.log("Flashing bootloader...");
    await device.writeFlashCompressed(0x0000, binBootloader);
    console.log("  Done!");


    // Flash REPL firmware to device
    console.log("Flashing Provision REPL firmware...");
    await device.writeFlashCompressed(0x10000, binRepl);
    console.log("  Done!");

    // Reset device, booting REPL firmware
    const repl = new REPL(device);

    console.log("Generating on-device signing keypair...");
    const t0 = getTime();
    const genkey = await repl.generateKey();
    console.log(`  Done! (took ${ (getTime() - t0) / 1000 }s)`);

    console.log("Requesting attestestion from Provisioning Service...");
    const prov = await fetchProvision(genkey);
    console.log(`  Done! (S/N: ${ prov.serial })`);

    console.log(`Setting device info (model: 0x${ prov.model.toString(16) }, S/N: ${ prov.serial })...`);
    await repl.setProvisionData(prov);
    console.log("  Done!");

    repl.logs.push(JSON.stringify(await repl._sendCommand("DUMP"), (key, value) => {
        if (value instanceof Uint8Array) {
            return hexlify(value);
        }
        return value;
    }));

    console.log("Burning attestaion key...");
    await repl.burn();
    console.log("  Done!");

    {
        const time = getTime();
        const path = `/Users/ricmoo/Downloads/provision-logs/log-${ prov.model }-${ prov.serial }-${ time }`;
        writeFileSync(path, JSON.stringify({
            logs: repl.logs, genkey, prov, time
        }, (key, value) => {
            if (value instanceof Uint8Array) {
                return hexlify(value);
            }
            return value;
        }));
    }


    // Reset device into boot mode
    await device.connect();

    console.log("Replacing partition table (read-only attest NVS)...");
    {
        const table = new PartitionTable(16 * 1024 * 1024);
        table.addPartition("attest", "data", "nvs", 0x009000, 0x7000, true);
        table.addPartition("factory", "app", "factory", 0x0010000, 0x700000, false);
        table.addPartition("nvs", "data", "nvs", 0x0f00000, 0x100000, false);
        await device.writeFlash(0x8000, table.binary);
    }
    console.log("  Done!");

    console.log("Flashing factory firmware...");
    await device.writeFlashCompressed(0x10000, binFactory);
    console.log("  Done!");

    await stall(100);

    await device.reset();

    return prov.serial;

})().then((serial) => {
    console.log("");
    console.log(`Provision Complete! (took ${ (getTime() - t0) / 1000 }s)`);
    console.log("");
}, (e) => {
    if (e.simple) {
        console.log(e.message);
        console.log("");
    } else {
        console.log("ERROR:");
        console.log(e);
    }
});
