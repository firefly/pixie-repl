#!/usr/bin/env node

import { readFileSync } from "fs";

import { hexlify, toBeArray } from "ethers";

import { REPL } from "../provision/repl.js";
import { compress } from "../provision/image.js";

import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../serial-node.js";
import { NVSData } from "../nvs.js";
import { PartitionTable } from "../partition.js";
import { getBytes } from "../utils/data.js";
import { assert } from "../utils/errors.js";
import { resolve } from "./utils/path.js";
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

    let serial;
    if (process.argv[2]) {
       serial = new SerialPort(process.argv[2]);
    } else {
       serial = SerialPort.discover();
    }
    console.log(`Connected to ${ serial.name }:`);

    const device = new Device(serial);
    await device.connect();

    /////////////////////////
    //// ROM Boot

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

    console.log("Erasing attestation NVS partition...");
    await device.eraseFlash(0x009000, 0x7000);

    console.log("Flashing bootloader...");
    await device.writeFlashCompressed(0x0000, binBootloader);


    /////////////////////////
    //// Boot ROM => REPL

    // Flash REPL firmware to device
    console.log("Flashing Provision REPL firmware...");
    await device.writeFlashCompressed(0x10000, binRepl);

    // Reset device, booting REPL firmware
    const repl = new REPL(device);


    /////////////////////////
    //// REPL

    console.log("Generating on-device signing keypair...");
    const t0 = getTime();
    const genkey = await repl.generateKey();
    console.log(`  (finished in ${ (getTime() - t0) / 1000 }s)`);

    console.log("Requesting attestation from Provisioning Service...");
    const prov = await fetchProvision(genkey);
    console.log(`  (got S/N: ${ prov.serial })`);

    console.log(`Setting device info (model: 0x${ prov.model.toString(16) }, S/N: ${ prov.serial })...`);
    await repl.setProvisionData(prov);

    repl.logs.push(JSON.stringify(await repl._sendCommand("DUMP"), (key, value) => {
        if (value instanceof Uint8Array) {
            return hexlify(value);
        }
        return value;
    }));

    console.log("Burning attestation key...");
    await repl.burn();

    await stall(2000);

    console.log("Resetting...");
    await repl.reset();

    console.log("Verifying...");
    const verify = await repl.attest();
    assert(verify.serial === prov.serial, `verify failed; serial mismatch`, {
        expected: prov, got: verify
    });
    assert(verify.model === prov.model, `verify failed; model mismatch`, {
        expected: prov, got: verify
    });


    /////////////////////////
    //// ROM Boot

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

    //if (0) {
    console.log("Flashing factory firmware...");
    await device.writeFlashCompressed(0x10000, binFactory);
    //}

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
