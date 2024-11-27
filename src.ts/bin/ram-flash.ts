#!/usr/bin/env node

import { readFileSync } from "fs";

import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../serial-node.js";

import { stall } from "../utils/timer.js";

const argv = process.argv.slice(2);
if (argv.length === 0) {
    console.log("USAGE: node ram-flash JSON [ PORT ]");
    process.exit(1);
}

const binJson = JSON.parse(readFileSync(argv[0]).toString());

(async function() {
    console.log("");

    let serial;
    if (argv[1]) {
       serial = new SerialPort(argv[1]);
    } else {
       serial = SerialPort.discover();
    }
    console.log(`Connected to ${ serial.name }:`);

    const device = new Device(serial);
    await device.connect();

    await device.run(binJson);

    // Run a serial monitor
    // @TODO: return something more useful for interacting, stopping, etc.
    while (true) {
        const data = await device._read();
        if (data.length) {
            for (let i = 0; i < data.length; i += 16) {
                const line = [ ];
                const chrs = [ ];

                for (let j = i; j < i + 16; j++) {
                    if (data[j] == null) {
                        line.push("  ");
                        chrs.push(" ");
                        if ((j % 2) == 1) { line.push(" "); }
                        continue;
                    }

                    if (data[j] >= 32 && data[j] < 127) {
                        chrs.push(String.fromCharCode(data[j]));
                    } else {
                        chrs.push(".");
                    }

                    let v = data[j].toString(16)
                    while (v.length < 2) { v = "0" + v; }
                    line.push(v);

                    if ((j % 2) == 1) { line.push(" "); }
                }

                line.push(` ${ chrs.join("") }`);
                console.log(line.join(""));
            }

        }
        await stall(100);
    }

})().catch((e: any) => {
    console.log(e.message);
    console.log("");
});
