#!/usr/bin/env node

import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../serial-node.js";

const serial = SerialPort.discover(true);

(async function() {
    const device = new Device(serial, { });
    await device.connect();

    const deviceInfo = await device.getDeviceInfo();
    const macAddress = await device.getMacAddress();

    console.log("Device Info:");
    console.log(`  Model: ${ deviceInfo.modelName }`);
    console.log(`  MAC Address: ${ macAddress }`);
    console.log(`  Serial Number: ${ deviceInfo.serial }`);
})();
