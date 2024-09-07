#!/usr/bin/env node

import { DeviceEsp32c3 as Device } from "../device-esp32c3.js";
import { SerialPort } from "../node-specific.js";

const serial = new SerialPort("/dev/cu.usbmodem101");

(async function() {
    const device = new Device(serial);
    await device.connect();

    const deviceInfo = await device.getDeviceInfo();
    const macAddress = await device.getMacAddress();

    console.log("Device Info:");
    console.log(`  Model: ${ deviceInfo.modelName }`);
    console.log(`  MAC Address: ${ macAddress }`);
})().catch((error: Error) => {
    console.log("Error:", error.message);
    console.log(error);
});
