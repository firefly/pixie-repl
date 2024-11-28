import {
    DeviceEsp32c3, SerialPortBrowser, NVSData
} from "../dist/pixie-repl.js"
import { clone } from "./ui.js";

const domContent = document.getElementById("content");

function stall(duration) {
    return new Promise((r) => { setTimeout(r, duration); });
}

function fromBase64(str) {
    const bytes = atob(str);
    const result = new Uint8Array(bytes.length);
    for (let i = 0; i < bytes.length; i++) {
        result[i] = bytes.charCodeAt(i);
    }
    return result;
}

import { pixie, probe, rroll } from "./bins.js";

function zpad(v, length) {
    while (v.length < length) { v = "0" + v; }
    return v;
}

function addr(v) { return zpad(v.toString(16), 7); }

function getHumanSize(v) {
    if (v < 1024) { return `${ v }b`; }
    if (v < 1024 * 1024) { return `${ (v / 1024).toFixed(1) }kb`;}
    return `${ (v / 1024 / 1024).toFixed(1) }Mb`;
}

function download(filename, data) {
    const a = document.createElement("a");
    const blob = new Blob([ data ]);
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { a.remove(); });
}

function setMutex(enable) {
    domContent.querySelectorAll(".mutex").forEach((e) => {
        if (enable) {
            e.classList.remove("disabled");
        } else {
            e.classList.add("disabled");
        }
    });
}

async function runAction(action, values) {
    console.log(action, values);

    await window.device.connect();

    if (values.table) {
        switch (action) {
            case "bin":
                download("partition.bin", values.table.binary.buffer);
                break;
            case "csv":
                download("partition.csv", values.table.csv);
                break;
            case "json":
                download("partition.json", JSON.stringify(values.table.json));
                break;
        }

    } else if (values.device) {
        const { device, name, offset, size } = values;
        const data = await device.readFlash(offset, size, (p) => console.log(p));
        if (action === "bin") {
            download(`${ name }.bin`, data);
        } else if (values.type === "data/nvs") {
            const nvs = NVSData.fromBinary(data);
            switch (action) {
                case "csv":
                    download(`${ name }.csv`, nvs.csv);
                    break;
                case "json":
                    download(`${ name }.json`, JSON.stringify(nvs.json));
                    break;
            }
        }
    }

    await window.device.reset();
}

function createActions(actions, values) {
    const div = document.createElement("div");
    div.classList.add("actions");
    actions.forEach(({ title, action }) => {
        const a = document.createElement("a");
        a.classList.add("link");
        a.classList.add("mutex");
        div.appendChild(a);
        a.innerText = title;
        a.onclick = function() {
            runAction(action, values);
        };
    });
    return div;
}

async function flash(device, name, progress) {
    console.log("FLASH", device, name);

    setMutex(false);
    await device.connect();

    const progressFunc = (percent) => {
        const left = Math.floor((percent * 82) / 100);
        progress.style.borderLeft = `${ left }px solid #ff8c00`;
        progress.style.borderRight = `${ 82 - left }px solid #9d549d`;
    };
    progressFunc(0);

    progress.classList.remove("hidden");

    if (name === "probe") {
        const bin = fromBase64(probe);
        await device.writeFlashCompressed(0x10000, bin, progressFunc);
    } else if (name === "ethcc") {
        const bin = fromBase64(pixie);
        await device.writeFlashCompressed(0x10000, bin, progressFunc);
    } else if (name === "rroll") {
        const bin = fromBase64(rroll);
        await device.writeFlashCompressed(0x10000, bin, progressFunc);
    }

    progress.classList.add("hidden");

    await device.reset();
    setMutex(true);
}

async function connect() {

    updateStatus(`Connecting to device over USB serial...`);
    const serialPort = await SerialPortBrowser.discover();
    const device = new DeviceEsp32c3(serialPort);
    await device.connect();
    window.device = device;

    updateStatus(`Fetching device info over USB serial...`);
    const deviceInfo = await device.getDeviceInfo();
    console.log("Device Info", deviceInfo);

    if (deviceInfo.version === 0) {
        updateStatus(`Device is unprovisioned. Please use the provisioned tool first.`);
        throw new Error("unprovisioned");
    }

    updateStatus(`Fetching device partition table over USB serial...`);
    const table = await device.readPartitionTable();
    console.log(table.summary());

    await device.reset();

    // Add the Device Info panel
    domContent.appendChild(clone("header", { name: "Device Info" }));
    const domInfo = clone("device-info", deviceInfo);
    domContent.appendChild(domInfo);

    // Add the Partition Table panel
    const domPtable = clone("ptable");;

    let offset = 0, size = 0x8000;
    //const hash = await device.verifyFlash(offset, size);
    domPtable.appendChild(clone("ptable-special-row", {
        range: `${ addr(offset) }:${ addr(offset + size - 1) }`,
        name: `[ BOOTLOADER ]`,
        size: getHumanSize(size),
        actions: createActions([
            { title: "bin", action: "bin" },
        ], { device, offset, size, name: "bootloader" })
    }));
    offset += size;

    size = 0x1000;
    domPtable.appendChild(clone("ptable-special-row", {
        range: `${ addr(offset) }:${ addr(offset + size - 1) }`,
        name: "[ PARTITION TABLE ]",
        size: getHumanSize(size),
        actions: createActions([
            { title: "bin", action: "bin" },
            { title: "csv", action: "csv" },
            { title: "json", action: "json" },
        ], { table })
    }));
    offset += size;

    for (const p of table.partitions) {
        const name = p.name;

        if (p.offset > offset) {
            domPtable.appendChild(clone("ptable-special-row", {
                range: `${ addr(offset) }:${ addr(p.offset - 1) }`,
                name: `[ UNUSED ]`,
                size: getHumanSize(p.offset - offset)
            }));
        }

        const actions = [ { title: "bin", action: "bin" } ];

        const type = `${ p.type }/${ p.subtype }`;
        if (type === "data/nvs") {
            actions.push({ title: "csv", action: "csv" });
            actions.push({ title: "json", action: "json" });
        }

        domPtable.appendChild(clone("ptable-row", {
            range: `${ addr(p.offset) }:${ addr(p.offset + p.size - 1) }`,
            name, type,
            size: getHumanSize(p.size),
            actions: createActions(actions, {
                device, name, type, offset: p.offset, size: p.size
            })
        }));
        offset = p.offset + p.size;
    }

    if (deviceInfo.flashSize > offset) {
        domPtable.appendChild(clone("ptable-special-row", {
            range: `${ addr(offset) }:${ addr(deviceInfo.flashSize - 1) }`,
            name: `[ UNUSED ]`,
            size: getHumanSize(deviceInfo.flashSize - offset)
        }));
    }

    domContent.appendChild(clone("header", { name: "Partition Table" }));
    domContent.appendChild(domPtable);
};

function startConnecting() {
    document.getElementById("box-connect").classList.add("connecting");
    document.getElementById("connect").classList.remove("hoverable");
    document.getElementById("connect").innerText = "connecting...";
    updateStatus("Searching for USB Serial...");
}

function updateStatus(status) {
    document.getElementById("connect-status").innerText = status;
}

function stopConnecting(success) {
    if (success) {
        document.getElementById("box-connect").classList.add("hidden");
        document.getElementById("content").appendChild(clone("header", { name: "Flash Firmware" }));
        document.getElementById("content").appendChild(clone("upload"));

        domContent.querySelectorAll(".flash").forEach((e) => {
            e.onclick = () => {
              flash(window.device, e.getAttribute("data-name"), e.querySelector(".progress"));
            };
        });

    } else {
        document.getElementById("box-connect").classList.remove("connecting");
        document.getElementById("connect").classList.add("hoverable");
        document.getElementById("connect").innerText = "Connect";
    }
}

//document.getElementById("connect").onclick = connect;
document.getElementById("connect").onclick = async () => {
    startConnecting();
    try {
        await connect();
        stopConnecting(true);
    } catch (error) {
        console.log(error);
        stopConnecting(false);
    }
};
