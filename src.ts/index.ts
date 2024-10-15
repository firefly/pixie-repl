
export { version } from "./_version.js";

export { Device, Sequences } from "./device.js";
//export { Logger } from "./logger.js";
export { SerialPort } from "./serial.js";
export { slipEncode, slipDecode } from "./slip.js";

export { DeviceEsp32c3 } from "./device-esp32c3.js";

export {
    Header,
    Entry, ValueEntry, NamespaceEntry, BlobIndexEntry,BlobEntry,
    Page, EmptyPage,
    NVSData
} from "./nvs.js";


//export type { Printer } from "./logger.js";
export type {
    DeviceInfo, DeviceOptions
} from "./device.js";
export type { SlipDecodeResult } from "./slip.js";

export type {
    PageState, EntryState, EntryType, Value,
    NvsValueTypeJson, NvsValueJson, NvsBlobJson, NvsJson
} from "./nvs.js";
