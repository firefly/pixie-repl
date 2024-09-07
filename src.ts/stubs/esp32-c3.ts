import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { readFileSync } from "node:fs";

import type { Stub as _Stub } from "./stub.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

const path = resolve(__dirname, "../../stub/build/stub_flasher.json");

const { text, text_start, data, data_start, entry } = JSON.parse(readFileSync(path).toString());

export const Stub: _Stub = { text, text_start, data, data_start, entry };
