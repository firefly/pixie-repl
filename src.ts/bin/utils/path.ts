import { dirname, resolve as _resolve } from "path";

import { fileURLToPath } from 'url';


const __dirname = dirname(fileURLToPath(import.meta.url));

const root = _resolve(__dirname, "..");

// Resolves wrt to the src.ts folder
export function resolve(path: string): string {
    return _resolve(root, path);
}
