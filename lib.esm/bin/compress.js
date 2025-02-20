#!/usr/bin/env node
import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";
import { compress } from "../provision/image.js";
const args = process.argv.slice(2);
if (args.length < 1 || args.length > 2) {
    console.log("USAGE: compress INFILE [ OUTFILE ]");
    process.exit(1);
}
(async function (input, output) {
    const data = readFileSync(resolve(input));
    const result = compress(data);
    console.log("Size:           ", data.length);
    console.log("Compressed Size:", result.length);
    if (output) {
        writeFileSync(output, result);
    }
    else {
        console.log("Base64:", Buffer.from(result).toString("base64"));
    }
})(args[0], args[1]);
//# sourceMappingURL=compress.js.map