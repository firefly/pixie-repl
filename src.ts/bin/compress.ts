import { readFileSync, writeFileSync } from "fs";
import { resolve } from "path";

import { sha256 } from "ethers";
import { deflate } from "pako";

import { concat, toLeBytes } from "../utils/data.js";


const args = process.argv.slice(2);
if (args.length < 1 || args.length > 2) {
    console.log("USAGE: compress INFILE [ OUTFILE ]");
    process.exit(1);
}

(async function(input: string, output?: string) {
    const data = readFileSync(resolve(input));
    const checksum = sha256(data);

    const result = concat([
        toLeBytes(0x7a62696e, 4),
        toLeBytes(data.length, 4),
        Buffer.from(checksum.substring(2), "hex"),
        deflate(data, { level: 9 })
    ]);

    console.log("Size:           ", data.length);
    console.log("Compressed Size:", result.length);
    console.log("Checksum:       ", checksum);

    if (output) {
        writeFileSync(output, result);
    } else {
        console.log("Base64:", Buffer.from(result).toString("base64"));
    }
})(args[0], args[1]);
