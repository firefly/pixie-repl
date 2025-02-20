import { getBytes, sha256 } from "ethers";
import { deflate } from "pako";
import { concat, toLeBytes } from "../utils/data.js";
// zbin
export const Magic = 0x7a62696e;
export function compress(data) {
    return concat([
        toLeBytes(Magic, 4),
        toLeBytes(data.length, 4),
        getBytes(sha256(data)),
        deflate(data, { level: 9 })
    ]);
}
//# sourceMappingURL=image.js.map