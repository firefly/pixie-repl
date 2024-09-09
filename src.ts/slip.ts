import { concat, hexlify } from "./utils.js";

/**
 *  Serial Line Internet Protocol (SLIP) coder library.
 *
 *  See: https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
 */

/**
 *  Encode %%data%% using SLIP encoding.
 */
export function slipEncode(data: Uint8Array): Uint8Array {
    let stuffBytes = 0;
    for (let i = 0; i < data.length; i++) {
        let c = data[i];
        if (c === 0xdb || c === 0xc0) { stuffBytes++; }
    }

    const slipData = new Uint8Array(2 + stuffBytes + data.length);

    let offset = 0;
    slipData[offset++] = 0xc0;

    for (let i = 0; i < data.length; i++) {
        let c = data[i];
        if (c === 0xdb) {
            slipData[offset++] = 0xdb;
            slipData[offset++] = 0xdd;
        } else if (c === 0xc0) {
            slipData[offset++] = 0xdb;
            slipData[offset++] = 0xdc;
        } else {
            slipData[offset++] = c;
        }
    }

    slipData[offset++] = 0xc0;

    return slipData;
}

/**
 *  The result of the decoded SLIP data, including how many bytes were
 *  skipped to find the start of the SLIP Packet.
 */
export type SlipDecodeResult = {
    data: Uint8Array;
    remaining: Uint8Array;
} | {
    debug: string;
    remaining: Uint8Array;
};

/*
export function slipCheckDebug(data: Uint8Array): null | SlipDecodeResult {
    const markers = [ ];
    for (let i = 0; i < data.length; i++) {
        if (data[i] === 0xc0) { markers.push(i); }
        if (markers.length >= 2) { break; }
    }
    if (markers.length === 2 && markers[1] - markers[0] === 1) {
        if (data.length < markers[1] + 1) { return null; }
        const length = data[markers[1] + 1];
        if (data.length < markers[1] + length) { return null; }
        return {
           start: markers[1] + 1,
           data: data.slice(markers[1] + 2, markers[1] + 2 + length),
           consumed: markers[1] + 2 + length
        }
    }

    return null;
}
*/

function findDebug(data: Uint8Array, start: number): number {
    for (let i = start; i < data.length - 2; i++) {
        if (hexlify(data.slice(i, i + 3)) === "c0c0c0") {
            return i;
        }
    }
    return -1;
}

const _TextDecoder = new TextDecoder();

/*
function _debugDecode(data: Uint8Array, offset: number): null | SlipDecodeResult {
    if (data.length < offset + 4) { return null; }

    const length = data[offset + 3];

    // Not all debug bytes are present yet
    if (data.length < offset + 4 + length) { return null; }

    return {
        debug: _TextDecoder.decode(data.slice(offset + 4, offset + 4 + length)),
        remaining: concat([ data.slice(0, offset), data.slice(offset + 4 + length) ])
    }
}
*/

function _slipDecode(data: Uint8Array): null | SlipDecodeResult {
    const markers = [ ];
    for (let i = 0; i < data.length; i++) {
        if (data[i] === 0xc0) { markers.push(i); }
        if (markers.length < 2) { continue; }

        const result: Array<number> = [ ];

        for (let i = markers[0] + 1; i < markers[1]; i++) {
            if (data[i] === 0xdb) {
                if (data[i + 1] === 0xdc) {
                    result.push(0xc0);
                    i++;
                    continue;
                } else if (data[i + 1] === 0xdd) {
                    result.push(0xdb);
                    i++;
                    continue;
                }
            }
            result.push(data[i]);
        }

        return {
            data: new Uint8Array(result),
            remaining: data.slice(markers[1] + 1)
        }
    }

    return null;
}

/**
 *  Decode %%data%% as SLIP encoded data, if valid SLIP-encoded data. Otherwise
 *  return ``null``.
 */
export function slipDecode(data: Uint8Array): null | SlipDecodeResult {
    const debug = findDebug(data, 0);
    if (debug === -1) { return _slipDecode(data); }

    const slip = _slipDecode(data.slice(0, debug));
    if (slip) { return slip; }

    const debugEnd = findDebug(data, debug + 3);
    if (debug === -1) { return null; }

    return {
        debug: _TextDecoder.decode(data.slice(debug + 4, debugEnd)),
        remaining: concat([ data.slice(0, debug), data.slice(debugEnd + 3) ])
    };
}
