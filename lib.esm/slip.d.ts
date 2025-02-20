/**
 *  Serial Line Internet Protocol (SLIP) coder library.
 *
 *  See: https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
 */
/**
 *  Encode %%data%% using SLIP encoding.
 */
export declare function slipEncode(data: Uint8Array): Uint8Array;
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
/**
 *  Decode %%data%% as SLIP encoded data, if valid SLIP-encoded data. Otherwise
 *  return ``null``.
 */
export declare function slipDecode(data: Uint8Array): null | SlipDecodeResult;
//# sourceMappingURL=slip.d.ts.map