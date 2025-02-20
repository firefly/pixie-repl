"use strict";
/**
 *  This is copied (basically) verbatim from node-forge, with the
 *  necessary TypeScript-ification along the way. As such, the
 *  license used is passed along. ~RicMoo
 *
 *  New BSD License (3-clause)
 *  Copyright (c) 2010, Digital Bazaar, Inc.
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Digital Bazaar, Inc. nor the
 *        names of its contributors may be used to endorse or promote products
 *        derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL DIGITAL BAZAAR BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports._padding = exports.Md5 = void 0;
const data_js_1 = require("./data.js");
class ByteBuffer {
    _data;
    _read;
    get bytes() { return this._data.slice(this._read); }
    get length() { return this._data.length - this._read; }
    get read() { return this._read; }
    constructor() {
        this._data = new Uint8Array(0);
        this._read = 0;
    }
    putBytes(data) {
        this._data = (0, data_js_1.concat)([this._data, data]);
    }
    compact() {
        this._data = this.bytes;
        this._read = 0;
    }
    putInt32Le(value) {
        this.putBytes((0, data_js_1.toLeBytes)(value, 4));
    }
    getInt32Le() {
        this._read += 4;
        return (0, data_js_1.fromLeBytes)(this._data.slice(this._read - 4, this._read));
    }
}
class Md5 {
    // MD5 state contains four 32-bit integers
    _state;
    // input buffer
    _input;
    // used for word storage
    _w;
    algorithm = 'md5';
    blockLength = 64;
    digestLength = 16;
    // 56-bit length of message so far (does not including padding)
    messageLength;
    // true message length
    fullMessageLength;
    // size of message length in bytes
    messageLengthSize;
    constructor() {
        // up to 56-bit message length for convenience
        this.messageLength = 0;
        this.messageLengthSize = 8;
        // full message length (set md.messageLength64 for backwards-compatibility)
        this.fullMessageLength = [];
        const int32s = this.messageLengthSize / 4;
        for (let i = 0; i < int32s; ++i) {
            this.fullMessageLength.push(0);
        }
        this._input = new ByteBuffer();
        this._state = {
            h0: 0x67452301,
            h1: 0xEFCDAB89,
            h2: 0x98BADCFE,
            h3: 0x10325476
        };
        this._w = new Array(16);
    }
    /**
     * Updates the digest with the given message input. The given input can
     * treated as raw input (no encoding will be applied) or an encoding of
     * 'utf8' maybe given to encode the input using UTF-8.
     *
     * @param msg the message input to update with.
     * @param encoding the encoding to use (default: 'raw', other: 'utf8').
     *
     * @return this digest object.
     */
    update(msg) {
        // update message length
        const msgLen = msg.length;
        this.messageLength += msgLen;
        const len = [(msgLen / 0x100000000) >>> 0, msgLen >>> 0];
        for (let i = this.fullMessageLength.length - 1; i >= 0; --i) {
            this.fullMessageLength[i] += len[1];
            len[1] = len[0] + ((this.fullMessageLength[i] / 0x100000000) >>> 0);
            this.fullMessageLength[i] = this.fullMessageLength[i] >>> 0;
            len[0] = (len[1] / 0x100000000) >>> 0;
        }
        // add bytes to input buffer
        this._input.putBytes(msg);
        // process bytes
        _update(this._state, this._w, this._input);
        // compact input buffer every 2K or if empty
        if (this._input.read > 2048 || this._input.length === 0) {
            this._input.compact();
        }
        return this;
    }
    ;
    /**
       * Produces the digest.
       *
       * @return a byte buffer containing the digest value.
       */
    digest() {
        /* Note: Here we copy the remaining bytes in the input buffer and
        add the appropriate MD5 padding. Then we do the final update
        on a copy of the state so that if the user wants to get
        intermediate digests they can do so. */
        /* Determine the number of bytes that must be added to the message
        to ensure its length is congruent to 448 mod 512. In other words,
        the data to be digested must be a multiple of 512 bits (or 128 bytes).
        This data includes the message, some padding, and the length of the
        message. Since the length of the message will be encoded as 8 bytes (64
        bits), that means that the last segment of the data must have 56 bytes
        (448 bits) of message and padding. Therefore, the length of the message
        plus the padding must be congruent to 448 mod 512 because
        512 - 128 = 448.

        In order to fill up the message length it must be filled with
        padding that begins with 1 bit followed by all 0 bits. Padding
        must *always* be present, so if the message length is already
        congruent to 448 mod 512, then 512 padding bits must be added. */
        const finalBlock = new ByteBuffer();
        finalBlock.putBytes(this._input.bytes);
        // compute remaining size to be digested (include message length size)
        const remaining = (this.fullMessageLength[this.fullMessageLength.length - 1] +
            this.messageLengthSize);
        // add padding for overflow blockSize - overflow
        // _padding starts with 1 byte with first bit is set (byte value 128), then
        // there may be up to (blockSize - 1) other pad bytes
        const overflow = remaining & (this.blockLength - 1);
        finalBlock.putBytes(exports._padding.slice(0, this.blockLength - overflow));
        // serialize message length in bits in little-endian order; since length
        // is stored in bytes we multiply by 8 and add carry
        let bits, carry = 0;
        for (let i = this.fullMessageLength.length - 1; i >= 0; --i) {
            bits = this.fullMessageLength[i] * 8 + carry;
            carry = (bits / 0x100000000) >>> 0;
            finalBlock.putInt32Le(bits >>> 0);
        }
        const s2 = {
            h0: this._state.h0,
            h1: this._state.h1,
            h2: this._state.h2,
            h3: this._state.h3
        };
        _update(s2, this._w, finalBlock);
        const rval = new ByteBuffer();
        rval.putInt32Le(s2.h0);
        rval.putInt32Le(s2.h1);
        rval.putInt32Le(s2.h2);
        rval.putInt32Le(s2.h3);
        return rval.bytes;
    }
    ;
    static hash(data) {
        return (new Md5()).update(data).digest();
    }
}
exports.Md5 = Md5;
exports._padding = new Uint8Array(65);
exports._padding[0] = 128;
// g values
const _g = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9
];
// rounds table
const _r = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
];
// get the result of abs(sin(i + 1)) as a 32-bit integer
const _k = new Array(64);
for (let i = 0; i < 64; ++i) {
    _k[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 0x100000000);
}
/**
 * Updates an MD5 state with the given byte buffer.
 *
 * @param s the MD5 state to update.
 * @param w the array to use to store words.
 * @param bytes the byte buffer to update with.
 */
function _update(s, w, bytes) {
    // consume 512 bit (64 byte) chunks
    var t, a, b, c, d, f, r, i;
    var len = bytes.length;
    while (len >= 64) {
        // initialize hash value for this chunk
        a = s.h0;
        b = s.h1;
        c = s.h2;
        d = s.h3;
        // round 1
        for (i = 0; i < 16; ++i) {
            w[i] = bytes.getInt32Le();
            f = d ^ (b & (c ^ d));
            t = (a + f + _k[i] + w[i]);
            r = _r[i];
            a = d;
            d = c;
            c = b;
            b += (t << r) | (t >>> (32 - r));
        }
        // round 2
        for (; i < 32; ++i) {
            f = c ^ (d & (b ^ c));
            t = (a + f + _k[i] + w[_g[i]]);
            r = _r[i];
            a = d;
            d = c;
            c = b;
            b += (t << r) | (t >>> (32 - r));
        }
        // round 3
        for (; i < 48; ++i) {
            f = b ^ c ^ d;
            t = (a + f + _k[i] + w[_g[i]]);
            r = _r[i];
            a = d;
            d = c;
            c = b;
            b += (t << r) | (t >>> (32 - r));
        }
        // round 4
        for (; i < 64; ++i) {
            f = c ^ (b | ~d);
            t = (a + f + _k[i] + w[_g[i]]);
            r = _r[i];
            a = d;
            d = c;
            c = b;
            b += (t << r) | (t >>> (32 - r));
        }
        // update hash state
        s.h0 = (s.h0 + a) | 0;
        s.h1 = (s.h1 + b) | 0;
        s.h2 = (s.h2 + c) | 0;
        s.h3 = (s.h3 + d) | 0;
        len -= 64;
    }
}
/*
import { randomBytes } from "ethers";
const message = randomBytes(10240);// new Uint8Array([ 0x31, 0x32, 0x33, 0x34 ]);
{
  //const md5 = new Md5();
  console.log(Buffer.from(Md5.hash(message)).toString("hex"));
}
{
  const hasher = createHash("md5");
  hasher.update(message);
  console.log(Buffer.from(hasher.digest()).toString("hex"));
}
*/
//# sourceMappingURL=md5.js.map