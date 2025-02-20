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
declare class ByteBuffer {
    _data: Uint8Array;
    _read: number;
    get bytes(): Uint8Array;
    get length(): number;
    get read(): number;
    constructor();
    putBytes(data: Uint8Array): void;
    compact(): void;
    putInt32Le(value: number): void;
    getInt32Le(): number;
}
export declare class Md5 {
    readonly _state: Record<string, number>;
    readonly _input: ByteBuffer;
    readonly _w: Array<number>;
    readonly algorithm = "md5";
    readonly blockLength = 64;
    readonly digestLength = 16;
    messageLength: number;
    fullMessageLength: Array<number>;
    messageLengthSize: number;
    constructor();
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
    update(msg: Uint8Array): Md5;
    /**
       * Produces the digest.
       *
       * @return a byte buffer containing the digest value.
       */
    digest(): Uint8Array;
    static hash(data: Uint8Array): Uint8Array;
}
export declare const _padding: Uint8Array;
export {};
//# sourceMappingURL=md5.d.ts.map