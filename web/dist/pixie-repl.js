const version$1 = "0.1.1-beta.0";

/* Do NOT modify this file; see /src.ts/_admin/update-version.ts */
/**
 *  The current version of Ethers.
 */
const version = "6.13.2";

/**
 *  Property helper functions.
 *
 *  @_subsection api/utils:Properties  [about-properties]
 */
/**
 *  Assigns the %%values%% to %%target%% as read-only values.
 *
 *  It %%types%% is specified, the values are checked.
 */
function defineProperties(target, values, types) {
    for (let key in values) {
        let value = values[key];
        Object.defineProperty(target, key, { enumerable: true, value, writable: false });
    }
}

/**
 *  All errors in ethers include properties to ensure they are both
 *  human-readable (i.e. ``.message``) and machine-readable (i.e. ``.code``).
 *
 *  The [[isError]] function can be used to check the error ``code`` and
 *  provide a type guard for the properties present on that error interface.
 *
 *  @_section: api/utils/errors:Errors  [about-errors]
 */
function stringify(value) {
    if (value == null) {
        return "null";
    }
    if (Array.isArray(value)) {
        return "[ " + (value.map(stringify)).join(", ") + " ]";
    }
    if (value instanceof Uint8Array) {
        const HEX = "0123456789abcdef";
        let result = "0x";
        for (let i = 0; i < value.length; i++) {
            result += HEX[value[i] >> 4];
            result += HEX[value[i] & 0xf];
        }
        return result;
    }
    if (typeof (value) === "object" && typeof (value.toJSON) === "function") {
        return stringify(value.toJSON());
    }
    switch (typeof (value)) {
        case "boolean":
        case "symbol":
            return value.toString();
        case "bigint":
            return BigInt(value).toString();
        case "number":
            return (value).toString();
        case "string":
            return JSON.stringify(value);
        case "object": {
            const keys = Object.keys(value);
            keys.sort();
            return "{ " + keys.map((k) => `${stringify(k)}: ${stringify(value[k])}`).join(", ") + " }";
        }
    }
    return `[ COULD NOT SERIALIZE ]`;
}
/**
 *  Returns a new Error configured to the format ethers emits errors, with
 *  the %%message%%, [[api:ErrorCode]] %%code%% and additional properties
 *  for the corresponding EthersError.
 *
 *  Each error in ethers includes the version of ethers, a
 *  machine-readable [[ErrorCode]], and depending on %%code%%, additional
 *  required properties. The error message will also include the %%message%%,
 *  ethers version, %%code%% and all additional properties, serialized.
 */
function makeError(message, code, info) {
    let shortMessage = message;
    {
        const details = [];
        if (info) {
            if ("message" in info || "code" in info || "name" in info) {
                throw new Error(`value will overwrite populated values: ${stringify(info)}`);
            }
            for (const key in info) {
                if (key === "shortMessage") {
                    continue;
                }
                const value = (info[key]);
                //                try {
                details.push(key + "=" + stringify(value));
                //                } catch (error: any) {
                //                console.log("MMM", error.message);
                //                    details.push(key + "=[could not serialize object]");
                //                }
            }
        }
        details.push(`code=${code}`);
        details.push(`version=${version}`);
        if (details.length) {
            message += " (" + details.join(", ") + ")";
        }
    }
    let error;
    switch (code) {
        case "INVALID_ARGUMENT":
            error = new TypeError(message);
            break;
        case "NUMERIC_FAULT":
        case "BUFFER_OVERRUN":
            error = new RangeError(message);
            break;
        default:
            error = new Error(message);
    }
    defineProperties(error, { code });
    if (info) {
        Object.assign(error, info);
    }
    if (error.shortMessage == null) {
        defineProperties(error, { shortMessage });
    }
    return error;
}
/**
 *  Throws an EthersError with %%message%%, %%code%% and additional error
 *  %%info%% when %%check%% is falsish..
 *
 *  @see [[api:makeError]]
 */
function assert$1(check, message, code, info) {
    if (!check) {
        throw makeError(message, code, info);
    }
}
/**
 *  A simple helper to simply ensuring provided arguments match expected
 *  constraints, throwing if not.
 *
 *  In TypeScript environments, the %%check%% has been asserted true, so
 *  any further code does not need additional compile-time checks.
 */
function assertArgument(check, message, name, value) {
    assert$1(check, message, "INVALID_ARGUMENT", { argument: name, value: value });
}
["NFD", "NFC", "NFKD", "NFKC"].reduce((accum, form) => {
    try {
        // General test for normalize
        /* c8 ignore start */
        if ("test".normalize(form) !== "test") {
            throw new Error("bad");
        }
        ;
        /* c8 ignore stop */
        if (form === "NFD") {
            const check = String.fromCharCode(0xe9).normalize("NFD");
            const expected = String.fromCharCode(0x65, 0x0301);
            /* c8 ignore start */
            if (check !== expected) {
                throw new Error("broken");
            }
            /* c8 ignore stop */
        }
        accum.push(form);
    }
    catch (error) { }
    return accum;
}, []);

/**
 *  Some data helpers.
 *
 *
 *  @_subsection api/utils:Data Helpers  [about-data]
 */
function _getBytes(value, name, copy) {
    if (value instanceof Uint8Array) {
        return value;
    }
    if (typeof (value) === "string" && value.match(/^0x(?:[0-9a-f][0-9a-f])*$/i)) {
        const result = new Uint8Array((value.length - 2) / 2);
        let offset = 2;
        for (let i = 0; i < result.length; i++) {
            result[i] = parseInt(value.substring(offset, offset + 2), 16);
            offset += 2;
        }
        return result;
    }
    assertArgument(false, "invalid BytesLike value", name || "value", value);
}
/**
 *  Get a typed Uint8Array for %%value%%. If already a Uint8Array
 *  the original %%value%% is returned; if a copy is required use
 *  [[getBytesCopy]].
 *
 *  @see: getBytesCopy
 */
function getBytes(value, name) {
    return _getBytes(value, name);
}
const HexCharacters = "0123456789abcdef";
/**
 *  Returns a [[DataHexString]] representation of %%data%%.
 */
function hexlify$1(data) {
    const bytes = getBytes(data);
    let result = "0x";
    for (let i = 0; i < bytes.length; i++) {
        const v = bytes[i];
        result += HexCharacters[(v & 0xf0) >> 4] + HexCharacters[v & 0x0f];
    }
    return result;
}

// utils/base64-browser
function decodeBase64(textData) {
    textData = atob(textData);
    const data = new Uint8Array(textData.length);
    for (let i = 0; i < textData.length; i++) {
        data[i] = textData.charCodeAt(i);
    }
    return getBytes(data);
}

function bytes(b, ...lengths) {
    if (!(b instanceof Uint8Array))
        throw new Error('Expected Uint8Array');
    if (lengths.length > 0 && !lengths.includes(b.length))
        throw new Error(`Expected Uint8Array of length ${lengths}, not of length=${b.length}`);
}
function exists(instance, checkFinished = true) {
    if (instance.destroyed)
        throw new Error('Hash instance has been destroyed');
    if (checkFinished && instance.finished)
        throw new Error('Hash#digest() has already been called');
}
function output(out, instance) {
    bytes(out);
    const min = instance.outputLen;
    if (out.length < min) {
        throw new Error(`digestInto() expects output buffer of length at least ${min}`);
    }
}

/*! noble-hashes - MIT License (c) 2022 Paul Miller (paulmillr.com) */
// We use WebCrypto aka globalThis.crypto, which exists in browsers and node.js 16+.
// node.js versions earlier than v19 don't declare it in global scope.
// For node.js, package.json#exports field mapping rewrites import
// from `crypto` to `cryptoNode`, which imports native module.
// Makes the utils un-importable in browsers without a bundler.
// Once node.js 18 is deprecated, we can just drop the import.
const u8a = (a) => a instanceof Uint8Array;
// Cast array to view
const createView = (arr) => new DataView(arr.buffer, arr.byteOffset, arr.byteLength);
// The rotate right (circular right shift) operation for uint32
const rotr = (word, shift) => (word << (32 - shift)) | (word >>> shift);
// big-endian hardware is rare. Just in case someone still decides to run hashes:
// early-throw an error because we don't support BE yet.
const isLE = new Uint8Array(new Uint32Array([0x11223344]).buffer)[0] === 0x44;
if (!isLE)
    throw new Error('Non little-endian hardware is not supported');
/**
 * @example utf8ToBytes('abc') // new Uint8Array([97, 98, 99])
 */
function utf8ToBytes(str) {
    if (typeof str !== 'string')
        throw new Error(`utf8ToBytes expected string, got ${typeof str}`);
    return new Uint8Array(new TextEncoder().encode(str)); // https://bugzil.la/1681809
}
/**
 * Normalizes (non-hex) string or Uint8Array to Uint8Array.
 * Warning: when Uint8Array is passed, it would NOT get copied.
 * Keep in mind for future mutable operations.
 */
function toBytes(data) {
    if (typeof data === 'string')
        data = utf8ToBytes(data);
    if (!u8a(data))
        throw new Error(`expected Uint8Array, got ${typeof data}`);
    return data;
}
// For runtime check if class implements interface
class Hash {
    // Safe version that clones internal state
    clone() {
        return this._cloneInto();
    }
}
function wrapConstructor(hashCons) {
    const hashC = (msg) => hashCons().update(toBytes(msg)).digest();
    const tmp = hashCons();
    hashC.outputLen = tmp.outputLen;
    hashC.blockLen = tmp.blockLen;
    hashC.create = () => hashCons();
    return hashC;
}

// Polyfill for Safari 14
function setBigUint64(view, byteOffset, value, isLE) {
    if (typeof view.setBigUint64 === 'function')
        return view.setBigUint64(byteOffset, value, isLE);
    const _32n = BigInt(32);
    const _u32_max = BigInt(0xffffffff);
    const wh = Number((value >> _32n) & _u32_max);
    const wl = Number(value & _u32_max);
    const h = isLE ? 4 : 0;
    const l = isLE ? 0 : 4;
    view.setUint32(byteOffset + h, wh, isLE);
    view.setUint32(byteOffset + l, wl, isLE);
}
// Base SHA2 class (RFC 6234)
class SHA2 extends Hash {
    constructor(blockLen, outputLen, padOffset, isLE) {
        super();
        this.blockLen = blockLen;
        this.outputLen = outputLen;
        this.padOffset = padOffset;
        this.isLE = isLE;
        this.finished = false;
        this.length = 0;
        this.pos = 0;
        this.destroyed = false;
        this.buffer = new Uint8Array(blockLen);
        this.view = createView(this.buffer);
    }
    update(data) {
        exists(this);
        const { view, buffer, blockLen } = this;
        data = toBytes(data);
        const len = data.length;
        for (let pos = 0; pos < len;) {
            const take = Math.min(blockLen - this.pos, len - pos);
            // Fast path: we have at least one block in input, cast it to view and process
            if (take === blockLen) {
                const dataView = createView(data);
                for (; blockLen <= len - pos; pos += blockLen)
                    this.process(dataView, pos);
                continue;
            }
            buffer.set(data.subarray(pos, pos + take), this.pos);
            this.pos += take;
            pos += take;
            if (this.pos === blockLen) {
                this.process(view, 0);
                this.pos = 0;
            }
        }
        this.length += data.length;
        this.roundClean();
        return this;
    }
    digestInto(out) {
        exists(this);
        output(out, this);
        this.finished = true;
        // Padding
        // We can avoid allocation of buffer for padding completely if it
        // was previously not allocated here. But it won't change performance.
        const { buffer, view, blockLen, isLE } = this;
        let { pos } = this;
        // append the bit '1' to the message
        buffer[pos++] = 0b10000000;
        this.buffer.subarray(pos).fill(0);
        // we have less than padOffset left in buffer, so we cannot put length in current block, need process it and pad again
        if (this.padOffset > blockLen - pos) {
            this.process(view, 0);
            pos = 0;
        }
        // Pad until full block byte with zeros
        for (let i = pos; i < blockLen; i++)
            buffer[i] = 0;
        // Note: sha512 requires length to be 128bit integer, but length in JS will overflow before that
        // You need to write around 2 exabytes (u64_max / 8 / (1024**6)) for this to happen.
        // So we just write lowest 64 bits of that value.
        setBigUint64(view, blockLen - 8, BigInt(this.length * 8), isLE);
        this.process(view, 0);
        const oview = createView(out);
        const len = this.outputLen;
        // NOTE: we do division by 4 later, which should be fused in single op with modulo by JIT
        if (len % 4)
            throw new Error('_sha2: outputLen should be aligned to 32bit');
        const outLen = len / 4;
        const state = this.get();
        if (outLen > state.length)
            throw new Error('_sha2: outputLen bigger than state');
        for (let i = 0; i < outLen; i++)
            oview.setUint32(4 * i, state[i], isLE);
    }
    digest() {
        const { buffer, outputLen } = this;
        this.digestInto(buffer);
        const res = buffer.slice(0, outputLen);
        this.destroy();
        return res;
    }
    _cloneInto(to) {
        to || (to = new this.constructor());
        to.set(...this.get());
        const { blockLen, buffer, length, finished, destroyed, pos } = this;
        to.length = length;
        to.pos = pos;
        to.finished = finished;
        to.destroyed = destroyed;
        if (length % blockLen)
            to.buffer.set(buffer);
        return to;
    }
}

// SHA2-256 need to try 2^128 hashes to execute birthday attack.
// BTC network is doing 2^67 hashes/sec as per early 2023.
// Choice: a ? b : c
const Chi = (a, b, c) => (a & b) ^ (~a & c);
// Majority function, true if any two inpust is true
const Maj = (a, b, c) => (a & b) ^ (a & c) ^ (b & c);
// Round constants:
// first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
// prettier-ignore
const SHA256_K = /* @__PURE__ */ new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);
// Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
// prettier-ignore
const IV = /* @__PURE__ */ new Uint32Array([
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]);
// Temporary buffer, not used to store anything between runs
// Named this way because it matches specification.
const SHA256_W = /* @__PURE__ */ new Uint32Array(64);
class SHA256 extends SHA2 {
    constructor() {
        super(64, 32, 8, false);
        // We cannot use array here since array allows indexing by variable
        // which means optimizer/compiler cannot use registers.
        this.A = IV[0] | 0;
        this.B = IV[1] | 0;
        this.C = IV[2] | 0;
        this.D = IV[3] | 0;
        this.E = IV[4] | 0;
        this.F = IV[5] | 0;
        this.G = IV[6] | 0;
        this.H = IV[7] | 0;
    }
    get() {
        const { A, B, C, D, E, F, G, H } = this;
        return [A, B, C, D, E, F, G, H];
    }
    // prettier-ignore
    set(A, B, C, D, E, F, G, H) {
        this.A = A | 0;
        this.B = B | 0;
        this.C = C | 0;
        this.D = D | 0;
        this.E = E | 0;
        this.F = F | 0;
        this.G = G | 0;
        this.H = H | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 48 words w[16..63] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4)
            SHA256_W[i] = view.getUint32(offset, false);
        for (let i = 16; i < 64; i++) {
            const W15 = SHA256_W[i - 15];
            const W2 = SHA256_W[i - 2];
            const s0 = rotr(W15, 7) ^ rotr(W15, 18) ^ (W15 >>> 3);
            const s1 = rotr(W2, 17) ^ rotr(W2, 19) ^ (W2 >>> 10);
            SHA256_W[i] = (s1 + SHA256_W[i - 7] + s0 + SHA256_W[i - 16]) | 0;
        }
        // Compression function main loop, 64 rounds
        let { A, B, C, D, E, F, G, H } = this;
        for (let i = 0; i < 64; i++) {
            const sigma1 = rotr(E, 6) ^ rotr(E, 11) ^ rotr(E, 25);
            const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const sigma0 = rotr(A, 2) ^ rotr(A, 13) ^ rotr(A, 22);
            const T2 = (sigma0 + Maj(A, B, C)) | 0;
            H = G;
            G = F;
            F = E;
            E = (D + T1) | 0;
            D = C;
            C = B;
            B = A;
            A = (T1 + T2) | 0;
        }
        // Add the compressed chunk to the current hash value
        A = (A + this.A) | 0;
        B = (B + this.B) | 0;
        C = (C + this.C) | 0;
        D = (D + this.D) | 0;
        E = (E + this.E) | 0;
        F = (F + this.F) | 0;
        G = (G + this.G) | 0;
        H = (H + this.H) | 0;
        this.set(A, B, C, D, E, F, G, H);
    }
    roundClean() {
        SHA256_W.fill(0);
    }
    destroy() {
        this.set(0, 0, 0, 0, 0, 0, 0, 0);
        this.buffer.fill(0);
    }
}
/**
 * SHA2-256 hash function
 * @param message - data that would be hashed
 */
const sha256$1 = /* @__PURE__ */ wrapConstructor(() => new SHA256());

const U32_MASK64 = /* @__PURE__ */ BigInt(2 ** 32 - 1);
const _32n = /* @__PURE__ */ BigInt(32);
// We are not using BigUint64Array, because they are extremely slow as per 2022
function fromBig(n, le = false) {
    if (le)
        return { h: Number(n & U32_MASK64), l: Number((n >> _32n) & U32_MASK64) };
    return { h: Number((n >> _32n) & U32_MASK64) | 0, l: Number(n & U32_MASK64) | 0 };
}
function split(lst, le = false) {
    let Ah = new Uint32Array(lst.length);
    let Al = new Uint32Array(lst.length);
    for (let i = 0; i < lst.length; i++) {
        const { h, l } = fromBig(lst[i], le);
        [Ah[i], Al[i]] = [h, l];
    }
    return [Ah, Al];
}
const toBig = (h, l) => (BigInt(h >>> 0) << _32n) | BigInt(l >>> 0);
// for Shift in [0, 32)
const shrSH = (h, _l, s) => h >>> s;
const shrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in [1, 32)
const rotrSH = (h, l, s) => (h >>> s) | (l << (32 - s));
const rotrSL = (h, l, s) => (h << (32 - s)) | (l >>> s);
// Right rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotrBH = (h, l, s) => (h << (64 - s)) | (l >>> (s - 32));
const rotrBL = (h, l, s) => (h >>> (s - 32)) | (l << (64 - s));
// Right rotate for shift===32 (just swaps l&h)
const rotr32H = (_h, l) => l;
const rotr32L = (h, _l) => h;
// Left rotate for Shift in [1, 32)
const rotlSH = (h, l, s) => (h << s) | (l >>> (32 - s));
const rotlSL = (h, l, s) => (l << s) | (h >>> (32 - s));
// Left rotate for Shift in (32, 64), NOTE: 32 is special case.
const rotlBH = (h, l, s) => (l << (s - 32)) | (h >>> (64 - s));
const rotlBL = (h, l, s) => (h << (s - 32)) | (l >>> (64 - s));
// JS uses 32-bit signed integers for bitwise operations which means we cannot
// simple take carry out of low bit sum by shift, we need to use division.
function add(Ah, Al, Bh, Bl) {
    const l = (Al >>> 0) + (Bl >>> 0);
    return { h: (Ah + Bh + ((l / 2 ** 32) | 0)) | 0, l: l | 0 };
}
// Addition with more than 2 elements
const add3L = (Al, Bl, Cl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0);
const add3H = (low, Ah, Bh, Ch) => (Ah + Bh + Ch + ((low / 2 ** 32) | 0)) | 0;
const add4L = (Al, Bl, Cl, Dl) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0);
const add4H = (low, Ah, Bh, Ch, Dh) => (Ah + Bh + Ch + Dh + ((low / 2 ** 32) | 0)) | 0;
const add5L = (Al, Bl, Cl, Dl, El) => (Al >>> 0) + (Bl >>> 0) + (Cl >>> 0) + (Dl >>> 0) + (El >>> 0);
const add5H = (low, Ah, Bh, Ch, Dh, Eh) => (Ah + Bh + Ch + Dh + Eh + ((low / 2 ** 32) | 0)) | 0;
// prettier-ignore
const u64 = {
    fromBig, split, toBig,
    shrSH, shrSL,
    rotrSH, rotrSL, rotrBH, rotrBL,
    rotr32H, rotr32L,
    rotlSH, rotlSL, rotlBH, rotlBL,
    add, add3L, add3H, add4L, add4H, add5H, add5L,
};

// Round contants (first 32 bits of the fractional parts of the cube roots of the first 80 primes 2..409):
// prettier-ignore
const [SHA512_Kh, SHA512_Kl] = /* @__PURE__ */ (() => u64.split([
    '0x428a2f98d728ae22', '0x7137449123ef65cd', '0xb5c0fbcfec4d3b2f', '0xe9b5dba58189dbbc',
    '0x3956c25bf348b538', '0x59f111f1b605d019', '0x923f82a4af194f9b', '0xab1c5ed5da6d8118',
    '0xd807aa98a3030242', '0x12835b0145706fbe', '0x243185be4ee4b28c', '0x550c7dc3d5ffb4e2',
    '0x72be5d74f27b896f', '0x80deb1fe3b1696b1', '0x9bdc06a725c71235', '0xc19bf174cf692694',
    '0xe49b69c19ef14ad2', '0xefbe4786384f25e3', '0x0fc19dc68b8cd5b5', '0x240ca1cc77ac9c65',
    '0x2de92c6f592b0275', '0x4a7484aa6ea6e483', '0x5cb0a9dcbd41fbd4', '0x76f988da831153b5',
    '0x983e5152ee66dfab', '0xa831c66d2db43210', '0xb00327c898fb213f', '0xbf597fc7beef0ee4',
    '0xc6e00bf33da88fc2', '0xd5a79147930aa725', '0x06ca6351e003826f', '0x142929670a0e6e70',
    '0x27b70a8546d22ffc', '0x2e1b21385c26c926', '0x4d2c6dfc5ac42aed', '0x53380d139d95b3df',
    '0x650a73548baf63de', '0x766a0abb3c77b2a8', '0x81c2c92e47edaee6', '0x92722c851482353b',
    '0xa2bfe8a14cf10364', '0xa81a664bbc423001', '0xc24b8b70d0f89791', '0xc76c51a30654be30',
    '0xd192e819d6ef5218', '0xd69906245565a910', '0xf40e35855771202a', '0x106aa07032bbd1b8',
    '0x19a4c116b8d2d0c8', '0x1e376c085141ab53', '0x2748774cdf8eeb99', '0x34b0bcb5e19b48a8',
    '0x391c0cb3c5c95a63', '0x4ed8aa4ae3418acb', '0x5b9cca4f7763e373', '0x682e6ff3d6b2b8a3',
    '0x748f82ee5defb2fc', '0x78a5636f43172f60', '0x84c87814a1f0ab72', '0x8cc702081a6439ec',
    '0x90befffa23631e28', '0xa4506cebde82bde9', '0xbef9a3f7b2c67915', '0xc67178f2e372532b',
    '0xca273eceea26619c', '0xd186b8c721c0c207', '0xeada7dd6cde0eb1e', '0xf57d4f7fee6ed178',
    '0x06f067aa72176fba', '0x0a637dc5a2c898a6', '0x113f9804bef90dae', '0x1b710b35131c471b',
    '0x28db77f523047d84', '0x32caab7b40c72493', '0x3c9ebe0a15c9bebc', '0x431d67c49c100d4c',
    '0x4cc5d4becb3e42b6', '0x597f299cfc657e2a', '0x5fcb6fab3ad6faec', '0x6c44198c4a475817'
].map(n => BigInt(n))))();
// Temporary buffer, not used to store anything between runs
const SHA512_W_H = /* @__PURE__ */ new Uint32Array(80);
const SHA512_W_L = /* @__PURE__ */ new Uint32Array(80);
class SHA512 extends SHA2 {
    constructor() {
        super(128, 64, 16, false);
        // We cannot use array here since array allows indexing by variable which means optimizer/compiler cannot use registers.
        // Also looks cleaner and easier to verify with spec.
        // Initial state (first 32 bits of the fractional parts of the square roots of the first 8 primes 2..19):
        // h -- high 32 bits, l -- low 32 bits
        this.Ah = 0x6a09e667 | 0;
        this.Al = 0xf3bcc908 | 0;
        this.Bh = 0xbb67ae85 | 0;
        this.Bl = 0x84caa73b | 0;
        this.Ch = 0x3c6ef372 | 0;
        this.Cl = 0xfe94f82b | 0;
        this.Dh = 0xa54ff53a | 0;
        this.Dl = 0x5f1d36f1 | 0;
        this.Eh = 0x510e527f | 0;
        this.El = 0xade682d1 | 0;
        this.Fh = 0x9b05688c | 0;
        this.Fl = 0x2b3e6c1f | 0;
        this.Gh = 0x1f83d9ab | 0;
        this.Gl = 0xfb41bd6b | 0;
        this.Hh = 0x5be0cd19 | 0;
        this.Hl = 0x137e2179 | 0;
    }
    // prettier-ignore
    get() {
        const { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        return [Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl];
    }
    // prettier-ignore
    set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl) {
        this.Ah = Ah | 0;
        this.Al = Al | 0;
        this.Bh = Bh | 0;
        this.Bl = Bl | 0;
        this.Ch = Ch | 0;
        this.Cl = Cl | 0;
        this.Dh = Dh | 0;
        this.Dl = Dl | 0;
        this.Eh = Eh | 0;
        this.El = El | 0;
        this.Fh = Fh | 0;
        this.Fl = Fl | 0;
        this.Gh = Gh | 0;
        this.Gl = Gl | 0;
        this.Hh = Hh | 0;
        this.Hl = Hl | 0;
    }
    process(view, offset) {
        // Extend the first 16 words into the remaining 64 words w[16..79] of the message schedule array
        for (let i = 0; i < 16; i++, offset += 4) {
            SHA512_W_H[i] = view.getUint32(offset);
            SHA512_W_L[i] = view.getUint32((offset += 4));
        }
        for (let i = 16; i < 80; i++) {
            // s0 := (w[i-15] rightrotate 1) xor (w[i-15] rightrotate 8) xor (w[i-15] rightshift 7)
            const W15h = SHA512_W_H[i - 15] | 0;
            const W15l = SHA512_W_L[i - 15] | 0;
            const s0h = u64.rotrSH(W15h, W15l, 1) ^ u64.rotrSH(W15h, W15l, 8) ^ u64.shrSH(W15h, W15l, 7);
            const s0l = u64.rotrSL(W15h, W15l, 1) ^ u64.rotrSL(W15h, W15l, 8) ^ u64.shrSL(W15h, W15l, 7);
            // s1 := (w[i-2] rightrotate 19) xor (w[i-2] rightrotate 61) xor (w[i-2] rightshift 6)
            const W2h = SHA512_W_H[i - 2] | 0;
            const W2l = SHA512_W_L[i - 2] | 0;
            const s1h = u64.rotrSH(W2h, W2l, 19) ^ u64.rotrBH(W2h, W2l, 61) ^ u64.shrSH(W2h, W2l, 6);
            const s1l = u64.rotrSL(W2h, W2l, 19) ^ u64.rotrBL(W2h, W2l, 61) ^ u64.shrSL(W2h, W2l, 6);
            // SHA256_W[i] = s0 + s1 + SHA256_W[i - 7] + SHA256_W[i - 16];
            const SUMl = u64.add4L(s0l, s1l, SHA512_W_L[i - 7], SHA512_W_L[i - 16]);
            const SUMh = u64.add4H(SUMl, s0h, s1h, SHA512_W_H[i - 7], SHA512_W_H[i - 16]);
            SHA512_W_H[i] = SUMh | 0;
            SHA512_W_L[i] = SUMl | 0;
        }
        let { Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl } = this;
        // Compression function main loop, 80 rounds
        for (let i = 0; i < 80; i++) {
            // S1 := (e rightrotate 14) xor (e rightrotate 18) xor (e rightrotate 41)
            const sigma1h = u64.rotrSH(Eh, El, 14) ^ u64.rotrSH(Eh, El, 18) ^ u64.rotrBH(Eh, El, 41);
            const sigma1l = u64.rotrSL(Eh, El, 14) ^ u64.rotrSL(Eh, El, 18) ^ u64.rotrBL(Eh, El, 41);
            //const T1 = (H + sigma1 + Chi(E, F, G) + SHA256_K[i] + SHA256_W[i]) | 0;
            const CHIh = (Eh & Fh) ^ (~Eh & Gh);
            const CHIl = (El & Fl) ^ (~El & Gl);
            // T1 = H + sigma1 + Chi(E, F, G) + SHA512_K[i] + SHA512_W[i]
            // prettier-ignore
            const T1ll = u64.add5L(Hl, sigma1l, CHIl, SHA512_Kl[i], SHA512_W_L[i]);
            const T1h = u64.add5H(T1ll, Hh, sigma1h, CHIh, SHA512_Kh[i], SHA512_W_H[i]);
            const T1l = T1ll | 0;
            // S0 := (a rightrotate 28) xor (a rightrotate 34) xor (a rightrotate 39)
            const sigma0h = u64.rotrSH(Ah, Al, 28) ^ u64.rotrBH(Ah, Al, 34) ^ u64.rotrBH(Ah, Al, 39);
            const sigma0l = u64.rotrSL(Ah, Al, 28) ^ u64.rotrBL(Ah, Al, 34) ^ u64.rotrBL(Ah, Al, 39);
            const MAJh = (Ah & Bh) ^ (Ah & Ch) ^ (Bh & Ch);
            const MAJl = (Al & Bl) ^ (Al & Cl) ^ (Bl & Cl);
            Hh = Gh | 0;
            Hl = Gl | 0;
            Gh = Fh | 0;
            Gl = Fl | 0;
            Fh = Eh | 0;
            Fl = El | 0;
            ({ h: Eh, l: El } = u64.add(Dh | 0, Dl | 0, T1h | 0, T1l | 0));
            Dh = Ch | 0;
            Dl = Cl | 0;
            Ch = Bh | 0;
            Cl = Bl | 0;
            Bh = Ah | 0;
            Bl = Al | 0;
            const All = u64.add3L(T1l, sigma0l, MAJl);
            Ah = u64.add3H(All, T1h, sigma0h, MAJh);
            Al = All | 0;
        }
        // Add the compressed chunk to the current hash value
        ({ h: Ah, l: Al } = u64.add(this.Ah | 0, this.Al | 0, Ah | 0, Al | 0));
        ({ h: Bh, l: Bl } = u64.add(this.Bh | 0, this.Bl | 0, Bh | 0, Bl | 0));
        ({ h: Ch, l: Cl } = u64.add(this.Ch | 0, this.Cl | 0, Ch | 0, Cl | 0));
        ({ h: Dh, l: Dl } = u64.add(this.Dh | 0, this.Dl | 0, Dh | 0, Dl | 0));
        ({ h: Eh, l: El } = u64.add(this.Eh | 0, this.El | 0, Eh | 0, El | 0));
        ({ h: Fh, l: Fl } = u64.add(this.Fh | 0, this.Fl | 0, Fh | 0, Fl | 0));
        ({ h: Gh, l: Gl } = u64.add(this.Gh | 0, this.Gl | 0, Gh | 0, Gl | 0));
        ({ h: Hh, l: Hl } = u64.add(this.Hh | 0, this.Hl | 0, Hh | 0, Hl | 0));
        this.set(Ah, Al, Bh, Bl, Ch, Cl, Dh, Dl, Eh, El, Fh, Fl, Gh, Gl, Hh, Hl);
    }
    roundClean() {
        SHA512_W_H.fill(0);
        SHA512_W_L.fill(0);
    }
    destroy() {
        this.buffer.fill(0);
        this.set(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
    }
}
const sha512 = /* @__PURE__ */ wrapConstructor(() => new SHA512());

/* Browser Crypto Shims */
function getGlobal() {
    if (typeof self !== 'undefined') {
        return self;
    }
    if (typeof window !== 'undefined') {
        return window;
    }
    if (typeof global !== 'undefined') {
        return global;
    }
    throw new Error('unable to locate global object');
}
const anyGlobal = getGlobal();
const crypto = anyGlobal.crypto || anyGlobal.msCrypto;
function createHash(algo) {
    switch (algo) {
        case "sha256": return sha256$1.create();
        case "sha512": return sha512.create();
    }
    assertArgument(false, "invalid hashing algorithm name", "algorithm", algo);
}
function randomBytes$1(length) {
    assert$1(crypto != null, "platform does not support secure random numbers", "UNSUPPORTED_OPERATION", {
        operation: "randomBytes"
    });
    assertArgument(Number.isInteger(length) && length > 0 && length <= 1024, "invalid length", "length", length);
    const result = new Uint8Array(length);
    crypto.getRandomValues(result);
    return result;
}

/**
 *  A **Cryptographically Secure Random Value** is one that has been
 *  generated with additional care take to prevent side-channels
 *  from allowing others to detect it and prevent others from through
 *  coincidence generate the same values.
 *
 *  @_subsection: api/crypto:Random Values  [about-crypto-random]
 */
let locked = false;
const _randomBytes = function (length) {
    return new Uint8Array(randomBytes$1(length));
};
let __randomBytes = _randomBytes;
/**
 *  Return %%length%% bytes of cryptographically secure random data.
 *
 *  @example:
 *    randomBytes(8)
 *    //_result:
 */
function randomBytes(length) {
    return __randomBytes(length);
}
randomBytes._ = _randomBytes;
randomBytes.lock = function () { locked = true; };
randomBytes.register = function (func) {
    if (locked) {
        throw new Error("randomBytes is locked");
    }
    __randomBytes = func;
};
Object.freeze(randomBytes);

const _sha256 = function (data) {
    return createHash("sha256").update(data).digest();
};
let __sha256 = _sha256;
let locked256 = false;
/**
 *  Compute the cryptographic SHA2-256 hash of %%data%%.
 *
 *  @_docloc: api/crypto:Hash Functions
 *  @returns DataHexstring
 *
 *  @example:
 *    sha256("0x")
 *    //_result:
 *
 *    sha256("0x1337")
 *    //_result:
 *
 *    sha256(new Uint8Array([ 0x13, 0x37 ]))
 *    //_result:
 *
 */
function sha256(_data) {
    const data = getBytes(_data, "data");
    return hexlify$1(__sha256(data));
}
sha256._ = _sha256;
sha256.lock = function () { locked256 = true; };
sha256.register = function (func) {
    if (locked256) {
        throw new Error("sha256 is locked");
    }
    __sha256 = func;
};
Object.freeze(sha256);
Object.freeze(sha256);

/**
 *  Concatenate an array of %%datas%% Uint8Arrays into a single
 *  Uint8Array.
 */
function concat(datas) {
    const length = datas.reduce((a, d) => (a + d.length), 0);
    const result = new Uint8Array(length);
    let offset = 0;
    for (const data of datas) {
        result.set(data, offset);
        offset += data.length;
    }
    return result;
}
const HEX = "0123456789abcdef";
/**
 *  Create a string representation of %%value%% as a hex string. If
 *  %%width%% is a number, it will be padded (on the left) with 0
 *  nibbles and it %%width%% is ``true``, will be padded (on the left)
 *  to an even length.
 */
function hexlify(value, width) {
    let result = "";
    if (typeof (value) === "number" || typeof (value) === "bigint") {
        result = value.toString(16);
    }
    else {
        for (let i = 0; i < value.length; i++) {
            const d = value[i];
            result += HEX[d >> 4] + HEX[d & 0x0f];
        }
    }
    if (typeof (width) === "number") {
        while (result.length < 2 * width) {
            result = "0" + result;
        }
    }
    else if (width) {
        if (result.length % 2) {
            result = "0" + result;
        }
    }
    return result;
}
/**
 *  Convert %%bytes%% from a Little-Endian representation to a
 *  number.
 */
function fromLeBytes(bytes) {
    let result = 0;
    for (let i = 0; i < bytes.length; i++) {
        result |= (bytes[i] << (i << 3));
    }
    return result >>> 0;
}
/**
 *  Convert %%value%% to a Little-Endian representation as a
 *  Uint8Array %%width%% bytes wide.
 */
function toLeBytes(value, width) {
    if (typeof (value) === "bigint") {
        value = Number(value);
    }
    const result = new Uint8Array(width);
    for (let i = 0; i < width; i++) {
        result[i] = Number(value & 0xff);
        value >>= 8;
    }
    return result;
}

/**
 *  Serial Line Internet Protocol (SLIP) coder library.
 *
 *  See: https://en.wikipedia.org/wiki/Serial_Line_Internet_Protocol
 */
/**
 *  Encode %%data%% using SLIP encoding.
 */
function slipEncode(data) {
    let stuffBytes = 0;
    for (let i = 0; i < data.length; i++) {
        let c = data[i];
        if (c === 0xdb || c === 0xc0) {
            stuffBytes++;
        }
    }
    const slipData = new Uint8Array(2 + stuffBytes + data.length);
    let offset = 0;
    slipData[offset++] = 0xc0;
    for (let i = 0; i < data.length; i++) {
        let c = data[i];
        if (c === 0xdb) {
            slipData[offset++] = 0xdb;
            slipData[offset++] = 0xdd;
        }
        else if (c === 0xc0) {
            slipData[offset++] = 0xdb;
            slipData[offset++] = 0xdc;
        }
        else {
            slipData[offset++] = c;
        }
    }
    slipData[offset++] = 0xc0;
    return slipData;
}
function findDebug(data, start) {
    for (let i = start; i < data.length - 2; i++) {
        if (hexlify(data.slice(i, i + 3)) === "c0c0c0") {
            return i;
        }
    }
    return -1;
}
const _TextDecoder$1 = new TextDecoder();
function _slipDecode(data) {
    const markers = [];
    for (let i = 0; i < data.length; i++) {
        if (data[i] === 0xc0) {
            markers.push(i);
        }
        if (markers.length < 2) {
            continue;
        }
        const result = [];
        for (let i = markers[0] + 1; i < markers[1]; i++) {
            if (data[i] === 0xdb) {
                if (data[i + 1] === 0xdc) {
                    result.push(0xc0);
                    i++;
                    continue;
                }
                else if (data[i + 1] === 0xdd) {
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
        };
    }
    return null;
}
/**
 *  Decode %%data%% as SLIP encoded data, if valid SLIP-encoded data. Otherwise
 *  return ``null``.
 */
function slipDecode(data) {
    const debug = findDebug(data, 0);
    if (debug === -1) {
        return _slipDecode(data);
    }
    const slip = _slipDecode(data.slice(0, debug));
    if (slip) {
        return slip;
    }
    const debugEnd = findDebug(data, debug + 3);
    if (debug === -1) {
        return null;
    }
    return {
        debug: _TextDecoder$1.decode(data.slice(debug + 4, debugEnd)),
        remaining: concat([data.slice(0, debug), data.slice(debugEnd + 3)])
    };
}

/**
 *  Helpers and constants for the serial protocol used by the UART
 *  bootloader in the ESP32 ROM and ESPTool Stub loader.
 *
 *  See: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */
/////////////
// Commands supported by ROM and Stub
const CMD_FLASH_BEGIN = 0x02;
const CMD_FLASH_DATA = 0x03;
const CMD_FLASH_END = 0x04;
const CMD_MEM_BEGIN = 0x05;
const CMD_MEM_END = 0x06;
const CMD_MEM_DATA = 0x07;
const CMD_SYNC = 0x08;
const CMD_WRITE_REG = 0x09;
const CMD_READ_REG = 0x0a;
const CMD_FLASH_DEFL_BEGIN = 0x10;
const CMD_FLASH_DEFL_DATA = 0x11;
const CMD_FLASH_DEFL_END = 0x12;
const CMD_ERASE_REGION = 0xd1;
const CMD_READ_FLASH = 0xd2;
/////////////
// Firefly extended commands
const CMD_FFX_VERSION = 0x80;
const CMD_FFX_VERIFY = 0x84;
const CMD_FFX_READ_RLE = 0x85;
const CMD_FFX_STIR_ENTROPY = 0x86;
const CMD_FFX_GENKEY = 0x87;
/////////////
// SPI Commands
const CMDSPI_RDID = 0x9f;
function computeChecksum(data) {
    let value = 0xef;
    for (let i = 0; i < data.length; i++) {
        value ^= data[i];
    }
    return value;
}
function syncPacket() {
    const packet = new Uint8Array(36);
    packet[0] = 0x07;
    packet[1] = 0x07;
    packet[2] = 0x12;
    packet[3] = 0x20;
    packet.fill(0x55, 4);
    return packet;
}
function getErrorMessage(code) {
    switch (code) {
        // ROM Error codes
        case 0x05:
            return "Received message is invalid; parameters or length field is invalid";
        case 0x06:
            return "Failed to act on received message";
        case 0x07:
            return "Invalid CRC in message";
        case 0x08:
            return "Flash write error; flash checksum does not match";
        case 0x09:
            return "Flash read error; SPI read failed";
        case 0x0a:
            return "Flash read length error; SPI read request length is too long";
        case 0x0b:
            return "Deflate error";
        // Ffx Error codes
        case 0x86:
            return "Ffx Error: FFX_FAILED_KEYGEN";
        // Stub Error codes
        case 0xc0:
            return "Stub Error: ESP_BAD_DATA_LEN";
        case 0xc1:
            return "Stub Error: ESP_BAD_DATA_CHECKSUM";
        case 0xc2:
            return "Stub Error: ESP_BAD_BLOCKSIZE";
        case 0xc3:
            return "Stub Error: ESP_INVALID_COMMAND";
        case 0xc4:
            return "Stub Error: ESP_FAILED_SPI_OP";
        case 0xc5:
            return "Stub Error: ESP_FAILED_SPI_UNLOCK";
        case 0xc6:
            return "Stub Error: ESP_NOT_IN_FLASH_MODE";
        case 0xc7:
            return "Stub Error: ESP_INFLATE_ERROR";
        case 0xc8:
            return "Stub Error: ESP_NOT_ENOUGH_DATA";
        case 0xc9:
            return "Stub Error: ESP_TOO_MUCH_DATA";
        case 0xff:
            return "Stub Error: ESP_CMD_NOT_IMPLEMENTED";
    }
    return `unknown error: 0x${hexlify(code, 1)}`;
}

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
        this._data = concat([this._data, data]);
    }
    compact() {
        this._data = this.bytes;
        this._read = 0;
    }
    putInt32Le(value) {
        this.putBytes(toLeBytes(value, 4));
    }
    getInt32Le() {
        this._read += 4;
        return fromLeBytes(this._data.slice(this._read - 4, this._read));
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
        finalBlock.putBytes(_padding.slice(0, this.blockLength - overflow));
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
const _padding = new Uint8Array(65);
_padding[0] = 128;
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

function assert(cond, message, info) {
    if (cond) {
        return;
    }
    const error = new Error(message);
    if (info) {
        for (const key in info) {
            error[key] = info[key];
        }
    }
    throw error;
}

const _TextEncoder = new TextEncoder();
function toUtf8Bytes(text) {
    return _TextEncoder.encode(text);
}
const _TextDecoder = new TextDecoder();
function toUtf8String(data) {
    return _TextDecoder.decode(data);
}
function extractString(data) {
    let i = 0;
    while (i < data.length && data[i] >= 32 && data[i] < 127) {
        i++;
    }
    return toUtf8String(data.slice(0, i));
}

// # 3K for partition data (96 entries) leaves 1K in a 4K sector for signature
const PartitionTableSize = 0xC00;
// Magic header for each partition
const Magic$1 = new Uint8Array([0xaa, 0x50]);
// End marker of partitions within the partition table
const EndMarker = new Uint8Array(16);
EndMarker.fill(0xff);
EndMarker[0] = 0xeb;
EndMarker[1] = 0xeb;
const FlagReadOnly = 0x02;
function getType(type) {
    switch (type) {
        case "app": return 0x00;
        case "data": return 0x01;
    }
    throw new Error(`unknown Type: ${type}`);
}
const TypeMap = { 0: "app", 1: "data" };
function getAppType(type) {
    switch (type) {
        case "factory": return 0x00;
        case "ota_0": return 0x10;
        case "ota_1": return 0x11;
        case "test": return 0x20;
    }
    throw new Error(`unknown AppType: ${type}`);
}
const AppTypeMap = {
    0x00: "factory", 0x10: "ota_0", 0x11: "ota_1", 0x20: "test"
};
function getDataType(type) {
    switch (type) {
        case "ota": return 0x00;
        case "phy": return 0x01;
        case "nvs": return 0x02;
        case "coredump": return 0x03;
        case "nvs_keys": return 0x04;
        case "efuse": return 0x05;
        case "undefined": return 0x06;
        case "esphttpd": return 0x80;
        case "fat": return 0x81;
        case "spiffs": return 0x82;
        case "littlefs": return 0x83;
    }
    throw new Error(`invalid DataType: ${type}`);
}
const DataTypeMap = {
    0x00: "ota", 0x01: "phy", 0x02: "nvs", 0x03: "coredump",
    0x04: "nvs_keys", 0x05: "efuse", 0x06: "undefined",
    0x80: "esphttpd", 0x81: "fat", 0x82: "spiffs", 0x83: "littlefs"
};
function getSubtype(type, subtype) {
    switch (type) {
        case "app": return getAppType(subtype);
        case "data": return getDataType(subtype);
    }
    throw new Error(`invalid Subtype: ${type}`);
}
class Partition {
    name;
    type;
    subtype;
    offset;
    size;
    isReadonly;
    constructor(name, type, subtype, offset, size, isReadonly) {
        if (toUtf8Bytes(name).length > 16) {
            throw new Error(`bad name: ${name}`);
        }
        this.name = name;
        this.type = type;
        this.subtype = subtype;
        this.offset = offset;
        this.size = size;
        this.isReadonly = isReadonly;
    }
    get binary() {
        let flags = 0;
        if (this.isReadonly) {
            flags |= FlagReadOnly;
        }
        // - Magic (2 bytes)
        // - type (1 byte)
        // - subtype (1 byte)
        // - offset (4 bytes; little-endian)
        // - size (4 bytes; little-endian)
        // - name (16 bytes)
        // - flags (4 bytes; read-only = 1)
        const result = new Uint8Array(32);
        result.set(Magic$1, 0);
        result[2] = getType(this.type);
        result[3] = getSubtype(this.type, this.subtype);
        result.set(toLeBytes(this.offset, 4), 4);
        result.set(toLeBytes(this.size, 4), 8);
        result.set(toUtf8Bytes(this.name), 12);
        result.set(toLeBytes(flags, 4), 28);
        return result;
    }
}
class PartitionTable {
    #records;
    #flashSize;
    get flashSize() { return this.#flashSize; }
    constructor(flashSize = 0) {
        this.#records = [];
        this.#flashSize = flashSize;
    }
    get partitions() {
        const records = this.#records.slice();
        records.sort((a, b) => (a.offset - b.offset));
        return records;
    }
    addPartition(name, type, subtype, offset, size, isReadonly) {
        // Check the flash is large enough
        assert(this.#flashSize === 0 || offset + size <= this.#flashSize, `partition outside flash range`, {
            name, offset, size, flashSize: this.#flashSize
        });
        if (type === "data") {
            // Check ota data is exactly 0x2000 bytes
            assert(subtype != "ota" || size === 0x2000, `ota_data must be 0x2000 bytes`, {
                name, size
            });
            // Check the data partition is 4k bounrary aligned
            assert((offset & 0xfff) === 0, `data partition must be aligned on 0x10000 boundary`, {
                name, offset
            });
        }
        if (type === "app") {
            // Check the app partition is 64k boundary aligned
            assert((offset & 0xffff) === 0, `app partition must be aligned on 0x10000 boundary`, {
                name, offset
            });
            // Check the size is 4k boundary aligned
            assert((size & 0xfff) === 0, `app partition size must be aligned on 0x1000 boundary`, {
                name, size
            });
        }
        // Check the name is unique
        const partition = this.getPartition(name);
        assert(!partition, `duplicate partition name: ${name}`, {
            name, partition
        });
        // Check the partition doesn't overlap any other partition
        const partitions = this.partitions;
        for (const partition of partitions) {
            assert(offset >= partition.offset + partition.size || offset + size < partition.offset, `overlapping partition: ${name} overlaps ${partition.name}`, {
                name, partition
            });
        }
        this.#records.push(new Partition(name, type, subtype, offset, size, isReadonly));
    }
    getPartitionAt(offset) {
        for (const partition of this.partitions) {
            const o = partition.offset;
            if (offset >= o && offset < o + partition.size) {
                return partition;
            }
        }
        return null;
    }
    getPartition(name) {
        for (const record of this.#records) {
            if (record.name === name) {
                return record;
            }
        }
        return null;
    }
    summary() {
        function toAddr(_v) {
            let v = String(_v.toString(16));
            while (v.length < 7) {
                v = "0" + v;
            }
            return v;
        }
        function size(v) {
            if (v < 1024) {
                return `${v}b`;
            }
            if (v < 1024 * 1024) {
                return `${(v / 1024).toFixed(1)}kb`;
            }
            return `${(v / 1024 / 1024).toFixed(1)}Mb`;
        }
        function padl(text, width) {
            while (text.length < width) {
                text = " " + text;
            }
            return text;
        }
        function padr(text, width) {
            while (text.length < width) {
                text = text + " ";
            }
            return text;
        }
        const lines = [];
        let offset = 0;
        for (const p of this.partitions) {
            if (p.offset > offset) {
                lines.push(`  ${toAddr(offset)}:${toAddr(p.offset)} ${padl(size(p.offset - offset), 10)}  [ UNUSED ]`);
            }
            lines.push(`  ${toAddr(p.offset)}:${toAddr(p.size)} ${padl(size(p.size), 10)}  ${padr(p.name, 16)}  ${p.type}/${p.subtype} ${p.isReadonly ? "RO" : ""}`);
            offset = p.offset + p.size;
        }
        if (this.#flashSize && offset < this.#flashSize) {
            lines.push(`  ${toAddr(offset)}:${toAddr(this.#flashSize)} ${padl(size(this.#flashSize - offset), 10)}  [ UNUSED ]`);
        }
        return lines.join("\n");
    }
    get csv() {
        const pad = (text, length) => {
            text += ', ';
            while (text.length < length) {
                text += " ";
            }
            return text;
        };
        const addr = (_v) => {
            let v = _v.toString(16);
            while (v.length < 7) {
                v = "0" + v;
            }
            return "0x" + v + ",";
        };
        const lines = [];
        lines.push([
            pad("# Name", 16),
            pad("Type", 7),
            pad("Subtype", 9),
            pad("Offset", 10),
            pad("Size", 10),
            "Flags"
        ].join(" "));
        for (const r of this.#records) {
            let flags = "";
            if (r.isReadonly) {
                flags += "readonly";
            }
            lines.push([
                pad(r.name, 16),
                pad(r.type, 7),
                pad(r.subtype, 9),
                addr(r.offset),
                addr(r.size),
                flags
            ].join(" "));
        }
        return lines.join("\n");
    }
    get json() {
        const partitions = [];
        for (const r of this.#records) {
            partitions.push({
                name: r.name,
                type: r.type,
                subtype: r.subtype,
                offset: r.offset,
                size: r.size,
                isReadonly: r.isReadonly,
            });
        }
        return { version: "0.1", partitions };
    }
    get binary() {
        const result = new Uint8Array(PartitionTableSize);
        result.fill(0xff);
        let offset = 0;
        for (const record of this.#records) {
            const bin = record.binary;
            result.set(bin, offset);
            offset += bin.length;
        }
        const checksum = Md5.hash(result.slice(0, offset));
        result.set(EndMarker, offset);
        offset += EndMarker.length;
        result.set(checksum, offset);
        offset += checksum.length;
        return result;
    }
    static from(data, size = 0) {
        assert(data.length === 4096, `unexpected data length`, {
            data
        });
        const result = new PartitionTable(size);
        for (let i = 0; i < data.length; i += 32) {
            const d = data.slice(i, i + 32);
            if (d[0] === EndMarker[0] && d[1] === EndMarker[1]) {
                break;
            }
            assert(d[0] === Magic$1[0] && d[1] === Magic$1[1], `invalid magic number`, {
                data, offset: i
            });
            const type = TypeMap[d[2]];
            assert(type, `unknown partition type`, { data, type: d[2] });
            const subtype = (type === "app") ? AppTypeMap[d[3]] :
                DataTypeMap[d[3]];
            assert(subtype, `unknown partition subtype`, { data, subtype: d[3] });
            const offset = fromLeBytes(d.slice(4, 8));
            const size = fromLeBytes(d.slice(8, 12));
            const _name = d.slice(12, 12 + 16);
            let np = 0;
            while (np < _name.length && _name[++np])
                ;
            const name = toUtf8String(_name.slice(0, np));
            const flags = fromLeBytes(d.slice(28));
            const isReadonly = !!(flags & FlagReadOnly);
            result.addPartition(name, type, subtype, offset, size, isReadonly);
        }
        return result;
    }
}
/*
import { BinDiff } from "./debug.js";

import fs from "fs";

const expected = fs.readFileSync("obsolete/test-part/partition.bin");

const table = new PartitionTable(16 * 1024 * 1024);
//table.addPartition("attest", "data", "nvs", 0x009000, 0x007000, false);
//table.addPartition("factory", "app", "factory", 0x010000, 0x700000, false);
//table.addPartition("nvs", "data", "nvs", 0xf00000, 0x100000, false);
table.addPartition("attest", "data", "nvs", 0x009000, 0x005000, true);
//table.addPartition("futurekeys", "data", "nvs", 0x00c000, 0x001000, false);
table.addPartition("otadata", "data", "ota", 0x00e000, 0x002000, false);
//table.addPartition("theme", "data", "nvs", 0x00D000, 0x003000, false);
table.addPartition("factory", "app", "factory", 0x010000, 0x0e0000, false);
table.addPartition("nvs", "data", "nvs", 0x100000, 0x100000, false);
table.addPartition("ota_0", "app", "ota_0", 0x200000, 0x700000, false);
table.addPartition("ota_1", "app", "ota_1", 0x900000, 0x700000, false);

const diff = new BinDiff(table.binary, expected);
diff.dump(0, undefined, true);

console.log(table.summary());
console.log(table.csv);
*/

/**
 *  Returns a **Promise** that will resolve after %%duration%%.
 */
function stall(duration) {
    return new Promise((resolve) => {
        setTimeout(resolve, duration);
    });
}

/**
 *  A simple communication library for the ESP Devices over the
 *  Serial Protocol for the UART bootloader.
 *
 *  See:
 *    ESPTool:
 *    ESPTool-js:
 *    Protocol: https://docs.espressif.com/projects/esptool/en/latest/esp32/advanced-topics/serial-protocol.html
 */
const Sequences = {
    Reset: "R 100 D 50 N",
    ResetUsb: "N 100 D 100 R 100 R 100 N",
    ResetHard: "R 100 N",
};
/**
 *  The **BaseDevice** class is a minimal implementation of
 *  of the Serial Protocol necessary to read/write and detect
 *  the device magic number.
 */
class Device {
    serial;
    #readBuffer;
    #writeBuffer;
    #maxReadBuffer;
    #maxWriteBuffer;
    #stub;
    #stubPromise;
    #bootMode;
    constructor(serial, options) {
        if (options == null) {
            options = {};
        }
        this.serial = serial;
        this.#readBuffer = [];
        this.#writeBuffer = [];
        this.#maxReadBuffer = getValue("invalid options.maxReadBuffer", options.maxReadBuffer, 1 << 20);
        this.#maxWriteBuffer = getValue("invalid options.maxWriteBuffer", options.maxReadBuffer, 1 << 20);
        this.#stub = "";
        this.#bootMode = false;
    }
    get _maxReadBuffer() { return this.#maxReadBuffer; }
    get _maxWriteBuffer() { return this.#maxWriteBuffer; }
    get _available() { return sum(this.#readBuffer); }
    get _backlog() { return sum(this.#writeBuffer); }
    get isBootMode() { return this.#bootMode; }
    /**
     *  Halts any executing code on the device and enters ROM
     *  bootmode. The stub is not loaded at this point, but
     *  any attempt to use operations that require the stub
     *  will automatically upload it to RAM and start it.
     */
    async connect() {
        await this.serial.connect();
        await this.serial.reset(true);
        this.#bootMode = true;
        await stall(50);
        await this._read(); // Flush
        await this._sync();
        await stall(100);
        await this._read(); // Flush
        return await this._readRegister(0x40001000);
    }
    /**
     *  Resets the device (leaving bootmode) executing any
     *  firmware flashed on the device;
     */
    async reset() {
        this.#stub = "";
        this.#stubPromise = undefined;
        await this.serial.reset();
        this.#bootMode = false;
    }
    _debug(data) {
        console.log("DEBUG", data);
    }
    /**
     *  Reads any data on the stream into the read buffer and returns
     *  the combined data.
     *
     *  Use [[_unread]] to place any data back on the read buffer
     *  to be processed in the future.
     */
    async _read() {
        const input = await this.serial.read();
        if (input.length) {
            this.#readBuffer.push(input);
        }
        const result = concat(this.#readBuffer);
        this.#readBuffer = [];
        return result;
    }
    /**
     *  Read a SLIP packet, optionally matching the %%op%%. Returns
     *  ``null`` if no complete matching packet is found.
     *
     *  Any stray packets or bytes at the front of the read buffer
     *  are discarded.
     */
    async _readSlipPacket(op) {
        const data = await this._read();
        const slip = slipDecode(data);
        // No packet found; maybe we need more bytes
        if (slip == null) {
            this._unread(data);
            return null;
        }
        // Place unconsumed bytes back onto the read buffer
        this._unread(slip.remaining);
        if ("debug" in slip) {
            this._debug(slip.debug);
            return null;
        }
        if (op == null) {
            return slip.data;
        }
        assert(slip.data[0] === 1, "invalid direction", {
            direction: slip.data[0],
            packet: slip.data
        });
        // @TODO: Skip unmatched operations
        if (slip.data[1] !== op) {
            console.log("unexpected command; @TODO: skip", {
                slip, op: `0x${op.toString(16)}`
            });
        }
        if (op === CMD_READ_REG || op === CMD_FFX_VERSION) {
            return slip.data.slice(4, 8);
        }
        const result = slip.data.slice(8);
        const status = result.slice(result.length - (this.#stub ? 2 : 4));
        assert(status[0] === 0, getErrorMessage(status[1]), {
            code: status[1], data: slip.data
        });
        return result.slice(0, result.length - status.length);
    }
    _unread(data) {
        this.#readBuffer.unshift(data);
    }
    async _write(data) {
        return this.serial.write(data);
    }
    async _writeSlipPacket(data) {
        return this._write(slipEncode(data));
    }
    async _sync() {
        let error = null;
        for (let i = 0; i < 5; i++) {
            try {
                return await this._command(CMD_SYNC, syncPacket());
            }
            catch (e) {
                console.log(error);
                console.log("retry");
                error = e;
            }
            await stall(10);
        }
        if (error) {
            throw error;
        }
    }
    /**
     *  Send a command to the connected device and parse the response.
     */
    async _command(op, data, checksum) {
        if (Array.isArray(data)) {
            data = new Uint8Array(data);
        }
        const packet = new Uint8Array(8 + (data ? data.length : 0));
        packet[0] = 0x00;
        packet[1] = op;
        if (data) {
            packet.set(toLeBytes(data.length, 2), 2);
            packet.set(data, 8);
        }
        await stall(2);
        if (checksum) {
            packet.set(toLeBytes(checksum, 4), 4);
        }
        await this._writeSlipPacket(packet);
        let waitTime = 30;
        // Generating an RSA key can take a while
        if (op === CMD_FFX_GENKEY) {
            waitTime = 100;
        }
        // Try reading up to a timeout
        for (let i = 0; i < ((waitTime * 1000) / 10); i++) {
            const result = await this._readSlipPacket(op);
            if (result) {
                return result;
            }
            await stall(10);
        }
        assert(false, `command failed to return a response`, {
            op, data, checksum
        });
    }
    async _readRegister(address) {
        const result = await this._command(CMD_READ_REG, toLeBytes(address, 4));
        return fromLeBytes(result);
    }
    async #uploadMemory(offset, data, entryPoint) {
        const blockCount = Math.ceil(data.length / RAM_BLOCK_SIZE);
        await this._command(CMD_MEM_BEGIN, concat([
            toLeBytes(data.length, 4),
            toLeBytes(blockCount, 4),
            toLeBytes(RAM_BLOCK_SIZE, 4),
            toLeBytes(offset, 4),
        ]));
        // docs say to pad the blocks, but that seems to break CRC
        for (let i = 0; i < blockCount; i++) {
            const start = i * RAM_BLOCK_SIZE;
            let block = data.slice(start, start + RAM_BLOCK_SIZE);
            await this._command(CMD_MEM_DATA, concat([
                toLeBytes(block.length, 4),
                toLeBytes(i, 4),
                toLeBytes(0, 4),
                toLeBytes(0, 4),
                block
            ]), computeChecksum(block));
        }
        if (entryPoint != null) {
            await this._command(CMD_MEM_END, concat([
                toLeBytes((entryPoint === 0) ? 1 : 0, 4),
                toLeBytes(entryPoint, 4),
            ]));
            // Wait for the stub to start
            let ohai = null;
            while (ohai == null) {
                await stall(10);
                ohai = await this._readSlipPacket();
                if (ohai && hexlify$1(ohai) === "0x4f484149") {
                    break;
                }
            }
        }
    }
    async _enableStub() {
        if (this.#stubPromise == null) {
            this.#stubPromise = (async () => {
                const stub = await this._getStub();
                await this.#uploadMemory(stub.text_start, decodeBase64(stub.text));
                await this.#uploadMemory(stub.data_start, decodeBase64(stub.data), stub.entry);
                const version = fromLeBytes(await this._command(CMD_FFX_VERSION));
                const major = version >> 24;
                const minor = (version >> 16) & 0xff;
                const patch = version & 0xffff;
                /*
                                const change = await this._command(CMD_CHANGE_BAUDRATE, concat([
                                    toLeBytes(460800, 4),
                                    toLeBytes(115200, 4)
                                ]));
                                console.log({ change });
                */
                this.#stub = `${major}.${minor}.${patch}`;
            })();
        }
        await this.#stubPromise;
        return this.#stub;
    }
    async run(stub) {
        await this.#uploadMemory(stub.text_start, decodeBase64(stub.text));
        if (stub.data != null && stub.data_start != null) {
            await this.#uploadMemory(stub.data_start, decodeBase64(stub.data));
        }
        const packet = new Uint8Array(8 + 8);
        packet[0] = 0x00;
        packet[1] = CMD_MEM_END;
        packet.set(toLeBytes(8, 2), 2);
        packet.set(concat([
            toLeBytes(0, 4), toLeBytes(stub.entry, 4),
        ]), 8);
        await stall(2);
        await this._writeSlipPacket(packet);
    }
    async verifyFlash(offset, length) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        return hexlify$1(await this._command(CMD_FFX_VERIFY, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4)
        ])));
    }
    async _readFlashOld(offset, length, progress) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        const blockSize = 0x1000;
        await this._command(CMD_READ_FLASH, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4),
            toLeBytes(blockSize, 4),
            toLeBytes(1024, 4),
        ]));
        let readCount = 0;
        const blocks = [];
        let pending = new Uint8Array(0);
        while (readCount < length) {
            pending = concat([pending, await this._read()]);
            if (pending.length == 0) {
                continue;
            }
            while (true) {
                const block = slipDecode(pending);
                if (block == null) {
                    break;
                }
                if ('debug' in block) {
                    this._debug(block.debug);
                    continue;
                }
                if (block.data.length === 3) {
                    const length = (block.data[0] << 8) | block.data[1];
                    const same = block.data[2];
                    block.data = new Uint8Array(length);
                    block.data.fill(same);
                }
                blocks.push(block.data);
                readCount += block.data.length;
                pending = block.remaining;
                // ACK
                await this._writeSlipPacket(toLeBytes(readCount, 4));
            }
            if (progress) {
                progress(readCount / length);
            }
        }
        const result = concat(blocks);
        while (true) {
            const _checksum = slipDecode(await this._read());
            if (_checksum == null) {
                await stall(5);
                continue;
            }
            if ("debug" in _checksum) {
                this._debug(_checksum.debug);
                continue;
            }
            const checksum = hexlify$1(_checksum.data);
            const computed = hexlify$1(Md5.hash(result));
            assert(checksum === computed, `checksum failed`, {
                checksum, computed
            });
            break;
        }
        return result;
    }
    async readFlash(offset, length, progress) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        let lastPercent = 0;
        if (progress) {
            progress(lastPercent);
        }
        await this._command(CMD_FFX_READ_RLE, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4),
        ]));
        const blocks = [];
        let readCount = 0;
        let pending = new Uint8Array(0);
        while (readCount < length) {
            pending = concat([pending, await this._read()]);
            if (pending.length == 0) {
                continue;
            }
            while (true) {
                const block = slipDecode(pending);
                if (block == null) {
                    break;
                }
                if ('debug' in block) {
                    this._debug(block.debug);
                    continue;
                }
                pending = block.remaining;
                let data = null;
                switch (block.data[0]) {
                    case 0:
                        data = block.data.slice(4);
                        break;
                    case 1: {
                        const l = fromLeBytes(block.data.slice(2, 4));
                        data = new Uint8Array(l);
                        data.fill(block.data[1]);
                        break;
                    }
                    case 2:
                        if (hexlify$1(block.data.slice(4)) !== sha256(concat(blocks))) {
                            throw new Error(`bad checksum`);
                        }
                        break;
                    default:
                        throw new Error("");
                }
                if (data == null) {
                    break;
                }
                blocks.push(data);
                readCount += data.length;
            }
            const percent = Math.floor(100 * readCount / length);
            if (progress && percent != lastPercent) {
                progress(percent);
                lastPercent = percent;
            }
        }
        if (progress) {
            progress(100);
        }
        return concat(blocks);
    }
    async eraseFlash(offset, length) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        await this._command(CMD_ERASE_REGION, concat([
            toLeBytes(offset, 4),
            toLeBytes(length, 4)
        ]));
    }
    async writeFlashCompressed(offset, data, progress) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        assert(fromLeBytes(data.slice(0, 4)) === 0x7a62696e, `invalid compressed image`, { data });
        let lastPercent = 0;
        if (progress) {
            progress(lastPercent);
        }
        const size = fromLeBytes(data.slice(4, 8));
        const expected = hexlify$1(data.slice(8, 8 + 32));
        data = data.slice(8 + 32);
        const blockCount = Math.ceil(data.length / FLASH_BLOCK_SIZE);
        await this._command(CMD_FLASH_DEFL_BEGIN, concat([
            toLeBytes(size, 4),
            toLeBytes(blockCount, 4),
            toLeBytes(FLASH_BLOCK_SIZE, 4),
            toLeBytes(offset, 4),
        ]));
        // docs say to pad the blocks, but that seems to break CRC
        for (let i = 0; i < blockCount; i++) {
            const start = i * FLASH_BLOCK_SIZE;
            const block = data.slice(start, start + FLASH_BLOCK_SIZE);
            await this._command(CMD_FLASH_DEFL_DATA, concat([
                toLeBytes(block.length, 4),
                toLeBytes(i, 4),
                toLeBytes(0, 4),
                toLeBytes(0, 4),
                block
            ]), computeChecksum(block));
            const percent = Math.floor(100 * i / blockCount);
            if (progress && percent != lastPercent) {
                progress(percent);
                lastPercent = percent;
            }
        }
        await this._command(CMD_FLASH_DEFL_END, toLeBytes(1, 4));
        const checksum = await this.verifyFlash(offset, size);
        assert(checksum === expected, `writeFlash failed checksum`, {
            checksum, expected
        });
        if (progress) {
            progress(100);
        }
        return checksum;
    }
    async writeFlash(offset, data, progress) {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        let lastPercent = 0;
        if (progress) {
            progress(lastPercent);
        }
        const blockCount = Math.ceil(data.length / FLASH_BLOCK_SIZE);
        await this._command(CMD_FLASH_BEGIN, concat([
            toLeBytes(data.length, 4),
            toLeBytes(blockCount, 4),
            toLeBytes(FLASH_BLOCK_SIZE, 4),
            toLeBytes(offset, 4),
        ]));
        // docs say to pad the blocks, but that seems to break CRC
        for (let i = 0; i < blockCount; i++) {
            const start = i * FLASH_BLOCK_SIZE;
            const block = data.slice(start, start + FLASH_BLOCK_SIZE);
            await this._command(CMD_FLASH_DATA, concat([
                toLeBytes(block.length, 4),
                toLeBytes(i, 4),
                toLeBytes(0, 4),
                toLeBytes(0, 4),
                block
            ]), computeChecksum(block));
            const percent = Math.floor(100 * i / blockCount);
            if (progress && percent != lastPercent) {
                progress(percent);
                lastPercent = percent;
            }
        }
        await this._command(CMD_FLASH_END, toLeBytes(1, 4));
        const checksum = await this.verifyFlash(offset, data.length);
        const expected = sha256(data);
        assert(checksum === expected, `writeFlash failed checksum`, {
            checksum, expected
        });
        if (progress) {
            progress(100);
        }
        return checksum;
    }
    async readPartitionTable() {
        const info = await this.getDeviceInfo();
        return PartitionTable.from(await this.readFlash(0x8000, 0x1000), info.flashSize);
    }
    async generateKey() {
        const version = await this._enableStub();
        assert(version === "0.1.0", `unknown Stub version`, { version });
        const getKey = (tag) => {
            return ({ C: "cipherdata", P: "pubkeyN", M: "marker" }[tag]) || "unknown";
        };
        // Add some extra entropy to the device
        await this._command(CMD_FFX_STIR_ENTROPY, randomBytes(32));
        // Generate an RSA keypair on-device
        const data = await this._command(CMD_FFX_GENKEY);
        // Decode the result
        const result = {};
        // Data encoding; [ TAG, length_hi, length_lo, data<length>, ... ]
        let offset = 0;
        while (offset < data.length) {
            const tag = String.fromCharCode(data[offset]);
            const length = (data[offset + 1] << 8) | data[offset + 2];
            result[getKey(tag)] = data.slice(offset + 3, offset + 3 + length);
            offset += 3 + length;
        }
        return result;
    }
}
function getValue(message, value, fallback) {
    if (value == null) {
        return fallback;
    }
    assert(Number.isInteger(value), `${message}: ${value}`, { value });
    if (value < -1) {
        return -1;
    }
    return value;
}
function sum(values) {
    return values.reduce((accum, value) => (accum + value.length), 0);
}
const RAM_BLOCK_SIZE = 0x1800;
const FLASH_BLOCK_SIZE = 0x4000;

function getModelName(model) {
    if ((model >> 8) === 1) {
        return `Firefly Pixie (rev: ${model & 0xff})`;
    }
    return `[unknown model=0x${model.toString(16)}]`;
}
BigInt(65537);

const Stub = { "text": "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", "text_start": 1077411840, "entry": 1077414386, "text_size": 4720, "data": "GGvIP1ANOEDcDThAUBI4QFwOOEAADjhAXA44QLwOOEBoDzhA1A84QIIPOEDsDDhAJA84QGQPOEDYDjhAPAw4QAwPOEA8DDhABhA4QCAOOEBcDjhAvA44QOoNOEAaDThArBA4QBASOEBMCzhANBI4QEwLOEBMCzhATAs4QEwLOEBMCzhATAs4QEwLOEBMCzhASBA4QEwLOEA2EThAEBI4QA==", "data_start": 1070164904, "data_size": 160, "total_size": 4880 };

//import { decodeConfig } from "./config.js";
const Magic = [0x6921506f, 0x1b31506f, 0x4881606f, 0x4361606f];
// SPI_USR register flags
const SPI_USR_COMMAND = (1 << 31) >>> 0;
const SPI_USR_MISO = 1 << 28;
const SPI_USR_MOSI = 1 << 27;
const SPI_CMD_USR = 1 << 18;
const SPI_USR2_COMMAND_LEN_SHIFT = 28;
const SPI_USR_OFFS = 0x18;
//const SPI_USR1_OFFS" = 0x1c;
const SPI_USR2_OFFS = 0x20;
const SPI_W0_OFFS = 0x58;
const UART_DATE_REG_ADDR = 0x6000007c;
function registerAddress(offset) {
    return SPI_REG_BASE + offset;
}
function countOnes(value) {
    let count = 0;
    while (value) {
        value &= value - 1;
        count++;
    }
    return count;
}
class DeviceEsp32c3 extends Device {
    async connect() {
        const magic = await super.connect();
        assert(Magic.indexOf(magic) >= 0, `invalid magic number: 0x${magic.toString(16)}`, {
            magic
        });
        return magic;
    }
    async _getStub() { return Stub; }
    // @TODO: Rename? setSpiLengthRegisters
    async _setDataLengths(mosiLength, misoLength) {
        const SPI_MOSI_DLEN_OFFS = 0x24;
        const SPI_MISO_DLEN_OFFS = 0x28;
        if (mosiLength > 0) {
            await this._writeSpiRegister(SPI_MOSI_DLEN_OFFS, mosiLength - 1);
        }
        if (misoLength > 0) {
            await this._writeSpiRegister(SPI_MISO_DLEN_OFFS, misoLength - 1);
        }
    }
    // ESP8266 maybe?
    /*
    _setDataLength(mosiLength: number, misoLength: number): Promise<void> {
        const SPI_DATA_LEN_REG = SPI_USR1_REG;
        const SPI_MOSI_BITLEN_S = 17;
        const SPI_MISO_BITLEN_S = 8;
        const mosiMask = mosiBits === 0 ? 0 : mosiBits - 1;
        const misoMask = misoBits === 0 ? 0 : misoBits - 1;
        const val = (misoMask << SPI_MISO_BITLEN_S) | (mosiMask << SPI_MOSI_BITLEN_S);
        await this.writeRegister(SPI_DATA_LEN_REG, val);
    }
    */
    async _spiFlashCommand(command, data, responseBits) {
        assert(responseBits <= 32, "max SPI response length is 32 bits", {
            length: responseBits
        });
        assert(data.length <= 64, "max SPI request length is 64 bytes", {
            length: data.length
        });
        const oldSpiUsr = await this._readSpiRegister(SPI_USR_OFFS);
        const oldSpiUsr2 = await this._readSpiRegister(SPI_USR2_OFFS);
        await this._setDataLengths(data.length * 8, responseBits);
        {
            let flags = SPI_USR_COMMAND;
            if (responseBits > 0) {
                flags |= SPI_USR_MISO;
            }
            if (data.length) {
                flags |= SPI_USR_MOSI;
            }
            await this._writeSpiRegister(SPI_USR_OFFS, flags);
        }
        {
            const val = (7 << SPI_USR2_COMMAND_LEN_SHIFT) | command;
            await this._writeSpiRegister(SPI_USR2_OFFS, val);
        }
        {
            let reg = SPI_W0_OFFS;
            if (data.length === 0) {
                await this._writeSpiRegister(reg, 0);
            }
            else {
                // TODO: I think this logic is wrong; copied mostly
                // from esptool-js, but the padding looks backwards
                if (data.length % 4 != 0) {
                    const padding = new Uint8Array(data.length % 4);
                    data = concat([data, padding]);
                }
                // TODO: This also looks wrong; like it stops short?
                for (let i = 0; i < data.length - 4; i += 4) {
                    await this._writeSpiRegister(reg, fromLeBytes(data.slice(i, i + 4)));
                    reg += 4;
                }
            }
        }
        await this._writeSpiRegister(0x00, SPI_CMD_USR);
        for (let i = 0; i < 11; i++) {
            const val = (await this._readSpiRegister(0x00)) & SPI_CMD_USR;
            if (val == 0) {
                break;
            }
            assert(i < 10, "SPI command did not complete in time");
        }
        const status = await this._readSpiRegister(SPI_W0_OFFS);
        await this._writeSpiRegister(SPI_USR_OFFS, oldSpiUsr);
        await this._writeSpiRegister(SPI_USR2_OFFS, oldSpiUsr2);
        return status;
    }
    async _readSpiRegister(offset) {
        return await this._readRegister(registerAddress(offset));
    }
    async _writeSpiRegister(offset, value, mask, delayUs, delayAfterUs) {
        const address = registerAddress(offset);
        if (mask == null) {
            mask = 0xffffffff;
        }
        if (delayUs == null) {
            delayUs = 0;
        }
        const fields = [address, value, mask, delayUs];
        if (delayAfterUs) {
            fields.push(UART_DATE_REG_ADDR, 0, 0, delayAfterUs);
        }
        const packet = concat(fields.map((v) => toLeBytes(v, 4)));
        await this._command(CMD_WRITE_REG, packet);
    }
    async getDeviceInfo() {
        await this._enableStub();
        const EFUSE_BASE = 0x60008800;
        const readWord = async (numWord) => {
            const block1Addr = EFUSE_BASE + 0x044;
            const addr = block1Addr + 4 * numWord;
            return await this._readRegister(addr);
        };
        const word3 = await readWord(3);
        const word5 = await readWord(5);
        const pkgver = Number((word3 >> 21) & 0x07);
        const major = (word5 >> 24) & 0x03;
        const minor = (((word5 >> 23) & 0x01) << 3) + ((word3 >> 18) & 0x07);
        const flashId = await this._spiFlashCommand(CMDSPI_RDID, new Uint8Array(0), 24);
        let pkg = `unknown:pkg=${pkgver}`;
        if (pkgver === 0) {
            pkg = "ESP32-C3";
        }
        const size = FlashSizeMap[(flashId >> 16) & 0xff] || {};
        const flashSize = size.value || 0;
        const chip = `${pkg} (v${major}.${minor}; ${size.human || "unknown flash size"})`;
        // Make sure we are provisioned
        let version = await this._readRegister(EFUSE_BASE + 124);
        if (version === 0) {
            return {
                chip, flashSize, version,
                modelName: "[unprovisioned]", model: 0, serial: 0
            };
        }
        else if (version > 1) {
            // Versions greater than 1 include a zero count; currently
            // not used, but planned for the future
            assert(!(version & 1), `invalid version encoding; lsb-set`, {
                reason: "lsb-set", version
            });
            const zeros = (version >> 1) & 0x1f;
            version >>= 6;
            assert(zeros === (32 - 6 - countOnes(version)), `invalid version encoding; bad-zero-count`, {
                reason: "bad-zero-count", version
            });
        }
        assert(version === 1, `unsupported provision version`, { version });
        const model = await this._readRegister(EFUSE_BASE + 128);
        const serial = await this._readRegister(EFUSE_BASE + 132);
        const modelName = getModelName(model);
        return {
            chip, flashSize, modelName, model, serial, version
        };
    }
    async getMacAddress() {
        const MAC_EFUSE_REG = 0x60008800 + 0x044;
        const mac0 = BigInt(((await this._readRegister(MAC_EFUSE_REG)) & 0xffffffff) >>> 0);
        const mac1 = (await this._readRegister(MAC_EFUSE_REG + 4)) & 0xffff;
        return [
            hexlify(mac1 >> 8, 1),
            hexlify(mac1 & 0xff, 1),
            hexlify(mac0 >> 24n, 1),
            hexlify((mac0 >> 16n) & 0xffn, 1),
            hexlify((mac0 >> 8n) & 0xffn, 1),
            hexlify(mac0 & 0xffn, 1),
        ].join(":");
    }
}
const SPI_REG_BASE = 0x60002000;
const FlashSizeMap = {
    0x12: { human: "256KB", value: 256 * (1 << 10) },
    0x13: { human: "512KB", value: 512 * (1 << 10) },
    0x14: { human: "1MB", value: 1 * (1 << 20) },
    0x15: { human: "2MB", value: 2 * (1 << 20) },
    0x16: { human: "4MB", value: 4 * (1 << 20) },
    0x17: { human: "8MB", value: 8 * (1 << 20) },
    0x18: { human: "16MB", value: 16 * (1 << 20) },
};

// NVS - Non-volatile storage
//
// See: https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/storage/nvs_flash.html
const PageSize = 4096;
function getPageState(state) {
    switch (state) {
        case "empty": return 0xffffffff;
        case "active": return 0xfffffffe;
        case "full": return 0xfffffffc;
        case "erasing": return 0xfffffff8;
        case "corrupt": return 0;
    }
    throw new Error(`invalid PageState: ${state}`);
}
const PageStateMap = {
    0xffffffff: "empty", 0xfffffffe: "active", 0xfffffffc: "full",
    0xfffffff8: "erasing", 0: "corrupt"
};
function getEntryState(state) {
    switch (state) {
        case "empty": return 0x03;
        case "written": return 0x02;
        case "erased": return 0x00;
    }
    throw new Error(`invalid EntryState: ${state}`);
}
const EntryStateMap = {
    0x00: "erased", 0x02: "written", 0x03: "empty"
};
function getEntryType(type) {
    switch (type) {
        case "u8": return 0x01;
        case "i8": return 0x11;
        case "u16": return 0x02;
        case "i16": return 0x12;
        case "u32": return 0x04;
        case "i32": return 0x14;
        case "u64": return 0x08;
        case "i64": return 0x18;
        case "string": return 0x21;
        case "blob": return 0x41;
        case "blob_data": return 0x42;
        case "blob_index": return 0x48;
        case "any": return 0xff;
    }
    throw new Error(`invalid EntryType: ${type}`);
}
const EntryTypeMap = {
    0x01: "u8", 0x11: "i8", 0x02: "u16", 0x12: "i16",
    0x04: "u32", 0x14: "i32", 0x08: "u64", 0x18: "i64",
    0x21: "string", 0x41: "blob", 0x42: "blob_data",
    0x48: "blob_index", 0xff: "any"
};
function writeLe4(value, data, offset) {
    data[offset + 3] = (value >> 24) & 0xff;
    data[offset + 2] = (value >> 16) & 0xff;
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}
function writeLe2(value, data, offset) {
    data[offset + 1] = (value >> 8) & 0xff;
    data[offset + 0] = (value >> 0) & 0xff;
}
// See: https://stackoverflow.com/questions/18638900/javascript-crc32
const crc32Lookup = Uint32Array.from({ length: 256 }, (_, c) => {
    for (let _ = 0; _ < 8; _++)
        c = ((c & 1) * 0xEDB88320) ^ (c >>> 1);
    return c;
});
function computeCrc(data, crc = 0) {
    crc = ~crc;
    for (let i = 0; i < data.length; i++) {
        crc = (crc >>> 8) ^ crc32Lookup[(crc ^ data[i]) & 0xff];
    }
    return ~crc >>> 0;
}
class Header {
    #state;
    get state() { return this.#state; }
    #seqNo;
    get seqNo() { return this.#seqNo; }
    #version;
    get version() { return this.#version; }
    constructor(state, seqNo, version = 2) {
        this.#state = state;
        this.#seqNo = seqNo;
        this.#version = version;
    }
    get binary() {
        const result = new Uint8Array(32);
        result.fill(0xff);
        writeLe4(getPageState(this.state), result, 0);
        writeLe4(this.seqNo, result, 4);
        result[8] = 256 - this.version;
        if (this.state !== "empty") {
            writeLe4(computeCrc(result.slice(4, 28), 0xffffffff), result, 28);
        }
        return result;
    }
    static fromBinary(data) {
        const state = PageStateMap[fromLeBytes(data.slice(0, 4))] || "corrupt";
        const seqNo = fromLeBytes(data.slice(4, 8));
        const version = 256 - data[8];
        const checksum = data.slice(28);
        const header = new Header(state, seqNo, version);
        const computed = header.binary.slice(28);
        assert(fromLeBytes(computed) === fromLeBytes(checksum), `checksum failed`, {
            checksum, expected: computed
        });
        return header;
    }
}
class Entry {
    #ns;
    get namespace() { return this.#ns; }
    #key;
    get key() { return this.#key; }
    #type;
    get type() { return this.#type; }
    #span;
    get span() { return this.#span; }
    #index;
    get index() { return this.#index; }
    #data;
    get data() { return new Uint8Array(this.#data); }
    #state;
    get state() { return this.#state; }
    constructor(ns, key, type, span, index, data) {
        this.#ns = ns;
        this.#key = key;
        this.#type = type;
        this.#span = span;
        this.#index = index;
        this.#state = "written";
        this.#data = data;
    }
    get binary() {
        const data = new Uint8Array(32);
        data.fill(0);
        data[0] = this.namespace;
        data[1] = getEntryType(this.type);
        data[2] = this.span;
        data[3] = this.index;
        // Add the key
        data.set(toUtf8Bytes(this.key), 8);
        // Add the data
        data.set(this.data, 24);
        // Add the checksum
        const crcData = new Uint8Array(28);
        crcData.set(data.slice(0, 4), 0);
        crcData.set(data.slice(8, 32), 4);
        writeLe4(computeCrc(crcData, 0xffffffff), data, 4);
        return data;
    }
    get checksum() {
        return 0x42424242;
        //return computeCrc(this.#data.slice(xx));
    }
    erase() {
        this.#state = "erased";
    }
    static from(ns, key, value, type) {
        switch (type) {
            case "u8":
            case "i8":
            case "u16":
            case "i16":
            case "u32":
            case "i32":
            case "u64":
            case "i64":
                return new ValueEntry(ns, key, value, type);
            case "blob":
                return new BlobEntry(ns, key, value);
            //case "string":
        }
        throw new Error(`unknown ${value} ${type}`);
    }
}
class ValueEntry extends Entry {
    constructor(ns, key, value, _type) {
        if (typeof (value) !== "number") {
            throw new Error("");
        }
        const type = getEntryType(_type);
        const data = new Uint8Array(8);
        data.fill(0xff);
        for (let i = 0; i < (type & 0x0f); i++) {
            data[i] = value & 0xff;
            value >>= 8;
        }
        super(ns, key, _type, 1, 0xff, data);
    }
    get value() { return fromLeBytes(this.data); }
}
class NamespaceEntry extends ValueEntry {
    #name;
    get name() { return this.#name; }
    constructor(ns, name) {
        super(0, name, ns, "u8");
        this.#name = name;
    }
}
class BlobIndexEntry extends Entry {
    constructor(blob) {
        const data = new Uint8Array(8);
        data.fill(0xff);
        writeLe4(blob.blobData.length, data, 0);
        data[4] = 1; // Chunk count
        data[5] = 0; // Chunk start??
        super(blob.namespace, blob.key, "blob_index", 0x01, 0xff, data);
    }
}
class BlobEntry extends Entry {
    #blobData;
    get blobData() { return new Uint8Array(this.#blobData); }
    get chunks() {
        return Math.ceil(this.#blobData.length / 32);
    }
    get blobIndex() {
        return new BlobIndexEntry(this);
    }
    constructor(ns, key, data) {
        const span = Math.ceil(data.length / 32);
        const meta = new Uint8Array(8);
        meta.fill(0xff);
        writeLe2(data.length, meta, 0);
        writeLe4(computeCrc(data, 0xffffffff), meta, 4);
        super(ns, key, "blob_data", span + 1, 0, meta);
        this.#blobData = data;
    }
    _blobs() {
        const data = this.blobData;
        const blobs = [];
        for (let i = 0; i < this.span - 1; i++) {
            const blob = new Uint8Array(32);
            blob.fill(0xff);
            blob.set(data.slice(i * 32, 32 + i * 32));
            blobs.push(blob);
        }
        return blobs;
    }
    get binary() {
        const result = this._blobs();
        result.unshift(super.binary);
        result.push(this.blobIndex.binary);
        return concat(result);
    }
}
/*
export class StringEntry extends BlobEntry {
    constructor(ns: number, key: string, data: string) {
        super(ns, key, _TextEncoder.encode(data));
    }
}
*/
class Page {
    #seqNo;
    #state;
    #entries;
    get seqNo() { return this.#seqNo; }
    get state() { return this.#state; }
    get entries() { return this.#entries; }
    get header() {
        return new Header(this.state, this.#seqNo);
    }
    constructor(seqNo, state) {
        this.#seqNo = seqNo;
        this.#state = state;
        this.#entries = [];
    }
    addEntry(entry) {
        this.#state = "active";
        this.#entries.push(entry);
    }
    get binary() {
        const entries = this.entries;
        const stateBitmap = new Uint8Array(32);
        let i = 0;
        for (const entry of entries) {
            const state = getEntryState(entry.state);
            let span = entry.span;
            if (entry instanceof BlobEntry) {
                span++;
            }
            for (let j = 0; j < span; j++) {
                const slot = Math.trunc((i + j) / 4);
                const offset = ((i + j) % 4) * 2;
                stateBitmap[slot] |= state << offset;
            }
            i += span;
        }
        // Fill with empty entries (including the reserved final 4 bits)
        while (i < 128) {
            const slot = Math.trunc(i / 4);
            const offset = (i % 4) * 2;
            stateBitmap[slot] |= 0x03 << offset;
            i++;
        }
        const result = new Uint8Array(PageSize);
        result.fill(0xff);
        result.set(this.header.binary, 0);
        result.set(stateBitmap, 32);
        let offset = 64;
        for (let i = 0; i < entries.length; i++) {
            const entry = entries[i].binary;
            result.set(entry, offset);
            offset += entry.length;
        }
        return result;
    }
    static fromBinary(data) {
        const header = Header.fromBinary(data.slice(0, 32));
        if (header.state === "empty") {
            return new EmptyPage(header.seqNo);
        }
        const page = new Page(header.seqNo, header.state);
        const getEntry = (i) => {
            return data.slice((i + 2) * 32, (i + 3) * 32);
        };
        let nextNs = 1;
        const stateBitmap = data.slice(32, 64);
        for (let i = 0; i < 126; i++) {
            const slot = Math.trunc(i / 4);
            const offset = (i % 4) * 2;
            const s = EntryStateMap[(stateBitmap[slot] >> offset) & 0x03];
            const d = getEntry(i);
            if (s === "empty") {
                continue;
            }
            const ns = d[0];
            const type = EntryTypeMap[d[1]];
            const span = d[2];
            //const cunkIndex = d[3];
            //const crc = d.slice(4, 8);
            const key = extractString(d.slice(8, 24));
            const value = d.slice(24);
            let entry;
            if (ns === 0) {
                entry = new NamespaceEntry(nextNs++, key);
            }
            else if (type.match(/^[iu](8|16|32|64)$/)) {
                entry = new ValueEntry(ns, key, fromLeBytes(value), type);
            }
            else if (type === "blob_data") {
                const length = fromLeBytes(value.slice(0, 2));
                const blob = [];
                for (let j = 1; j < span; j++) {
                    blob.push(getEntry(++i));
                }
                entry = new BlobEntry(ns, key, concat(blob).slice(0, length));
                // @TODO: get this entry and make sure it matches the
                //        expected blob index
                i++;
            }
            else {
                throw new Error("unsupporte");
            }
            page.addEntry(entry);
        }
        return page;
    }
}
class EmptyPage extends Page {
    constructor(seqNo) {
        super(seqNo, "empty");
    }
    get binary() {
        const result = new Uint8Array(PageSize);
        result.fill(0xff);
        return result;
    }
}
class NVSData {
    #data;
    size;
    constructor(size) {
        this.size = size;
        this.#data = new Map();
    }
    get binary() {
        const pages = [
            new Page(0, "full"),
            new Page(1, "full"),
            new EmptyPage(2),
        ];
        // @TODO: this needs to be much more complex; currently
        //        we only support writing values to page 0
        const page = pages[0];
        let ns = 1;
        for (const [namespace, kvs] of this.#data) {
            page.addEntry(new NamespaceEntry(ns, namespace));
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                page.addEntry(Entry.from(ns, key, value, type));
            }
            ns++;
        }
        return concat(pages.map(p => p.binary));
    }
    get csv() {
        const result = ["key, type, encoding, value"];
        for (const [namespace, kvs] of this.#data) {
            result.push(`${namespace}, namespace, ,`);
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                if (value instanceof Uint8Array) {
                    result.push(`${key}, data, hex, ${hexlify(value)}`);
                }
                else {
                    result.push(`${key}, data, ${type}, ${value}`);
                }
            }
        }
        return result.join("\n");
    }
    get json() {
        const result = {};
        for (const [namespace, kvs] of this.#data) {
            const values = {};
            result[namespace] = values;
            for (const [key, _value] of kvs) {
                const { value, type } = _value;
                if (value instanceof Uint8Array) {
                    values[key] = { "type": "blob", value: hexlify(value) };
                }
                else {
                    values[key] = {
                        type: type,
                        value: value
                    };
                }
            }
        }
        return { namespaces: result };
    }
    #get(namespace, key) {
        const ns = this.#data.get(namespace);
        if (ns == null) {
            return null;
        }
        if (ns.has(key)) {
            return ns.get(key) || null;
        }
        return null;
    }
    get(namespace, key) {
        const e = this.#get(namespace, key);
        if (e) {
            return e.value;
        }
        return null;
    }
    getType(namespace, key) {
        const e = this.#get(namespace, key);
        if (e) {
            return e.type;
        }
        return null;
    }
    set(namespace, key, value, type) {
        if (type == null) {
            if (typeof (value) === "number") {
                if (value > 0) {
                    if (value > 0xffffffff) {
                        throw new Error("out of range");
                    }
                    type = "u32";
                }
                else if (value < -0x80000000) {
                    type = "i32";
                }
            }
            else if (value instanceof Uint8Array) {
                type = "blob";
            }
            else {
                throw new Error(`cannot guess: ${value}`);
            }
        }
        if (type == null) {
            throw new Error("foo");
        }
        if (!this.#data.has(namespace)) {
            this.#data.set(namespace, new Map());
        }
        this.#data.get(namespace).set(key, { type, value });
    }
    static fromValues(values) {
        throw new Error();
    }
    static fromBinary(data) {
        const nvs = new NVSData(data.length);
        let namespace = "_";
        for (let i = 0; i < data.length; i += 4096) {
            const page = Page.fromBinary(data.slice(i, i + 4096));
            for (const entry of page.entries) {
                if (entry instanceof NamespaceEntry) {
                    namespace = entry.key;
                }
                else if (entry instanceof ValueEntry) {
                    nvs.set(namespace, entry.key, entry.value, entry.type);
                }
                else if (entry instanceof BlobEntry) {
                    nvs.set(namespace, entry.key, entry.blobData, "blob");
                }
            }
        }
        return nvs;
    }
}
/*
function decode(chunk: Uint8Array): string {
    let result = "";
    for (let i = 0; i < chunk.length; i++) {
        const c = chunk[i];
        if (c >= 32 && c <= 127) {
            result += String.fromCharCode(c);
        } else {
            result += ".";
        }
    }
    return result;
}

const nvs = new NVSData(0x3000);
nvs.set("namespace", "testU8", 1, "u8");
nvs.set("namespace", "testI32", -1, "i32");
nvs.set("namespace", "testBlob", Buffer.from("00ff30313233416100ff", "hex"), "blob");
nvs.set("namespace", "testBlob2", Buffer.from("8888424242424242424242424242424242424242424242424242424242424242424242424242424288", "hex"), "blob");

function pad(v: string): string {
    while (v.length < 8) { v = "0" + v; }
    return v;
}

const expected = fs.readFileSync("obsolete/test-nvs/test0.bin");
const actual = nvs.binary;

function line(index: number, data: Uint8Array): string {
    const hex = hexlify(data).substring(2);
    const nibbles: Array<string> = [ ];
    for (let i = 0; i < 32; i += 4) {
        nibbles.push(hex.substring(i, i + 4));
    }
    return `${ pad(index.toString(16)) }: ${ nibbles.join(" ") }   ${ decode(data) }`;
}
function diff(a: string, b: string): string {
    let result = "";
    const length = Math.max(a.length, b.length);
    for (let i = 0; i < length; i++) {
        result += (a[i] === b[i]) ? " ": "^";
    }
    if (result.trim() === "") { return ""; }
    return result;
}

function dump(from: number, to: number, onlyDiff: boolean) {
    let countDiff = 0;
    for (let i = from; i < to; i += 16) {
        const a = actual.slice(i, i + 16), e = expected.slice(i, i + 16);
        const la = line(i, a), le = line(i, e);
        const ld = diff(la, le);

        if (!ld && onlyDiff) { continue; }

        if (ld && countDiff++ > 10) {
            console.log("Too many diffs; stopping");
            break;
        }

        console.log("ACTUAL:", la);
        console.log("EXPECT:", le);
        console.log("       ", diff(la, le));

    }
}

//dump(0x1000 - 32, 0x1000 + 64, false);
dump(0, actual.length, true);
*/
/*
import fs from "fs";

const nvs = NVSData.fromBinary(fs.readFileSync("./test-attest.bin"));
//console.log(nvs);
console.log(JSON.stringify(nvs.json));
*/

function isSerial(value) {
    return true;
}
class SerialPort {
    port;
    _dtr;
    _data;
    _dataLength;
    _dataStall;
    #isOpen;
    constructor(port) {
        this.port = port;
        this._dtr = false;
        this._data = [];
        this._dataLength = 0;
        this._dataStall = stall(1);
    }
    get name() { return "serial-port"; }
    async connect() {
        if (this.#isOpen) {
            return await this.#isOpen;
        }
        this.#isOpen = this.port.open({ baudRate: 115200, bufferSize: 4096 * 4 });
        await this.#isOpen;
        await stall(5);
        (async () => {
            while (this.port.readable) {
                const reader = this.port.readable.getReader();
                while (true) {
                    const { value, done } = await reader.read();
                    if (value && value.length) {
                        this._data.push(value);
                        this._dataLength += value.length;
                        //await stall(1);
                        //console.log("DATA", value, this._dataLength);
                    }
                    else {
                        this._dataStall = stall(1);
                        await this._dataStall;
                    }
                    if (done) {
                        break;
                    }
                }
                console.log("CLOSED!");
                await reader.releaseLock();
            }
        })().then(console.log, console.log);
    }
    async reset(bootMode) {
        // For info on setting vs clearing download mode:
        // See: https://github.com/espressif/arduino-esp32/issues/6762
        await this.signal({ rts: false });
        await this.signal({ dtr: false });
        await stall(100);
        if (bootMode) {
            await this.signal({ dtr: true });
            await this.signal({ rts: false });
            await stall(100);
            await this.signal({ rts: true });
            await this.signal({ dtr: false });
            await this.signal({ rts: true });
            await stall(100);
        }
        await this.signal({ rts: true });
        await this.signal({ dtr: false });
        await stall(100);
    }
    async signal(signal) {
        if (signal.dtr != null) {
            this._dtr = signal.dtr;
            await this.port.setSignals({ dataTerminalReady: this._dtr });
        }
        else if (signal.rts != null) {
            await this.port.setSignals({ requestToSend: signal.rts });
            await this.signal({ dtr: this._dtr });
        }
        else {
            await this.signal({ dtr: false });
        }
    }
    async write(data) {
        const writer = this.port.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return true;
    }
    async read() {
        await stall(100);
        const data = concat(this._data);
        this._data = [];
        this._dataLength = 0;
        return data;
    }
    async _read() {
        const result = [];
        const reader = this.port.readable.getReader();
        let timer = null;
        let cancelled = false;
        const reset = (duration) => {
            if (timer) {
                clearTimeout(timer);
            }
            timer = setTimeout(() => {
                //reader.cancel();
                cancelled = true;
                timer = null;
            }, duration);
        };
        while (true) {
            reset(5);
            const { value, done } = await reader.read();
            if (value && value.length) {
                result.push(value);
                //read += value.length;
                await stall(1);
            }
            else if (cancelled) {
                break;
            }
            else {
                await stall(3);
            }
            if (done) {
                break;
            }
        }
        if (timer) {
            clearTimeout(timer);
        }
        await reader.releaseLock();
        const data = concat(result);
        //console.log("READ", result.length, data.length, data.length ? data: 0);
        return data;
    }
    async forget() {
        await this.port.forget();
    }
    static async discover() {
        assert(("serial" in navigator) && isSerial(), `no Serial API present`, {});
        let port;
        const oldPorts = await navigator.serial.getPorts();
        if (oldPorts.length) {
            port = oldPorts[0];
        }
        else {
            port = await navigator.serial.requestPort({
                filters: [
                    { usbProductId: 4097, usbVendorId: 12346 }
                ]
            });
        }
        if (port == null) {
            throw new Error("no port selected");
        }
        return new SerialPort(port);
    }
}

export { BlobEntry, BlobIndexEntry, Device, DeviceEsp32c3, EmptyPage, Entry, Header, NVSData, NamespaceEntry, Page, Sequences, SerialPort as SerialPortBrowser, ValueEntry, slipDecode, slipEncode, version$1 as version };
//# sourceMappingURL=pixie-repl.js.map
