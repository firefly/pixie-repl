"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.IssuerAddress = void 0;
exports.getModelName = getModelName;
exports.compute = compute;
exports.verify = verify;
const ethers_1 = require("ethers");
const errors_js_1 = require("./utils/errors.js");
// Official address of the private key used by Firefly to sign devices
exports.IssuerAddress = "0x70CD34d96E58876a25445dd75f54630D99258182";
function getModelName(model) {
    if ((model >> 8) === 1) {
        return `Firefly Pixie (rev: ${model & 0xff})`;
    }
    return `[unknown model=0x${model.toString(16)}]`;
}
function compute(signer, model, serial, pubkey) {
    const message = getMessage(model, serial, pubkey);
    const attest = signer.signMessageSync(message);
    return ethers_1.Signature.from(attest).compactSerialized;
    ;
}
function verify(bytes) {
    let offset = 0;
    const readBytes = (length) => {
        const result = bytes.slice(offset, offset + length);
        offset += length;
        return result;
    };
    // Deserialize the raw attestation
    const version = readBytes(1)[0];
    if (version !== 1) {
        throw new Error(`unsupporter attestation version: ${version}`);
    }
    const nonce = (0, ethers_1.hexlify)(readBytes(16));
    const challenge = (0, ethers_1.hexlify)(readBytes(32));
    const model = toNumber(readBytes(4));
    const serial = toNumber(readBytes(4));
    const pubkeyN = readBytes(384);
    const attestProof = readBytes(64);
    const signature = readBytes(384);
    // Determine the model name
    const modelName = getModelName(model);
    // Check the attestation proof is valid
    const message = getMessage(model, serial, (0, ethers_1.hexlify)(pubkeyN));
    const recovered = (0, ethers_1.verifyMessage)(message, (0, ethers_1.hexlify)(attestProof));
    if (exports.IssuerAddress !== recovered) {
        throw new Error(`invalid attestation; address not signing authority (${recovered} != ${exports.IssuerAddress})`);
    }
    // Compute the message hash
    const check = new Uint8Array(384);
    check.set((0, ethers_1.getBytes)((0, ethers_1.sha256)(bytes.slice(0, bytes.length - 384))), 384 - 33);
    // Check the RSA maths are correct
    // See: https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
    const verify = ((BigInt((0, ethers_1.hexlify)(signature)) ** E) % BigInt((0, ethers_1.hexlify)(pubkeyN)));
    (0, errors_js_1.assert)(BigInt((0, ethers_1.hexlify)(check)) === verify, `invalid attestation; signature check failed`, {
        expected: (0, ethers_1.hexlify)(check), got: ("0x" + verify.toString(16)),
        signature: (0, ethers_1.hexlify)(signature), pubkey: (0, ethers_1.hexlify)(pubkeyN)
    });
    return { nonce, challenge, model, serial, modelName };
}
const E = BigInt(65537);
function toHex(v, length) {
    if (typeof (v) === "number") {
        v = (0, ethers_1.hexlify)((0, ethers_1.toBeArray)(v));
    }
    return (0, ethers_1.zeroPadValue)(v, length).substring(2);
}
function getMessage(model, serial, pubkey) {
    return `model=${toHex(model, 4)} serial=${toHex(serial, 4)} pubkey=${toHex(pubkey, 384)}`;
}
function toNumber(data) {
    let value = 0;
    for (let i = 0; i < data.length; i++) {
        value *= 256;
        value += data[i];
    }
    return value;
}
//# sourceMappingURL=attest.js.map