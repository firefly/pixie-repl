import {
    Signature,
    getBytes, hexlify, sha256, toBeArray, verifyMessage, zeroPadValue
} from "ethers";

import type { BaseWallet } from "ethers";

export const IssuerAddress = "0x70CD34d96E58876a25445dd75f54630D99258182";

export interface AttestedDeviceInfo {
    nonce: string;
    challenge: string;

    modelNumber: number;
    modelName: string;
    serialNumber: number;
}

export function getModelName(modelNumber: number) {
    if ((modelNumber >> 8) === 1) {
        return `Firefly Pixie (rev: ${ modelNumber & 0xff })`;
    }
    return `[unknown model=0x${ modelNumber.toString(16) }]`;
}

export function compute(signer: BaseWallet, modelNumber: number, serialNumber: number, pubkey: string) {
    const message = getMessage(modelNumber, serialNumber, pubkey);
    const attest = signer.signMessageSync(message);
    return Signature.from(attest).compactSerialized;;
}

export function verify(attest: string): AttestedDeviceInfo {
    const bytes = getBytes(attest.startsWith("0x") ? attest: ("0x" + attest));

    let offset = 0;
    const readBytes = (length: number) => {
        const result = bytes.slice(offset, offset + length);
        offset += length;
        return result;
    };

    // Deserialize the raw attestation
    const version = readBytes(1)[0];
    if (version !== 1) { throw new Error(`unsupporter attestation version: ${ version }`); }
    const nonce = hexlify(readBytes(16));
    const challenge = hexlify(readBytes(32));
    const modelNumber = toNumber(readBytes(4));
    const serialNumber = toNumber(readBytes(4));
    const pubkeyN = readBytes(384);
    const attestProof = readBytes(64);
    const signature = readBytes(384);

    // Determine the model name
    const modelName = getModelName(modelNumber);

    // Check the attestation proof is valid
    const message = getMessage(modelNumber, serialNumber, hexlify(pubkeyN));
    const recovered = verifyMessage(message, hexlify(attestProof));
    if (IssuerAddress !== recovered) {
        throw new Error(`invalid attestation; address not signing authority (${ recovered } != ${ IssuerAddress })`);
    }

    // Compute the message hash
    const check = new Uint8Array(384);
    check.fill(0x42);
    check.set(getBytes(sha256(bytes.slice(0, bytes.length - 384))));

    // Check the RSA maths are correct
    // See: https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
    const verify = ((BigInt(hexlify(signature)) ** E) % BigInt(hexlify(pubkeyN)));
    if (BigInt(hexlify(check)) !== verify) {
        throw new Error("invalid attestion; signature did not match");
    }

    return { nonce, challenge, modelNumber, serialNumber, modelName };
}


const E = BigInt(65537);

function toHex(v: number | string, length: number): string {
    if (typeof(v) === "number") { v = hexlify(toBeArray(v)); }
    return zeroPadValue(v, length).substring(2);
}

function getMessage(model: number, serial: number, pubkey: string) {
    return `model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex(pubkey, 384) }`
}

function toNumber(data: Uint8Array): number {
    let value = 0;
    for (let i = 0; i < data.length; i++) {
        value *= 256;
        value += data[i];
    }
    return value;
}
