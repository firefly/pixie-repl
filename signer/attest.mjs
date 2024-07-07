import {
    getBytes, hexlify, sha256, verifyMessage, zeroPadValue
} from "ethers";


export const address = "0x70CD34d96E58876a25445dd75f54630D99258182";

export function getModel(model) {
    if ((model >> 8) === 1) {
        return `Firefly Pixie (DevKit; rev.${ model & 0xff })`;
    }
    return `unknown model 0x${ model.toString(hex) }`;
}

function getMessage(model, serial, pubkey) {
    return `model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex(pubkey, 384) }`
    //`model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex(pubkeyN, 384) }`;
}

export function compute(model, serial, pubkey) {
    const message = getMessage(model, serial, pubkey);
    log.log({ message });

    const attest = wallet.signMessageSync(message);
    log.log({ attest });
    log.set("attest", attest);

    return Signature.from(attest).compactSerialized.substring(2);
}

export function verify(_proof) {
    const proof = getBytes(_proof);

    let offset = 0;
    const readBytes = function(length) {
        const result = hexlify(proof.slice(offset, offset + length));
        offset += length;
        return result;
    };

    const version = readBytes(1);
    const nonceRand = readBytes(7);
    const nonce = readBytes(8);
    const model = readBytes(4);
    const serial = readBytes(4);
    const pubkeyN = readBytes(384);
    const attestation = readBytes(64);
    const sig = readBytes(384);

    // Check the version is supported
    if (version !== "0x01") {
        throw new Error(`invalid attestation; unknown version ${ version }`);
    }

    // Check the attestation is correct for the model and serial
    const message = getMessage(model, serial, pubkeyN);
    const recovered = verifyMessage(message, attestation);
    if (address !== recovered) {
        throw new Error(`invalid attestation; address not signing authority (${ recovered } != ${ address })`);
    }

    // Compute the RSA challenge hash
    const challenge = proof.slice(0, proof.length - 384);
    const hash = sha256(challenge);

    // Check the RSA maths are correct
    // See: https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples
    const verify = ((BigInt(sig) ** E) % BigInt(pubkeyN));
    if (BigInt(hash) !== verify) {
        throw new Error("invalid attestion; signature did not match");
    }

    return {
        authority: address,
        model: parseInt(model),
        modelName: getModel(model),
        serial: parseInt(serial),
        nonce
    };
}

const E = BigInt(65537);

function toHex(v, length) {
    if (typeof(v) === "number") { v = hexlify(toBeArray(v)); }
    return zeroPadValue(v, length).substring(2);
}

/*
console.log(verify("01371cd374871ac70123456789abcdef000001050000000abc08e652d2086d1a2e1a2ad4fb62a01a37e5e7c3942bd6ab1e9dced20e4a59cd55664e392d9cd08e395c902e064b94b6e50466af384c32681214a630f96edaa120090ff652c6030d941bc86d519c6ee6829d8742b5603dbd1ed84bf1577fa19a8259f9ecc2bf17cc4dd8ceb08b551c56df99fbb9efbaca0fa2003c1c00828ceed768f3fe92408e22ed94c2d690f363e81974665aed622ac0baa8b92b6c03f92c47435df683a0d8346d2e6caad0ad04899091d207c2295eb0c533a677faf2261e7d55f179c7b8fefd1aa69c90dc94f920f946548afcf69c64551af02e46a150d11f6c68f7fb6d5ec3eb41ab72a6fa13db842a2f561f3d70064ed38e093a55c57db7cc4e8bcef7015791482c0628fa7637106e43d55067bf18301d18c861d1ee1278442f3a7f6633cf64ba863235a738b31471c2f38c8796fe3227ddff8de534423e914c652d6a35b97ea4a69367d96d03662549a7eb768a8c34d307ebf36de35746691366623b5834b549aaa62d3e9e7b8b538d2003b71c1909e09daa44753ec36e03af0670294a672070143ee8a7554ed32b7bac28877f7540eed73b5880653c9277f64eeac7b61cd66d6509403b573c9c379f8df7a7979e009eb5cac52728aa94de810f755091c4e416e803734820a38a588675963dea5137ef57c18ab55d4cda71478ecb81dc5a29f3c7bb45023a79c5f51039e29240e2469ccdf133eeb5d4d22371e38177dfa3011a224622db8d060b93dc26198cbde16ded710356cd11b5a90a7032ab9c885f066645f2afe1a9987a30fe7a143638d408307b2db4bd4663872dbaebc11652e4d047fbfef292563f377d1cffc805ed48464d679db5917e5e57cf4d80f1f86f3444a02a572b023a78351e97dd745c991996627b0641fcb54ae0ab33be97e1c31ea615a6092da5375bb5bd61a177c6d4cda0c6f0c38d0b9b25d3eefb60ee48ddd38bd15073d4da28c5c3d2be65e0fb5002c5fca21ebf0fe22f83567777e08d80a42083943c704c498de2fe3cfc1d22fd676ab676a9a1c33a90b852b3d4c6bbf35a2e35481d29cdf5ab373d6f71b52e35e8537e989b25559432eb9ff7888d673279fa1abc4e049e1e702ece77c807402226cc62ff4077e78168f5172246ceb0031fddff525ea1a49669d3dc8f1ceec32235b1901137898648a9"));
*/
