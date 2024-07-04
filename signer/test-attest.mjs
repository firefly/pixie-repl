import {
    hexlify, sha256, verifyMessage, zeroPadValue
} from "ethers";


export const address = "0x70CD34d96E58876a25445dd75f54630D99258182";

export function getModel(model) {
    if ((model >> 8) === 1) {
        return `Firefly Pixie (DevKit; rev.${ model & 0xff })`;
    }
    return `unknown model 0x${ model.toString(hex) }`;
}

export function attest(proof) {
    let offset = 0;

    const getBytes = function(_length) {
        const start = offset * 2;
        const end = start + _length * 2;
        offset += _length
        return "0x" + proof.substring(start, end);
    };

    const version = getBytes(1);
    const nonceRand = getBytes(7);
    const nonce = getBytes(8);
    const model = getBytes(4);
    const serial = getBytes(4);
    const pubkeyN = getBytes(384);
    const attestation = getBytes(64);
    const sig = getBytes(384);

    // Check the version is supported
    if (version !== "0x01") {
        throw new Error(`invalid attestation; unknown version ${ version }`);
    }

    // Check the attestation is correct for the model and serial
    const message = `model=${ toHex(model, 4) } serial=${ toHex(serial, 4) } pubkey=${ toHex(pubkeyN, 384) }`;
    if (address !== verifyMessage(message, attestation)) {
        throw new Error("invalid attestation; address not signing authority");
    }

    // Compute the RSA challenge hash
    const hash = sha256("0x" + proof.substring(0, proof.length - 2 * 384));

    // Check the RSA maths are correct
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


console.log(attest("011d41bd87370bef1234567890abcdef00000105000000098d71979cd21f0f0b9181244f80b08688dae08e83baca3100e1bad2e0c0602ed77b5e3cd0c16a6f76035551820b227ee2cee989d9506972954e191de09c96391c4ba78fcfd07cbd2de6057d84932d2e24c335707398c2a37552497aa369a0999b41e12cca9e1f9fc6d103d04279349e03d815368756eb50b68564926a38a467714d5e45cd144638764ce66f069e3173368b200e705968e9406ca07cc189f53b4afeb6d35084c59a65199ec903a128f3826bde9344ca00a695c4a38733c900be749395378d7c4c0505b6b86e80fb14cc06841d68dfefbc7debc97cb2a23866e20faae43fc71b16d8a4fcc9c1325dd07f591c6adcd2379a38a05b1254ce6e6a4f99806747def565e7171317e30b1e8159a9f64f216ea47a10598721bd9d4abb881d3f08eac75e82ac824fe426521d8a7e37d3fc0088680ff237f8351cdc71557ec6cad537312fff699a46726252a42afa455fb0497f78335f45367f09d469b07ab2c13b1d1e830cf1f6ba13205006415a8b5e60ebe0830c24248d5dd74d4a5401afd657a4924bbf37a45be901ddc54ecdd12401a2651b34959ee438c416ffa9ae774e77e822737d4f6f5194d5109511c5c119bd14a8591d1c67323d1e5c9a8376713844c6128321b5bd87750801a2d46c47a5c26c30734e5a17d944044b29c134012d34cc076cf03f05644782a7406735688e58474219b60962f21fdc6d6d70403c14cbc0cc5f7155b1cc101a95e0a7ea881b18177eba50c6b77406a198305d4ee75c8b80f35e3a0a9e723cc8e74a05c65c5b68368df30f7d6ae94b374a946a8dccbe00af7c960da5251891eec800ffe14e017437fd2f8296d2e8d941636f1758591f30273e877a394a95104b8bbece0291875153adbb9a9bb904d906f9823a5b63ecfc80067dca7806836c2e66ae1c67c66dcfe730e373ef3e865c97afff4e1cb4340e23efc05caab514f8aac724d21b1671c89e1909bd9bb8e81656e831652dede5bfe0b34c75db92f82d07d0254d48375d910b947159ad633050e0fff6b04ae2fd57f25aae8d835061ce06fdc4398e977b74991370153cbb1e63b720b3dabfc0de4dda43fb820ec45b142367935bfb67100e2049a1aa5871789557d797586897f4fa9349e06e2686dfd64660fd9517d6739bb39be7f4ed5a1e620d70e157f8fd"));
