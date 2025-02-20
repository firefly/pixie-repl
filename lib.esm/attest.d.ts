import type { BaseWallet } from "ethers";
export declare const IssuerAddress = "0x70CD34d96E58876a25445dd75f54630D99258182";
export interface AttestedDeviceInfo {
    nonce: string;
    challenge: string;
    model: number;
    modelName: string;
    serial: number;
}
export declare function getModelName(model: number): string;
export declare function compute(signer: BaseWallet, model: number, serial: number, pubkey: string): string;
export declare function verify(bytes: Uint8Array): AttestedDeviceInfo;
//# sourceMappingURL=attest.d.ts.map