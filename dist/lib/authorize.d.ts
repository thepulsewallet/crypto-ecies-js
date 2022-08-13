import * as BN from 'bn.js';
import { CryptoJSBytes } from "@safeheron/crypto-utils";
export declare namespace Authorize {
    /**
     * Sign a message
     * @param localAuthPriv
     * @param data
     * @return Promise<string>  Hex(r) + Hex(s)
     */
    function sign(localAuthPriv: BN, data: string | Uint8Array | CryptoJSBytes): Promise<string>;
    /**
     * Verify the signatures.
     * @returns boolean
     * @param authPub
     * @param data
     * @param sig
     */
    function verify(authPub: any, data: string | Uint8Array | CryptoJSBytes, sig: string): boolean;
}
