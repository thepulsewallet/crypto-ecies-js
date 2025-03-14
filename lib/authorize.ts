import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@thepulsewallet/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex, UrlBase64, CryptoJSBytes} from "@safeheron/crypto-utils"
import {ECIES} from "./ecies"
import * as assert from "assert"

export namespace Authorize {
    /**
     * Sign a message
     * @param localAuthPriv
     * @param data
     * @return Promise<string>  Hex(r) + Hex(s)
     */
    export async function sign(localAuthPriv: BN, data: string | Uint8Array| CryptoJSBytes): Promise<string> {
        if (typeof data === 'string') {
            data = cryptoJS.enc.Utf8.parse(data)
        } else if (data instanceof Uint8Array) {
            data = Hex.toCryptoJSBytes(Hex.fromBytes(data))
        } else {
            // CryptoJSBytes, do nothing
        }

        // Get hash of cypher text
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(data)
        const dig = sha256.finalize()
        let hash = new BN(cryptoJS.enc.Hex.stringify(dig), 16)

        // Get signature
        //let ecdsa = new elliptic.ec(P256)
        let priv = P256.keyFromPrivate(localAuthPriv);
        let signature = P256.sign(hash, priv);
        return Hex.pad64(signature.r.toString(16))
            + Hex.pad64(signature.s.toString(16))
    }

    /**
     * Verify the signatures.
     * @returns boolean
     * @param authPub
     * @param data
     * @param sig
     */
     export function verify(authPub: any, data: string | Uint8Array| CryptoJSBytes, sig: string): boolean {
        // Get r,s
        assert(sig.length === 128)
        const r = new BN(sig.substring(0, 64), 16)
        const s = new BN(sig.substring(64), 16)
        let signature = {r: r, s: s}

        if (typeof data === 'string') {
            data = cryptoJS.enc.Utf8.parse(data)
        } else if (data instanceof Uint8Array) {
            data = Hex.toCryptoJSBytes(Hex.fromBytes(data))
        } else {
            // CryptoJSBytes, do nothing
        }
        // Get hash of cypher text
        const sha256 = cryptoJS.algo.SHA256.create()
        sha256.update(data)
        const dig = sha256.finalize()
        let hash = new BN(dig.toString(cryptoJS.enc.Hex), 16)

        // Verify signature
        return P256.verify(hash, signature, authPub)
    }
}
