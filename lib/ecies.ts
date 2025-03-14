import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@thepulsewallet/crypto-rand"
import {Hex, CryptoJSBytes} from "@safeheron/crypto-utils"

const P256 = elliptic.ec('p256')

export namespace ECIES {
    /**
     * Encryption.
     * @param pub. ECC Public Key
     * @param plainBytes
     * @param r The private key
     * @param ivWordArray AES encrypt iv
     * @returns {CryptoJSBytes}: [gR.encode()||aesCypher||macCypher||ivWordArray]
     * @private
     */
    function _encryptCryptoJSBytesWithRIV(pub: any, plainBytes: CryptoJSBytes, r: BN, ivWordArray: CryptoJSBytes): CryptoJSBytes {
        // get share Key
        let gR = P256.g.mul(r)
        let keyPoint = pub.mul(r)

        //generate seed
        let seed = cryptoJS.lib.WordArray.create();

        let keyPointX = keyPoint.getX()
        let gREncode = gR.encode()

        seed.concat(cryptoJS.enc.Hex.parse(Hex.padLength(Hex.fromBytes(gREncode), 65 * 2)))
        seed.concat(cryptoJS.enc.Hex.parse(Hex.pad64(keyPointX.toString(16))))

        //generate derivation key
        let symmKeyBytes = 256 / 8
        let macKeyBytes = 1024 / 8
        let digestBytes = 512 / 8

        let derivationKey = ''
        let totalBytes = symmKeyBytes + macKeyBytes
        for (let i = 1; i <= (totalBytes +  digestBytes - 1)/ digestBytes; i++) {
            let sha512 = cryptoJS.algo.SHA512.create();
            let iWordArray = cryptoJS.enc.Hex.parse(Hex.pad8(i.toString(16)))
            sha512.update(seed)
            sha512.update(iWordArray)
            let digest = sha512.finalize();
            derivationKey += Hex.padLength(digest.toString(cryptoJS.enc.Hex), 128)
        }
        derivationKey = derivationKey.substring(0, totalBytes*2)

        let symmKey = derivationKey.substring(0, symmKeyBytes * 2)
        let macKey = derivationKey.substring(symmKeyBytes * 2, derivationKey.length)

        // encrypt, AES256, CBC default
        let aesEncryptor = cryptoJS.algo.AES.createEncryptor(cryptoJS.enc.Hex.parse(symmKey), {iv: ivWordArray})
        let cypher1 = aesEncryptor.process(plainBytes)
        let cypher2 = aesEncryptor.finalize()
        let aesCypher = cypher1.concat(cypher2)

        //cal mac for cypher
        let macIVLen = "0"
        let hmac_sha512 = cryptoJS.algo.HMAC.create(cryptoJS.algo.SHA512, cryptoJS.enc.Hex.parse(macKey));
        hmac_sha512.update(aesCypher);
        hmac_sha512.update(cryptoJS.enc.Hex.parse(Hex.pad16(macIVLen)))
        let macCypher = hmac_sha512.finalize();

        let gREncodeWordArray = cryptoJS.enc.Hex.parse(Hex.padLength(Hex.fromBytes(gREncode), 65 * 2));

        return gREncodeWordArray.concat(aesCypher).concat(macCypher).concat(ivWordArray)
    }

    /**
     * Decryption
     * @param gR. Curve.g^R
     * @param priv.
     * @param ivWordArray AES encrypt iv
     * @param aesCypher
     * @param macCypher
     * @returns {CryptoJSBytes} PLain
     * @private
     */
    function _decryptCryptoJSBytes(gR: any, priv: BN, ivWordArray: CryptoJSBytes, aesCypher: CryptoJSBytes, macCypher: CryptoJSBytes): CryptoJSBytes {
        // get share key
        let keyPoint = gR.mul(priv)

        //generate seed
        let keyPointX = keyPoint.getX()
        let gREncode = gR.encode()

        let seed = cryptoJS.lib.WordArray.create()
        seed.concat(cryptoJS.enc.Hex.parse(Hex.padLength(Hex.fromBytes(gREncode), 65 * 2)))
        seed.concat(cryptoJS.enc.Hex.parse(Hex.pad64(keyPointX.toString(16))))

        //generate derivation key
        let symmKeyBytes = 256 / 8
        let macKeyBytes = 1024 / 8
        let digestBytes = 512 / 8

        let derivationKey = ''
        let totalBytes = symmKeyBytes + macKeyBytes
        for (let i = 1; i <= (totalBytes + digestBytes - 1)/ digestBytes; i++) {
            let sha512 = cryptoJS.algo.SHA512.create();
            let iWordArray = cryptoJS.enc.Hex.parse(Hex.pad8(i.toString(16)))
            sha512.update(seed)
            sha512.update(iWordArray)
            let digest = sha512.finalize();
            derivationKey += Hex.padLength(digest.toString(cryptoJS.enc.Hex), 128)
        }
        derivationKey = derivationKey.substring(0, totalBytes*2)

        let symmKey = derivationKey.substring(0, symmKeyBytes * 2)
        let macKey = derivationKey.substring(symmKeyBytes * 2, derivationKey.length)

        //cal mac for cypher
        let macIVLen = "0"
        let hmac_sha512 = cryptoJS.algo.HMAC.create(cryptoJS.algo.SHA512, cryptoJS.enc.Hex.parse(macKey));
        hmac_sha512.update(aesCypher);
        hmac_sha512.update(cryptoJS.enc.Hex.parse(Hex.pad16(macIVLen)))
        let verifyMacCypher = hmac_sha512.finalize();
        if (verifyMacCypher.toString(cryptoJS.enc.Hex) != macCypher.toString(cryptoJS.enc.Hex)) {
            throw 'Mac verify error: verifyMacCypher != macCypher'
        }

        // decrypt
        let aesDecryptor = cryptoJS.algo.AES.createDecryptor(cryptoJS.enc.Hex.parse(symmKey), {iv: ivWordArray});
        let plainPart1 = aesDecryptor.process(aesCypher);
        let plainPart2 = aesDecryptor.finalize();
        return plainPart1.concat(plainPart2)
    }

    /**
     * Encrypt CryptoJSBytes to cypher CryptoJSBytes.
     * @param pub. ECC Public Key
     * @param plainCryptoJSBytes.
     * @returns {Promise<CryptoJSBytes>}
     */
    export async function encryptCryptoJSBytes(pub: any, plainCryptoJSBytes:  CryptoJSBytes): Promise<CryptoJSBytes> {
        const r = await Rand.randomBNLt(P256.n)
        let iv = await Rand.randomBytes(16)
        const ivCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(iv))
        return await _encryptCryptoJSBytesWithRIV(pub, plainCryptoJSBytes, r, ivCryptoJSBytes)

    }

    /**
     * Encrypt CryptoJSBytes to cypher CryptoJSBytes with specified random IV.
     * @param pub. ECC Public Key
     * @param plainCryptoJSBytes.
     * @param r. BN
     * @param iv. Uint8Array
     * @returns {Promise<CryptoJSBytes>}
     */
    export async function encryptCryptoJSBytesWithRIV(pub: any, plainCryptoJSBytes: CryptoJSBytes, r: BN, iv: Uint8Array): Promise<CryptoJSBytes> {
        const ivCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(iv))
        return await _encryptCryptoJSBytesWithRIV(pub, plainCryptoJSBytes, r, ivCryptoJSBytes)
    }

    /**
     * Decrypt CryptoJSBytes to plain CryptoBytes.
     * @param priv. Private Key.
     * @param cypherCryptoJSBytes
     * @returns {CryptoJSBytes} Plain
     */
    export function decryptCryptoJSBytes(priv: BN, cypherCryptoJSBytes: CryptoJSBytes): CryptoJSBytes {
        // Split cypher data

        let cypherStr = cryptoJS.enc.Hex.stringify(cypherCryptoJSBytes)
        let start = 0
        let prefix = cypherStr.substring(start, start + 2)
        if(prefix != "04") {
            throw 'prefix error'
        }
        start += 2
        let gR_x = cypherStr.substring(start, start + 64)
        start += 64
        let gR_y = cypherStr.substring(start, start + 64)
        start += 64

        let aesCypher = cypherStr.substring(start, cypherStr.length - 128 - 32)
        let macCypher = cypherStr.substring(cypherStr.length - 128 - 32, cypherStr.length - 32)
        let iv = cypherStr.substring(cypherStr.length - 32, cypherStr.length)


        let gR = P256.curve.point(gR_x, gR_y)
        let ivWordArray = cryptoJS.enc.Hex.parse(iv)

        aesCypher = cryptoJS.enc.Hex.parse(aesCypher)
        macCypher = cryptoJS.enc.Hex.parse(macCypher)
        return _decryptCryptoJSBytes(gR, priv, ivWordArray, aesCypher, macCypher)
    }

    /**
     * Encrypt bytes to cypher bytes.
     * @param pub. ECC Public Key
     * @param plainBytes.
     * @returns {Promise<Uint8Array>} cypher bytes.
     */
    export async function encryptBytes(pub: any, plainBytes: Uint8Array): Promise<Uint8Array>{
        let plainCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(plainBytes))
        let cypherCryptoJSBytes = await encryptCryptoJSBytes(pub, plainCryptoJSBytes)
        return Hex.toBytes(Hex.fromCryptoJSBytes(cypherCryptoJSBytes))
    }

    /**
     * Decrypt cypher bytes to plain bytes.
     * @param priv. Private Key.
     * @param cypherBytes
     * @returns {Uint8Array}
     */
    export function decryptBytes(priv: BN, cypherBytes: Uint8Array): Uint8Array {
        let cypherCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(cypherBytes))
        let plainCryptoJSBytes = decryptCryptoJSBytes(priv, cypherCryptoJSBytes)
        return Hex.toBytes(Hex.fromCryptoJSBytes(plainCryptoJSBytes))
    }

    /**
     * Encrypt a string to cypher bytes.
     * @param pub. ECC Public Key
     * @param plainStr
     * @returns {Promise<Uint8Array>}
     */
    export async function encryptString(pub:any, plainStr: string): Promise<Uint8Array>{
        let  plainCryptoJSBytes = cryptoJS.enc.Utf8.parse(plainStr)
        let cypherCryptoJSBytes = await encryptCryptoJSBytes(pub, plainCryptoJSBytes)
        return Hex.toBytes(Hex.fromCryptoJSBytes(cypherCryptoJSBytes))
    }

    /**
     * Decrypt bytes to plain bytes.
     * @param priv. Private Key.
     * @param cypherBytes
     * @returns {string} plain
     */
    export function decryptString(priv: BN, cypherBytes: Uint8Array): string {
        let cypherCryptoJSBytes = Hex.toCryptoJSBytes(Hex.fromBytes(cypherBytes))
        let plainCryptoJSBytes = decryptCryptoJSBytes(priv, cypherCryptoJSBytes)
        return cryptoJS.enc.Utf8.stringify(plainCryptoJSBytes)
    }
}
