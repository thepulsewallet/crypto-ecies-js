import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import * as assert from 'assert'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex} from "@safeheron/crypto-utils"
import {ECIES, AuthEnc} from ".."

describe('Elliptic Curve Encryption', function () {
  it('Encrypt a string', async function () {
      let msg = 'hello, string'
      let localAuthPriv = await Rand.randomBN(32)
      let remoteAuthPriv = await Rand.randomBN(32)
      let localAuthPub = P256.g.mul(localAuthPriv)
      let remoteAuthPub = P256.g.mul(remoteAuthPriv)
      let cypherData = await AuthEnc.encryptString(localAuthPriv, remoteAuthPub, msg)
      console.log("cypherData:", cypherData)
      let [verifySig, plain] = AuthEnc.decryptString(remoteAuthPriv, localAuthPub, cypherData)
      if(verifySig){
          console.log("plainData:", plain)
      }
      assert(verifySig)
  });

    it('Encrypt Bytes', async function () {
        let data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encryptBytes(localAuthPriv, remoteAuthPub, data)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decryptBytes(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", Hex.fromBytes(plain))
        }
        assert(verifySig)
    });

    it('Encrypt a WordArray(CryptoJSBytes)', async function () {
        let msg = 'hello, WordArray(CryptoJSBytes)'
        let msgWordArray = cryptoJS.enc.Utf8.parse(msg)
        let localAuthPriv = await Rand.randomBN(32)
        let remoteAuthPriv = await Rand.randomBN(32)
        let localAuthPub = P256.g.mul(localAuthPriv)
        let remoteAuthPub = P256.g.mul(remoteAuthPriv)
        let cypherData = await AuthEnc.encryptCryptoJSBytes(localAuthPriv, remoteAuthPub, msgWordArray)
        console.log("cypherData:", cypherData)
        let [verifySig, plain] = AuthEnc.decryptCryptoJSBytes(remoteAuthPriv, localAuthPub, cypherData)
        if(verifySig){
            console.log("plainData:", Hex.fromCryptoJSBytes(plain))
        }
        assert(verifySig)
    });
})
