import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import * as assert from 'assert'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {ECIES, AuthEnc, Authorize} from ".."

describe('Authorize', function () {
    it('Signature Test', async function () {
        let msg = 'hello'
        msg = cryptoJS.enc.Utf8.parse(msg)

        // local author key pair
        let authPriv = await Rand.randomBN(32)
        let authPub = P256.g.mul(authPriv)

        let signature = await Authorize.sign(authPriv, msg)
        console.log('sig:', signature)
        console.log('\n\n')
        let verifySig = Authorize.verify(authPub, msg, signature)
        assert(verifySig)
    });
})
