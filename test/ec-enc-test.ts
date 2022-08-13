import * as BN from 'bn.js'
import * as cryptoJS from "crypto-js"
import * as elliptic from 'elliptic'
import {Rand, Prime} from "@safeheron/crypto-rand"
const P256 = elliptic.ec('p256')
import {Hex} from "@safeheron/crypto-utils"
import {ECIES, AuthEnc} from ".."
import * as assert from "assert";

describe('ECIES_CryptoJSBytes', function () {
    it('Encrypt CryptoJSBytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a"
            let data = cryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
            console.log('cypher: ', cryptoJS.enc.Hex.stringify(cypher))
            let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
            let plainHex = cryptoJS.enc.Hex.stringify(plain)
            console.log("plainHex: ", plainHex)
            assert.equal(msgHex, plainHex)
        }
    });

    it('Encrypt long CryptoJSBytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
            let data = cryptoJS.enc.Hex.parse(msgHex)
            let cypher = await ECIES.encryptCryptoJSBytes(pub, data)
            console.log("cypher: ", cryptoJS.enc.Hex.stringify(cypher))
            let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
            let plainHex = cryptoJS.enc.Hex.stringify(plain)
            console.log("plainHex: ", plainHex)
            assert.equal(msgHex, plainHex)
        }
    });

    it('EncryptwithRIV', async function () {
        let priv = new BN('542EE1CCB70AE3FEB94607D695ACDB3CA6630B7827113147FD0B509A86AEB2DB', 16)
        let pub = P256.g.mul(priv)
        let msgHex = "123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a123456789a"
        let data = cryptoJS.enc.Hex.parse(msgHex)
        let r = new BN("D76D0F6A427C860337262BA519A861ABF7C59BC419177525F83394C21DA55AE7", 16)
        let iv = Hex.toBytes("0B70C4E730C20761E397AB9EE83D7B04")
        let cypher = await ECIES.encryptCryptoJSBytesWithRIV(pub, data, r, iv)
        console.log("cypher: ", cryptoJS.enc.Hex.stringify(cypher))
        let plain = ECIES.decryptCryptoJSBytes(priv, cypher)
        let plainHex = cryptoJS.enc.Hex.stringify(plain)
        console.log("plainHex: ", plainHex)
        assert.equal(msgHex, plainHex)
    });



})

describe('ECIES_string', function () {
    it('Encrypt a string', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let msg = 'hello world'
            let cypher = await ECIES.encryptString(pub, msg)
            console.log("cypher: ", Hex.fromBytes(cypher))
            let plain = ECIES.decryptString(priv, cypher)
            console.log("plain: ", plain)
            assert.equal(msg, plain)
        }
    });
})

describe('ECIES_Bytes', function () {
    it('Encrypt Bytes', async function () {
        for(let i = 0; i < 100; i ++){
            let priv = await Rand.randomBN(32)
            console.log('priv: ', priv.toString(16))
            let pub = P256.g.mul(priv)
            let data = new Uint8Array([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
            let cypher = await ECIES.encryptBytes(pub, data)
            console.log('cypher: ', Hex.fromBytes(cypher))
            let plain = ECIES.decryptBytes(priv, cypher)
            console.log("plain data: ", Hex.fromBytes(plain))
            assert.equal(data.length, plain.length)
            for(let i = 0; i < data.length; i++){
                assert.equal(data.at(i), plain.at(i))
            }
        }
    })
})

describe('Encrypt_And_Verify', function () {
    it('Encrypt_And_Verify', async function () {
        console.log("verify c++ enc: ")
        //plainStr:"01234"
        let priv = new BN("A1FC6B4FEC902D1421113909D23260E50A730F47ADB164DC9CC7DEF0E0B54B16", 16)
        let cypherBytes = Hex.toBytes("04ddd6f79beba045678b142462a929de4d4e96581fe08e43c8ab54118dff96acaf037526b25d36e225a462c56dedbe958c9c19b1d622e3556b708ec5a52983044b8e6bf1960fe3d17b53a2aa50c665f8309731689eb56a6bd7ad0a69b122e1637321b4cc7eecee7980a01847e1462b84a875e43110b1aa9d09a21e4cdefdb53e2e0371c665fbb337b8e034be69f1fed2684964728d6ce4533e7c5852e971800ed7")
        let plainBytes =  ECIES.decryptBytes(priv, cypherBytes)
        let plainStr = ECIES.decryptString(priv, cypherBytes)
        console.log("plainHex: ",Hex.fromBytes(plainBytes))
        console.log("plainStr: ",plainStr)

        //plainBytes:[0, 1, 2, 3, 4]
        priv = new BN("D056CFE81ECDB3EAFA58BD7922F7AFD404523D66BC5F2ADE637FA31EE3B690AA", 16)
        cypherBytes = Hex.toBytes("04aa102be2ab983fb59d240121306f736a5cd71c38fe5366a43ee0d72743f73b1fb989565c37b2be1a740a49062bb13a33fa9f4b39e25e97dfe8073e9e6e3d3fb6f9442df3aa8a59a4f3ae772bf56b557b8c8adc92852e8a6f0140d242374cfac998fe5bfcd879a4848ce24e3988ef1c40cfa197a004808ab7277a2f5c33b34077e752554b88afe5f18529b764ef8d7cd7fbcb97ae77e391590e6b90cbb636a4d5")
        plainBytes =  ECIES.decryptBytes(priv, cypherBytes)
        plainStr = ECIES.decryptString(priv, cypherBytes)
        console.log("plainHex: ",Hex.fromBytes(plainBytes))
        //utf8
        console.log("plainStr: ",plainStr)


        console.log("encode and verify str: ")
        let message = "hello world"
        priv = await Rand.randomBN(32)
        console.log("priv: ", priv.toString(16))
        let pub = P256.g.mul(priv)
        cypherBytes = await ECIES.encryptString(pub, message)
        console.log("CypherBytes: ", Hex.fromBytes(cypherBytes))
        plainStr =  ECIES.decryptString(priv, cypherBytes)
        console.log("plainStr: ", plainStr)
        plainBytes =  ECIES.decryptBytes(priv, cypherBytes)
        console.log("plainHex: ", Hex.fromBytes(plainBytes))

        console.log("encode and verify bytes: ")
        let messageBytes = new Uint8Array([0, 1, 2, 3, 4])
        priv = await Rand.randomBN(32)
        console.log("priv: ", priv.toString(16))
        pub = P256.g.mul(priv)
        cypherBytes = await ECIES.encryptBytes(pub, messageBytes)
        console.log("cypherBytes: ", Hex.fromBytes(cypherBytes))
        plainBytes = ECIES.decryptBytes(priv, cypherBytes)
        plainStr = ECIES.decryptString(priv, cypherBytes)
        console.log("plainStr: ", plainStr)
        for(let i = 0; i < plainBytes.length; i++) {
            console.log(plainBytes[i], " ")
        }
        console.log("plainHex: ", Hex.fromBytes(plainBytes))
    })
})