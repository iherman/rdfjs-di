import {
    KeyData, VerificationResult,
    generateProofGraph, verifyProofGraph,
    embedProofGraph, verifyEmbeddedProofGraph
} from '../../index';
import { KeyDetails }   from '../../lib/crypto_utils';
import { Cryptosuites } from '../../lib/types';


async function generateKey(suite: Cryptosuites, keyData?: KeyDetails): Promise<CryptoKeyPair> {
    const suiteToAPI = (): any => {
        switch (suite) {
            case Cryptosuites.ecdsa: return {
                name: "ECDSA",
                namedCurve: keyData?.namedCurve || "P-256",
            };
            case Cryptosuites.eddsa: return {
                name: "Ed25519"
            };
            case Cryptosuites.rsa_pss: return {
                name: "RSA-PSS",
                modulusLength: keyData?.modulusLength || 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || "SHA-256",
            };
            case Cryptosuites.rsa_ssa: return {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keyData?.modulusLength || 2048,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || "SHA-256",
            }
         }
    };

    return await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);
    // return newPair.publicKey;
}

(async () => {

    const key = await generateKey(Cryptosuites.eddsa);

    const v = {
        "public": await crypto.subtle.exportKey('jwk', key.publicKey),
        "private": await crypto.subtle.exportKey('jwk', key.privateKey),
        "controller": "https://www.ivan-herman.net/foaf#me",
        "cryptosuite": "ecdsa-rdfc-2022",
        "expires": "2055-02-24T00:00",
    };

    console.log(JSON.stringify(v,null,4));




    // const { cryptosuite, multikey } = await keyToMultikey(key);
    // console.log(await crypto.subtle.exportKey('jwk', key.privateKey))
    // console.log(await crypto.subtle.exportKey('jwk', key.publicKey))

    // console.log(`suite: ${cryptosuite}; key: ${multikey}`);

    // // const convertedKey = await multikeyToKey(multikey);
    // console.log(await crypto.subtle.exportKey('jwk', convertedKey))


    // const eddsa = await generateKey(Cryptosuites.eddsa);
    // const rsa_pss: CryptoKey = await generateKey(Cryptosuites.rsa_pss);
    // const rsa_raw = await crypto.subtle.exportKey('raw',rsa_pss);
    // const rsa_ssa = await generateKey(Cryptosuites.rsa_ssa);
})();
