import { KeyData } from '../../index';
import { KeyDetails }   from '../../lib/crypto_utils';
import { Cryptosuites } from '../../lib/types';
import { get_keys } from './keys';



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

    const keyPairs: KeyData[] = await get_keys();

    console.log(keyPairs);
    
    for (const key of keyPairs) {
        console.log("----");
        console.log(JSON.stringify(key.publicKey.algorithm, null, 4));
        console.log(JSON.stringify(key.privateKey.algorithm, null, 4));
    }

    // const ecdsa384 = await generateKey(Cryptosuites.ecdsa, { namedCurve: "P-384" });
    // const ecdsa256 = await generateKey(Cryptosuites.ecdsa);
    // const eddsa    = await generateKey(Cryptosuites.eddsa);
    // const rsa_pss  = await generateKey(Cryptosuites.rsa_pss);
    // const rsa_ssa  = await generateKey(Cryptosuites.rsa_ssa);

    // for (const k of [ecdsa256, ecdsa384, eddsa, rsa_pss, rsa_ssa]) {
    //     const alg = k.publicKey.algorithm;
    //     console.log(JSON.stringify(alg,null,4))
    //     switch (alg.name) {
    //         case 'ECDSA': {
    //             if ((alg as EcKeyAlgorithm)?.namedCurve === "P-384") {
    //                 console.log("ecdsa; P-384");
    //             } else {
    //                 console.log("ecdsa; P-256");
    //             }
    //             break;
    //         }
    //         case 'Ed25519': {
    //             console.log("EDDSA");
    //             break;
    //         }
    //         default: {
    //             console.log("some rsa")
    //         }
    //     }
    // }




    // // const key = await generateKey(Cryptosuites.eddsa);
    // const key = await generateKey(Cryptosuites.ecdsa, { namedCurve: "P-384" });

    // const v = {
    //     "public": await crypto.subtle.exportKey('jwk', key.publicKey),
    //     "private": await crypto.subtle.exportKey('jwk', key.privateKey),
    //     "controller": "https://www.ivan-herman.net/foaf#me",
    //     "cryptosuite": "ecdsa-rdfc-2022",
    //     "expires": "2055-02-24T00:00",
    // };

    // console.log(JSON.stringify(v, null, 4));


    // const eddsa = await generateKey(Cryptosuites.eddsa);
    // const rsa_pss: CryptoKey = await generateKey(Cryptosuites.rsa_pss);
    // const rsa_raw = await crypto.subtle.exportKey('raw',rsa_pss);
    // const rsa_ssa = await generateKey(Cryptosuites.rsa_ssa);
})();
