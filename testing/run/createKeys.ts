import {
    KeyData, VerificationResult,
    generateProofGraph, verifyProofGraph,
    embedProofGraph, verifyEmbeddedProofGraph
} from '../../index';
import { KeyDetails }                   from '../../lib/crypto_utils';
import { Cryptosuites }                 from '../../lib/types';
import { keyToMultikey, multikeyToKey } from '../../lib/multikey';


async function generateKey(suite: Cryptosuites, keyData?: KeyDetails): Promise<CryptoKey> {
    const suiteToAPI = (): any => {
        switch (suite) {
            case Cryptosuites.ecdsa: return {
                name: "ECDSA",
                namedCurve: keyData?.namedCurve || "P-256",
            };
            case Cryptosuites.eddsa: return {
                name: "Ed25519"
            };
         }
    };

    const newPair = await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);
    return newPair.publicKey;
}




(async () => {
    const key = await generateKey(Cryptosuites.ecdsa, {namedCurve: "P-384"});
    const { cryptosuite, multikey } = await keyToMultikey(key);
    console.log(await crypto.subtle.exportKey('jwk', key))
    console.log(`suite: ${cryptosuite}; key: ${multikey}`);

    const convertedKey = await multikeyToKey(multikey);
    console.log(await crypto.subtle.exportKey('jwk', convertedKey))


    // const eddsa = await generateKey(Cryptosuites.eddsa);
    // const rsa_pss = await generateKey(Cryptosuites.rsa_pss);
    // const rsa_ssa = await generateKey(Cryptosuites.rsa_ssa);

})();
