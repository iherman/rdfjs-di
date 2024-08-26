import {
    Cryptosuites, KeyDetails, generateKey
} from '../../index';


(async () => {
    const keyData: KeyDetails = {
        namedCurve: "P-384"
    }
    const key = await generateKey(Cryptosuites.ecdsa, keyData);

    const jwkKeyData = {
        publicKey: await crypto.subtle.exportKey('jwk', key.publicKey),
        privateKey:  await crypto.subtle.exportKey('jwk', key.privateKey),
        controller: "https://www.ivan-herman.net/foaf#me",
        expires: "2055-02-24T00:00",
    };

    console.log(JSON.stringify(jwkKeyData, null, 4));

    // const eddsa = await generateKey(Cryptosuites.eddsa);
    // const rsa_pss: CryptoKey = await generateKey(Cryptosuites.rsa_pss);
    // const rsa_ssa = await generateKey(Cryptosuites.rsa_ssa);
})();
