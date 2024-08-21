/**
 * Handling the Multikey encoding of ECDSA and EDDSA keys.
 * 
 * Put into a separate file for an easier maintenance; not meant
 * to be part of the external API.
 * They are not exported (via `index.ts`) to
 * package users.
 * 
 * @packageDocumentation
 */

import * as mkwc                          from "../../../VC/multikey-webcrypto";
export { multikeyToJWK as multikeyToKey } from "../../../VC/multikey-webcrypto";

import { Cryptosuites } from './types';

/**
 * Convert a public ECDSA/ECDDA key into multikey.
 * 
 * Most of the work is done in the external, `multikey-webcrypto` package; the only
 * additional action is to establish the exact cryptosuite value.
 * 
 * @param key Public key
 * @returns a predefined cryptosuite ID, and the multikey encoded key
 * @throws the Key type is not available in multikey
 */
export function keyToMultikey(key: JsonWebKey): { cryptosuite: string, multikey: string; } {
    // First find out which cryptosuite are we using
    const cryptosuite = ((): Cryptosuites => {
        if (key.kty) {
            if (key.kty === "EC") {
                if (key.crv === "P-256" || key.crv === "P-384") {
                    return Cryptosuites.ecdsa
                } else {
                    throw new Error(`Unknown crv value ${key.crv}`);
                }
            } else if(key.kty === "OKP") {
                if (key.crv === "Ed25519") {
                    return Cryptosuites.eddsa
                } else {
                    throw new Error(`Unknown crv value for an OKP key (${key.crv})`);
                }
            } else {
                // In fact, at present, it never happens, because the only place where this function
                // is invokes already makes some tests, but this keeps TypeScript quiet, and is
                // more future proof.
                throw new Error(`No multikey definition for this key ${key.kty}`);
            }
        } else {
            // See comment above...
            throw new Error(`No key type provided`);
        }
    })();

    const multikey = mkwc.JWKToMultikey(key);
    return { cryptosuite: `${cryptosuite}`, multikey };
}

// export async function keyToMultikey(key: CryptoKey): Promise<{cryptosuite: string, multikey: string}> {
//     // First find out which cryptosuite are we using
//     const key_alg = key.algorithm as Algorithm;
//     const algorithm: string = key_alg.name;

//     // const algorithm: string = key.algorithm.name as object;
//     const cryptosuite = ((alg: string): types.Cryptosuites => {
//         switch (alg) {
//             case ECDSA: return types.Cryptosuites.ecdsa; 
//             case EDDSA: return types.Cryptosuites.eddsa;
//         }
//         throw new Error("No Multikey for this key");
//     })(algorithm);

//     const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
//     let mk: Uint8Array;
//     if (cryptosuite === types.Cryptosuites.eddsa) {
//         mk = new Uint8Array([...EDDSA_MK_PREFIX, ...rawKey]);
//     } else if (cryptosuite === types.Cryptosuites.ecdsa) {
//         // In reality, this should be more complicated: the
//         // rawKey is uncompressed key data and it should be
//         // compressed before assigning to mk below
//         if (key_alg.namedCurve === "P-256") {
//             mk = new Uint8Array([...ECDSA_256_MK_PREFIX, ...rawKey]);
//         } else {
//             mk = new Uint8Array([...ECDSA_384_MK_PREFIX, ...rawKey]);
//         }
//     }
//     const multikey = 'z' + base58.encode(mk);
//     return { cryptosuite: `${cryptosuite}`, multikey }
// }


/**
 * Convert a Multikey encoded key into a Crypto Key.
 * 
 * @param multikey 
 * @returns 
 */


// export function multikeyToKey(multikey: string): JsonWebKey {
//     return mkwc.multikeyToJWK(multikey)
// }



// export async function multikeyToKey(multikey: string): Promise<CryptoKey> {
//     // Separate the real content from the preambles
//     const full_raw = base58.decode(multikey.slice(1))
//     const preamble: Uint8Array = full_raw.slice(0,2);
//     const keyData: Uint8Array = full_raw.slice(2);

//     // the content of the preamble provides information on the crypto type
//     const algorithm: Algorithm = { name: "" };

//     if (preamble[0] === EDDSA_MK_PREFIX[0] && preamble[1] === EDDSA_MK_PREFIX[1]) {
//         algorithm.name = EDDSA;
//     } else if (preamble[0] === ECDSA_256_MK_PREFIX[0] && preamble[1] === ECDSA_256_MK_PREFIX[1]) {
//         // in reality, the keyData must be uncompressed at this point. Alas!, I did not find
//         // or could create, a decompression algorithm. T.B.D....
//         algorithm.name = ECDSA;
//         algorithm.namedCurve = "P-256";
//     } else if (preamble[0] === ECDSA_384_MK_PREFIX[0] && preamble[1] === ECDSA_384_MK_PREFIX[1]) {
//         algorithm.name = ECDSA;
//         algorithm.namedCurve = "P-384";
//     } else {
//         throw new Error("Invalid Multikey");
//     }
//     return crypto.subtle.importKey('raw', keyData, algorithm, true, ['verify']);
// }
