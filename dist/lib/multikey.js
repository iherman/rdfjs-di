"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.multikeyToKey = exports.keyToMultikey = void 0;
const base58 = require("./base58/index");
const types = require("./types");
// Crypto's name for the two EC algorithms
const ECDSA = "ECDSA";
const EDDSA = "Ed25519";
const EDDSA_MK_PREFIX = new Uint8Array([0xed, 0x01]);
const ECDSA_256_MK_PREFIX = new Uint8Array([0x80, 0x24]);
const ECDSA_384_MK_PREFIX = new Uint8Array([0x81, 0x24]);
/**
 * Convert a public ECDSA/ECDDA key into multikey.
 *
 * Note: this method is proof-of concept; it does not generate a valid Multikey for ECDSA curves.
 * The reason is that the W3C standard demands the encoding of a compressed key, as opposed to an
 * uncompressed one (that is created by WebCrypto key export). Unfortunately, I have not found
 * a suitable package to uncompress a compressed key, hence this part of the standard is,
 * currently, ignored.
 *
 * @param key Public key
 * @returns a predefined cryptosuite ID, and the multikey encoded key
 * @throws the Key type is not available in multikey
 */
async function keyToMultikey(key) {
    // First find out which cryptosuite are we using
    const key_alg = key.algorithm;
    const algorithm = key_alg.name;
    // const algorithm: string = key.algorithm.name as object;
    const cryptosuite = ((alg) => {
        switch (alg) {
            case ECDSA: return types.Cryptosuites.ecdsa;
            case EDDSA: return types.Cryptosuites.eddsa;
        }
        throw new Error("No Multikey for this key");
    })(algorithm);
    const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', key));
    let mk;
    if (cryptosuite === types.Cryptosuites.eddsa) {
        mk = new Uint8Array([...EDDSA_MK_PREFIX, ...rawKey]);
    }
    else if (cryptosuite === types.Cryptosuites.ecdsa) {
        // In reality, this should be more complicated: the
        // rawKey is uncompressed key data and it should be
        // compressed before assigning to mk below
        if (key_alg.namedCurve === "P-256") {
            mk = new Uint8Array([...ECDSA_256_MK_PREFIX, ...rawKey]);
        }
        else {
            mk = new Uint8Array([...ECDSA_384_MK_PREFIX, ...rawKey]);
        }
    }
    const multikey = 'z' + base58.encode(mk);
    return { cryptosuite: `${cryptosuite}`, multikey };
}
exports.keyToMultikey = keyToMultikey;
/**
 * Convert a Multikey encoded key into a Crypto Key.
 *
 * Note: this method is proof-of concept; it does not generate a valid Multikey for ECDSA curves.
 * The reason is that the W3C standard demands the encoding of a compressed key, as opposed to an
 * uncompressed one (that is created by WebCrypto key export). Unfortunately, I have not found
 * a suitable package to uncompress a compressed key, hence this part of the standard is,
 * currently, ignored.
 *
 * @param multikey
 * @returns
 */
async function multikeyToKey(multikey) {
    // Separate the real content from the preambles
    const full_raw = base58.decode(multikey.slice(1));
    const preamble = full_raw.slice(0, 2);
    const keyData = full_raw.slice(2);
    // the content of the preamble provides information on the crypto type
    const algorithm = { name: "" };
    if (preamble[0] === EDDSA_MK_PREFIX[0] && preamble[1] === EDDSA_MK_PREFIX[1]) {
        algorithm.name = EDDSA;
    }
    else if (preamble[0] === ECDSA_256_MK_PREFIX[0] && preamble[1] === ECDSA_256_MK_PREFIX[1]) {
        // in reality, the keyData must be uncompressed at this point. Alas!, I did not find
        // or could create, a decompression algorithm. T.B.D....
        algorithm.name = ECDSA;
        algorithm.namedCurve = "P-256";
    }
    else if (preamble[0] === ECDSA_384_MK_PREFIX[0] && preamble[1] === ECDSA_384_MK_PREFIX[1]) {
        algorithm.name = ECDSA;
        algorithm.namedCurve = "P-384";
    }
    else {
        throw new Error("Invalid Multikey");
    }
    return crypto.subtle.importKey('raw', keyData, algorithm, true, ['verify']);
}
exports.multikeyToKey = multikeyToKey;
