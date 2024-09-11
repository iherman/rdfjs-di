"use strict";
/**
 * "Internal API" to the WebCrypto facilities.
 *
 * Put into a separate file for an easier maintenance; not meant
 * to be part of the external API.
 * Most of them are not exported (via `index.ts`) to
 * package users.
 *
 * Note that, at the moment, the "interchange format" for keys is restricted to JWK. One
 * area of improvement may be to allow for other formats (the DI standard refers to Multikey).
 *
 * @packageDocumentation
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateKey = exports.cryptosuiteId = exports.verify = exports.sign = exports.jwkToCrypto = void 0;
const types = require("./types");
const types_1 = require("./types");
const base58 = require("./encodings/base58/index");
/***********************************************************************************
 *
 * JWK vs. WebCrypto API mappings
 *
***********************************************************************************/
/** Default values for keys, some of them can be overwritten */
const SALT_LENGTH = 32;
const DEFAULT_MODUS_LENGTH = 2048;
const DEFAULT_HASH = "SHA-256";
const DEFAULT_CURVE = "P-256";
/**
 * Mapping between the "alg values in the JWK instance and the necessary
 * terms for the WebCrypto API
 */
const RsaAlgs = {
    "PS256": { name: 'RSA-PSS', hash: 'SHA-256', saltLength: SALT_LENGTH },
    "PS384": { name: 'RSA-PSS', hash: 'SHA-384', saltLength: SALT_LENGTH },
    "RS256": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    "RS384": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
};
/**
 * Mapping of the JWK instance and the corresponding terms for the WebCrypto API.
 *
 * @param report
 * @param key
 * @returns
 */
function algorithmDataJWK(key) {
    switch (key.kty) {
        case "RSA": {
            try {
                return RsaAlgs[key.alg];
            }
            catch (e) {
                throw new Error(`Key's error in 'alg': ${e.message}`);
            }
        }
        case "EC": {
            return {
                name: "ECDSA",
                namedCurve: key.crv,
                hash: key.crv === "P-256" ? "SHA-256" : "SHA-384",
            };
        }
        case "OKP":
        default: {
            return {
                name: "Ed25519"
            };
        }
    }
}
/**
 * Mapping of the CryptoKey instance and the corresponding terms for the WebCrypto API.
 *
 * @param report
 * @param key
 * @returns
 */
function algorithmDataCR(report, key) {
    const alg = key.algorithm;
    switch (alg.name) {
        case "RSA-PSS": {
            return { name: 'RSA-PSS', hash: 'SHA-256', saltLength: SALT_LENGTH };
        }
        case "RSASSA-PKCS1-v1_5": {
            return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        }
        case "ECDSA": {
            const curve = alg.namedCurve;
            return {
                name: "ECDSA",
                namedCurve: curve,
                hash: curve === "P-384" ? "SHA-384" : "SHA-256",
            };
        }
        case "Ed25519":
        default: {
            return {
                name: "Ed25519"
            };
        }
    }
}
/***********************************************************************************
 *
 * Utilities for ArrayBuffer vs. string representations
 *
***********************************************************************************/
/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
function textToArrayBuffer(text) {
    return (new TextEncoder()).encode(text).buffer;
}
/***********************************************************************************
 *
 * The externally visible API entries
 *
***********************************************************************************/
/**
 * Convert a JWK key into WebCrypto; a thin layer on top of WebCrypto, which gathers
 * the right algorithmic details needed for the import itself.
 *
 * This function is also useful to the end user, so it is also meant to be
 * re-exported via the `index.ts` module.
 *
 * @param jwkKey
 * @param privateKey - whether this is a private or public key
 * @returns
 */
async function jwkToCrypto(jwkKey, privateKey = false) {
    const algorithm = algorithmDataJWK(jwkKey);
    return await crypto.subtle.importKey("jwk", jwkKey, algorithm, true, privateKey ? ["sign"] : ["verify"]);
}
exports.jwkToCrypto = jwkToCrypto;
/**
 * Sign a message.
 *
 * Possible errors are added to the report, no exceptions should be thrown.
 *
 * @param report
 * @param message
 * @param privateKey
 * @returns - either the signature in Multicode format, or `null` in case of an error.
 */
async function sign(report, message, privateKey) {
    // Prepare the message to signature:
    const rawMessage = textToArrayBuffer(message);
    // The crypto algorithm to be used with this key:
    const algorithm = algorithmDataCR(report, privateKey);
    if (algorithm === null) {
        return null;
    }
    else {
        try {
            const rawSignature = await crypto.subtle.sign(algorithm, privateKey, rawMessage);
            // Turn the the signature into Base64URL, and then into multicode
            return `z${base58.encode(new Uint8Array(rawSignature))}`;
            // return `u${arrayBufferToBase64Url(rawSignature)}`;
        }
        catch (e) {
            report.errors.push(new types.Proof_Generation_Error(e.message));
            return null;
        }
    }
}
exports.sign = sign;
/**
 * Verify a signature
 *
 * Possible errors are added to the report, no exceptions should be thrown.
 *
 * @param report - placeholder for error reports
 * @param message
 * @param signature
 * @param publicKey
 * @returns
 */
async function verify(report, message, signature, publicKey) {
    const rawMessage = textToArrayBuffer(message);
    if (signature.length === 0 || signature[0] !== 'z') {
        report.errors.push(new types.Proof_Verification_Error(`Signature is of an incorrect format (${signature})`));
        return false;
    }
    const rawSignature = base58.decode(signature.slice(1));
    // const rawSignature: ArrayBuffer = base64UrlToArrayBuffer(signature.slice(1));
    // get the algorithm details
    const algorithm = algorithmDataCR(report, publicKey);
    if (algorithm === null) {
        return false;
    }
    else {
        try {
            const retval = await crypto.subtle.verify(algorithm, publicKey, rawSignature, rawMessage);
            if (retval === false) {
                report.errors.push(new types.Proof_Verification_Error(`Signature ${signature} is invalid`));
            }
            return retval;
        }
        catch (e) {
            report.errors.push(new types.Proof_Generation_Error(e.message));
            return false;
        }
    }
}
exports.verify = verify;
/**
 * Mapping from the Crypto Key data to the corresponding DI cryptosuite identifier.
 *
 * @param report - placeholder for error reports
 * @param keyPair
 * @returns
 */
function cryptosuiteId(report, keyPair) {
    const alg = keyPair.publicKey.algorithm;
    if (alg === null) {
        return null;
    }
    else {
        switch (alg.name) {
            case "ECDSA": return types_1.Cryptosuites.ecdsa;
            case "Ed25519": return types_1.Cryptosuites.eddsa;
            case "RSA-PSS": return types_1.Cryptosuites.rsa_pss;
            case "RSASSA-PKCS1-v1_5": return types_1.Cryptosuites.rsa_ssa;
            default: {
                report.errors.push(new types.Invalid_Verification_Method(`Invalid algorithm name (${alg.name})`));
                return null;
            }
        }
    }
}
exports.cryptosuiteId = cryptosuiteId;
/**
 * Generate key pair to be used with DI in general. This function is not necessary for the core
 * functionalities of the package, but may be useful for the package users. It is therefore
 * meant to be re-exported via the `index.ts` module.
 *
 * @param suite
 * @param keyData
 * @param metadata
 * @returns
 */
async function generateKey(suite, keyData, metadata) {
    const suiteToAPI = () => {
        switch (suite) {
            case types_1.Cryptosuites.ecdsa: return {
                name: "ECDSA",
                namedCurve: keyData?.namedCurve || DEFAULT_CURVE,
            };
            case types_1.Cryptosuites.eddsa: return {
                name: "Ed25519"
            };
            case types_1.Cryptosuites.rsa_pss: return {
                name: "RSA-PSS",
                modulusLength: keyData?.modulusLength || DEFAULT_MODUS_LENGTH,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || DEFAULT_HASH,
            };
            case types_1.Cryptosuites.rsa_ssa: return {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keyData?.modulusLength || DEFAULT_MODUS_LENGTH,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || DEFAULT_HASH,
            };
        }
    };
    const newPair = await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);
    const output = {
        publicKey: newPair.publicKey,
        privateKey: newPair.privateKey,
    };
    return { ...output, ...metadata };
}
exports.generateKey = generateKey;
