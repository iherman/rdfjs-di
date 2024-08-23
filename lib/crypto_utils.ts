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

import * as types from "./types";
import { KeyMetadata, KeyData, Cryptosuites, KeyPair, Errors } from './types';

/** JWK values for the algorithms that are relevant for this package */
export type Alg = "RS256" | "RS384" | "PS256" | "PS384";

/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384";

/** JWK values for the hash methods that are relevant for this package */
export type Hsh = "SHA-256" | "SHA-384";

/** JWK values for the key types that are relevant for this package */
export type Kty = "EC" | "RSA" | "OKP";

/** 
 * Interface to the Web Crypto information that has to be provided for the
 * creation of some RSA encryption keys.  
 */
interface WebCryptoAPIData {
    name:         string,
    hash?:        Hsh;
    saltLength?:  number;
    namedCurve ?: Crv;
}

/** Information that may be used when generating new keys */
export interface KeyDetails {
    namedCurve?:    Crv,
    hash?:          Hsh,
    modulusLength?: number;
}

/***********************************************************************************
 * 
 * JWK vs. WebCrypto API mappings
 * 
***********************************************************************************/

/** Default values for keys, some of them can be overwritten */
const SALT_LENGTH             = 32;
const DEFAULT_MODUS_LENGTH    = 2048;
const DEFAULT_HASH            = "SHA-256";
const DEFAULT_CURVE           = "P-256";

/**
 * Mapping between the "alg values in the JWK instance and the necessary 
 * terms for the WebCrypto API
 */
const RsaAlgs: Record<Alg, WebCryptoAPIData> = {
    "PS256": { name: 'RSA-PSS', hash: 'SHA-256', saltLength: SALT_LENGTH },
    "PS384": { name: 'RSA-PSS', hash: 'SHA-384', saltLength: SALT_LENGTH },
    "RS256": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    "RS384": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
}

/**
 * Mapping of the JWK instance and the corresponding terms for the WebCrypto API.
 * 
 * @param report 
 * @param key 
 * @returns 
 */
function algorithmDataJWK(key: JsonWebKey): WebCryptoAPIData | null {
    switch (key.kty as Kty) {
        case "RSA" : {
            try {
                return RsaAlgs[key.alg as Alg];
            } catch (e) {
                throw new Error(`Key's error in 'alg': ${e.message}`);
            }
        }
        case "EC": {
            return {
                name: "ECDSA",
                namedCurve: key.crv as Crv,
                hash: (key.crv as Crv) === "P-256" ? "SHA-256" : "SHA-384",
            };
        }
        case "OKP": default: {
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
export function algorithmDataCR(report: Errors, key: CryptoKey): WebCryptoAPIData | null {
    const alg = key.algorithm;
    switch (alg.name) {
        case "RSA-PSS": {
            return { name: 'RSA-PSS', hash: 'SHA-256', saltLength: SALT_LENGTH }
        }
        case "RSASSA-PKCS1-v1_5": {
            return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }
        }
        case "ECDSA": {
            const curve = (alg as EcKeyAlgorithm).namedCurve as Crv;
            return {
                name:       "ECDSA",
                namedCurve: curve,
                hash:       curve === "P-384" ? "SHA-384" : "SHA-256",
            };
        }
        case "Ed25519": default: {
            return {
                name: "Ed25519"
            };
        }
    }
}

/**
 * Export a WebCrypto crypto key into its JWK equivalent.
 * 
 * @param newPair 
 * @returns 
 */
export async function toJWK(crKey: CryptoKey): Promise<JsonWebKey> {
    const jwkKey: JsonWebKey = await crypto.subtle.exportKey("jwk", crKey);
    return jwkKey;
}

// @@@@@@@@ Errors
export async function jwkToCrypto(report: Errors, jwkKey: JsonWebKey): Promise<CryptoKey> {
    const algorithm = algorithmDataJWK(jwkKey);
    return await crypto.subtle.importKey("jwk", jwkKey, algorithm, true, ["verify"]);
}

/***********************************************************************************
 * 
 * Utilities for ArrayBuffer vs. string representations
 * 
***********************************************************************************/

/*
 * These two came from perplexity, hopefully it is correct...
 */
const base64ToUrl = (base64String: string): string => {
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

const urlToBase64 = (base64Url: string): string => {
    return base64Url.replace(/-/g, '+').replace(/_/g, '/');
};

/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Convert an array buffer to a base64url value.
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    const bytes = new Uint8Array(arrayBuffer);

    let binary: string = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);

    return base64ToUrl(base64String);
}

/**
 * Convert a base64url value to an array buffer
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param url 
 * @returns 
 */
function base64UrlToArrayBuffer(url: string): ArrayBuffer {
    const base64string = urlToBase64(url);

    const binary = atob(base64string);

    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }

    return byteArray.buffer;
}

/***********************************************************************************
 * 
 * The externally visible API entries
 * 
***********************************************************************************/

/**
 * Sign a message.
 * 
 * Possible errors are added to the report, no exceptions should be thrown.
 * 
 * @param report 
 * @param message 
 * @param secretKey 
 * @returns - either the signature in Multicode format, or `null` in case of an error.
 */
export async function sign(report: Errors, message: string, secretKey: CryptoKey) : Promise<string | null> {
    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: WebCryptoAPIData | null = algorithmDataCR(report, secretKey);

    if (algorithm === null) {
        return null;
    } else {
        try {
            const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, secretKey, rawMessage);
            // Turn the the signature into Base64URL, and then into multicode
            return `u${arrayBufferToBase64Url(rawSignature)}`;
        } catch(e) {
            report.errors.push(new types.Proof_Generation_Error(e.message));
            return null;
        }
    }
}

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
export async function verify(report: Errors, message: string, signature: string, publicKey: CryptoKey): Promise<boolean> {
    const rawMessage: ArrayBuffer = textToArrayBuffer(message);
    if (signature.length === 0 || signature[0] !== 'u') {
        report.errors.push(new types.Proof_Verification_Error(`Signature is of an incorrect format (${signature})`));
        return false;
    }
    const rawSignature: ArrayBuffer = base64UrlToArrayBuffer(signature.slice(1));

    // get the algorithm details
    const algorithm: WebCryptoAPIData | null = algorithmDataCR(report, publicKey);

    if (algorithm === null) {
        return false;
    } else {
        try {
            const retval: boolean = await crypto.subtle.verify(algorithm, publicKey, rawSignature, rawMessage);
            if (retval === false) {
                report.errors.push(new types.Proof_Verification_Error(`Signature ${signature} is invalid`));
            }
            return retval;
        } catch(e) {
            report.errors.push(new types.Proof_Generation_Error(e.message));
            return false;
        }
    }
}

/**
 * Mapping from the Crypto Key data to the corresponding DI cryptosuite identifier.
 * 
 * @param report - placeholder for error reports
 * @param keyPair 
 * @returns 
 */
export function cryptosuiteId(report: Errors, keyPair: CryptoKeyPair): Cryptosuites | null {
    const alg = keyPair.publicKey.algorithm;
    if (alg === null) {
        return null;
    } else {
        switch (alg.name) {
            case "ECDSA":             return Cryptosuites.ecdsa;
            case "Ed25519":           return Cryptosuites.eddsa;
            case "RSA-PSS":           return Cryptosuites.rsa_pss;
            case "RSASSA-PKCS1-v1_5": return Cryptosuites.rsa_ssa;
            default: {
                report.errors.push(new types.Invalid_Verification_Method(`Invalid algorithm name (${alg.name})`));
                return null;
            }
        }
    }
}

/**
 * Generate key pair to be used with DI in general. This function is not necessary for the core
 * functionalities of the package, but may be useful for the package users. It is therefore 
 * meant to be re-exported via the `index.ts` module.
 * 
 * @param metadata 
 * @param suite 
 * @param keyData 
 * @returns 
 */
export async function generateKey(suite: Cryptosuites, metadata?: KeyMetadata, keyData?: KeyDetails): Promise<KeyData> {
    const suiteToAPI = (): any => {
        switch(suite) {
            case Cryptosuites.ecdsa : return {
                name: "ECDSA",
                namedCurve: keyData?.namedCurve || DEFAULT_CURVE,
            }
            case Cryptosuites.eddsa: return {
                name: "Ed25519"
            }
            case Cryptosuites.rsa_pss : return {
                name: "RSA-PSS",
                modulusLength: keyData?.modulusLength || DEFAULT_MODUS_LENGTH,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || DEFAULT_HASH,
            }
            case Cryptosuites.rsa_ssa: return {
                name: 'RSASSA-PKCS1-v1_5',
                modulusLength: keyData?.modulusLength || DEFAULT_MODUS_LENGTH,
                publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
                hash: keyData?.hash || DEFAULT_HASH,
            }
        }
    }

    const newPair: CryptoKeyPair = await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);
    const retval: KeyData = {
        publicKey   : newPair.publicKey,
        privateKey  : newPair.privateKey,
        cryptosuite : `${suite}`,
    }
    return {...retval, ...metadata};
}

