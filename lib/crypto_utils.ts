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
export type Alg = "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512";

/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384" | "P-521";

/** JWK values for the hash methods that are relevant for this package */
export type Hsh = "SHA-256" | "SHA-384" | "SHA-512";

/** JWK values for the key types that are relevant for this package */
export type Kty = "EC" | "RSA";

interface WebCryptoAPIData {
    name:         string,
    hash:         Hsh;
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
    "PS512": { name: 'RSA-PSS', hash: 'SHA-512', saltLength: SALT_LENGTH },
    "RS256": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    "RS384": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
    "RS512": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-512' },
}

/**
 * Mapping of the JWK instance and the corresponding terms for the WebCrypto API
 * 
 * @param report 
 * @param key 
 * @returns 
 */
function algorithmData(report: Errors, key: JsonWebKey): WebCryptoAPIData | null {
    switch (key.kty as Kty) {
        case "EC" : {
            return {
                name:       "ECDSA",
                namedCurve: key.crv as Crv,
                hash:       DEFAULT_HASH
            }
        }
        case "RSA" : {
            try {
                return RsaAlgs[key.alg as Alg];
            } catch (e) {
                report.errors.push(new types.Unclassified_Error(`Key's error in 'alg': ${e.message}`));
                return null;
            }
        }
    }   
}

/**
 * Export a WebCrypto crypto key pair into their JWK equivalent.
 * 
 * @param newPair 
 * @returns 
 */
async function toJWK(newPair: CryptoKeyPair): Promise<KeyPair> {
    const publicKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.publicKey);
    const privateKey: JsonWebKey = await crypto.subtle.exportKey("jwk", newPair.privateKey);
    return { public: publicKey, private: privateKey };
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
export async function sign(report: Errors, message: string, secretKey: JsonWebKey) : Promise<string | null> {
    // Prepare the message to signature:
    const rawMessage: ArrayBuffer = textToArrayBuffer(message);

    // The crypto algorithm to be used with this key:
    const algorithm: WebCryptoAPIData | null = algorithmData(report, secretKey);

    if (algorithm === null) {
        return null;
    } else {
        try {
            // Import the JWK key into crypto key:
            const key: CryptoKey = await crypto.subtle.importKey("jwk", secretKey, algorithm, true, ["sign"]);
            const rawSignature: ArrayBuffer = await crypto.subtle.sign(algorithm, key, rawMessage);
            
            // Turn the the signature into Base64URL, and the into multicode
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
export async function verify(report: Errors, message: string, signature: string, publicKey: JsonWebKey): Promise<boolean> {
    const rawMessage: ArrayBuffer = textToArrayBuffer(message);
    if (signature.length === 0 || signature[0] !== 'u') {
        report.errors.push(new types.Malformed_Proof_Error(`Signature is of an incorrect format (${signature})`));
        return false;
    }
    const rawSignature: ArrayBuffer = base64UrlToArrayBuffer(signature.slice(1));

    // get the keys:
    const algorithm: WebCryptoAPIData | null = algorithmData(report, publicKey);

    if (algorithm === null) {
        return false;
    } else {
        try {
            const key: CryptoKey = await crypto.subtle.importKey("jwk", publicKey, algorithm, true, ["verify"]);
            const retval: boolean = await crypto.subtle.verify(algorithm, key, rawSignature, rawMessage);
            return retval;
        } catch(e) {
            report.errors.push(new types.Proof_Generation_Error(e.message));
            return false;
        }
    }
}

/**
 * Mapping from the JWK data to the corresponding DI cryptosuite identifier.
 * 
 * @param report - placeholder for error reports
 * @param keyPair 
 * @returns 
 */
export function cryptosuiteId(report: Errors, keyPair: KeyPair): Cryptosuites | null {
    // Some elementary check
    if (keyPair.private.kty !== keyPair.public.kty ||
        keyPair.private.crv !== keyPair.public.crv ||
        keyPair.private.alg !== keyPair.private.alg) {
        report.errors.push(new types.Invalid_Verification_Method('Keys are not in pair (in:\n ${JSON.stringify(keyPair,null,4)})'));
        return null;
    }

    const alg = algorithmData(report, keyPair.public);
    switch (alg.name) {
        case "ECDSA": return Cryptosuites.ecdsa;
        case "RSA-PSS": return Cryptosuites.rsa_pss;
        case "RSASSA-PKCS1-v1_5": return Cryptosuites.rsa_ssa;
        default: {
            report.errors.push(new types.Invalid_Verification_Method(`Unknown alg (${alg.name} in:\n ${JSON.stringify(keyPair,null,4)})`));
            return null;
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

    const newPair = await crypto.subtle.generateKey(suiteToAPI(), true, ["sign", "verify"]);
    const keyPair = await toJWK(newPair);
    const retval: KeyData = {
        public      : keyPair.public,
        private     : keyPair.private,
        cryptosuite : `${suite}`,
    }
    return {...retval, ...metadata};
}
