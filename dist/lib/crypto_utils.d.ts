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
import { KeyMetadata, KeyData, Cryptosuites, KeyPair, Errors } from './types';
/** JWK values for the algorithms that are relevant for this package */
export type Alg = "RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512";
/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384" | "P-521";
/** JWK values for the hash methods that are relevant for this package */
export type Hsh = "SHA-256" | "SHA-384" | "SHA-512";
/** JWK values for the key types that are relevant for this package */
export type Kty = "EC" | "RSA" | "OKP";
/**
 * Interface to the Web Crypto information that has to be provided for the
 * creation of some RSA encryption keys.
 */
interface WebCryptoAPIData {
    name: string;
    hash?: Hsh;
    saltLength?: number;
    namedCurve?: Crv;
}
/** Information that may be used when generating new keys */
export interface KeyDetails {
    namedCurve?: Crv;
    hash?: Hsh;
    modulusLength?: number;
}
/**
 * Mapping of the JWK instance and the corresponding terms for the WebCrypto API.
 *
 * @param report
 * @param key
 * @returns
 */
export declare function algorithmData(report: Errors, key: JsonWebKey): WebCryptoAPIData | null;
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
export declare function sign(report: Errors, message: string, secretKey: JsonWebKey): Promise<string | null>;
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
export declare function verify(report: Errors, message: string, signature: string, publicKey: JsonWebKey): Promise<boolean>;
/**
 * Mapping from the JWK data to the corresponding DI cryptosuite identifier.
 *
 * @param report - placeholder for error reports
 * @param keyPair
 * @returns
 */
export declare function cryptosuiteId(report: Errors, keyPair: KeyPair): Cryptosuites | null;
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
export declare function generateKey(suite: Cryptosuites, metadata?: KeyMetadata, keyData?: KeyDetails): Promise<KeyData>;
export {};
