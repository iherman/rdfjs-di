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
import { KeyMetadata, KeyData, Cryptosuites, Errors } from './types';
/** JWK values for the elliptic curves that are relevant for this package */
export type Crv = "P-256" | "P-384";
/** JWK values for the hash methods that are relevant for this package */
export type Hsh = "SHA-256" | "SHA-384";
/** Information that may be used when generating new keys */
export interface KeyDetails {
    namedCurve?: Crv;
    hash?: Hsh;
    modulusLength?: number;
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
export declare function jwkToCrypto(jwkKey: JsonWebKey, privateKey?: boolean): Promise<CryptoKey>;
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
export declare function sign(report: Errors, message: string, privateKey: CryptoKey): Promise<string | null>;
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
export declare function verify(report: Errors, message: string, signature: string, publicKey: CryptoKey): Promise<boolean>;
/**
 * Mapping from the Crypto Key data to the corresponding DI cryptosuite identifier.
 *
 * @param report - placeholder for error reports
 * @param keyPair
 * @returns
 */
export declare function cryptosuiteId(report: Errors, keyPair: CryptoKeyPair): Cryptosuites | null;
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
export declare function generateKey(suite: Cryptosuites, keyData?: KeyDetails, metadata?: KeyMetadata): Promise<KeyData>;
