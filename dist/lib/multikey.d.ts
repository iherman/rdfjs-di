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
export declare function keyToMultikey(key: CryptoKey): Promise<{
    cryptosuite: string;
    multikey: string;
}>;
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
export declare function multikeyToKey(multikey: string): Promise<CryptoKey>;
