/**
 * BaseN-encodes a Uint8Array using the given alphabet.
 *
 * @param {Uint8Array} input - The bytes to encode in a Uint8Array.
 * @param {string} alphabet - The alphabet to use for encoding.
 * @param {number} maxline - The maximum number of encoded characters per line
 *          to use, defaults to none.
 *
 * @returns {string} The baseN-encoded output string.
 */
export function encode(input: Uint8Array, alphabet: string, maxline: number): string;
/**
 * Decodes a baseN-encoded (using the given alphabet) string to a
 * Uint8Array.
 *
 * @param {string} input - The baseN-encoded input string.
 * @param {string} alphabet - The alphabet to use for decoding.
 *
 * @returns {Uint8Array} The decoded bytes in a Uint8Array.
 */
export function decode(input: string, alphabet: string): Uint8Array;
