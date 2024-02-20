// const { subtle } = globalThis.crypto;
import * as n3 from 'n3';
import * as rdf from '@rdfjs/types';
import * as Constants from './constants';
import base64url from 'base64url';


export type BNodeId = string;

export const dataFactory: rdf.DataFactory = n3.DataFactory;

export enum Confidentiality {
    public = "public",
    secret = "secret"
}

/**
 * Crypto key pair. The keys are stored in JWK format.
 */
export interface KeyPair {
    public  : JsonWebKey,
    private : JsonWebKey
}

/**
 * Object to string for printing or storing
 */
// deno-lint-ignore no-explicit-any
export function objToStr(obj: any, formatted: boolean = true) {
    return formatted ? JSON.stringify(obj, null, 4) : JSON.stringify(obj);
}

export async function importKey(key: JsonWebKey, type: Confidentiality): Promise<CryptoKey | null> {
    return await crypto.subtle.importKey("jwk", key,
        {
            name: Constants.algorithm,
            namedCurve: Constants.curve
        },
        true,
        type === Confidentiality.public ? ["verify"] : ["sign"]
    );
}

/**
 * Text to array buffer
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Convert an array buffer to base64url
 * 
 * (Created by chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
export function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = "";

    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }

    const base64String = btoa(binary);
    return base64url.fromBase64(base64String);
}

// export function uint8ArrayToHex(uint8Array: Uint8Array): string {
//     return Array.from(uint8Array, byte => byte.toString(16).padStart(2, '0')).join('');
// }

/**
 * Generate a random string of a specific number of characters
 *
 * @param size
 */

// export function randomString(size: number): string {
//     const uint8Array = new Uint8Array(size);
//     crypto.getRandomValues(uint8Array);
//     return uint8ArrayToHex(uint8Array);
// }


/**
 * Convert ArrayBuffer to hex
 * @param arrayBuffer 
 */
// export function arrayBufferToHex(arrayBuffer: ArrayBuffer): string {
//     return uint8ArrayToHex(new Uint8Array(arrayBuffer));
// }

/**
 * Convert A hex encoding of an ArrayBuffer to a buffer
 * @param arrayBuffer 
 * @throws the incoming string is not a hex encoded number
 */
// export function hexToArrayBuffer(hexString: string): ArrayBuffer {
//     const hexArray = hexString.match(/.{1,2}/g);
//     if (hexArray === null) {
//         throw new Error(`hexToArrayBuffer: input parameter "${hexString}" is invalid`);
//     }
//     const uint8Array = new Uint8Array(hexArray.map(byte => parseInt(byte, 16)));
//     return uint8Array.buffer;
// }


