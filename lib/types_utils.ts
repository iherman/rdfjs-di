// const { subtle } = globalThis.crypto;
import * as n3    from 'n3';
import * as rdf   from '@rdfjs/types';
import { RDFC10 } from 'rdfjs-c14n';
import base64url  from 'base64url';


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
 * Text to array buffer
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}


/**
 * Calculate the canonical hash of a dataset; this is based on the
 * implementation of RDFC 1.0
 * 
 * @param dataset 
 * @returns 
 */
export async function calculateDatasetHash(dataset: rdf.DatasetCore): Promise < string > {
    const rdfc10 = new RDFC10();
    const canonical_quads: string = await rdfc10.canonicalize(dataset);
    const datasetHash: string = await rdfc10.hash(canonical_quads);
    return datasetHash;
}


/**
 * Convert an array buffer to base64url value.
 * 
 * (Created mostly by chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
export function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    // /** */ console.log(`>>>> Converting to base64url\n`);
    // /** */ console.log(arrayBuffer)
    const bytes = new Uint8Array(arrayBuffer);

    let binary: string = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);
    // /** */ console.log(`>>>> base64: ${base64String}`);

    const retval = base64url.fromBase64(base64String);
    // /** */ console.log(`>>>> Yielding ${retval}`);
    return retval;
}

/**
 * Convert a base64url value to an array buffer
 * 
 * (Created mostly by chatgpt...)
 * 
 * @param string 
 * @returns 
 */
export function base64UrlToArrayBuffer(url: string): ArrayBuffer {
    // /** */ console.log(`<<<< Converting base64url ${base64url} to array buffer`);
    const base64string = base64url.toBase64(url);

    // /** */ console.log(`<<<< Getting base64 value: ${base64string}`);
    const binary = atob(base64string);

    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }

    const retval: ArrayBuffer = byteArray.buffer;
    // /** */ console.log(`>>>> yielding`);
    // /** */ console.log(retval)
    return retval;
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


