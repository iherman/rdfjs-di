// const { subtle } = globalThis.crypto;
import * as n3 from 'n3';
import * as rdf from '@rdfjs/types';

export type Quads = rdf.DatasetCore;
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
