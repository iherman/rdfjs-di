/**
 * Common types and classes.
 * 
 * @packageDocumentation
 */

import * as rdf   from '@rdfjs/types';

export enum Cryptosuites {
    ecdsa   = "ecdsa-2022",
    rsa_pss = "rdfjs-di-rsa-pss",
    rsa_ssa = "rdfjs-di-rss-ssa"
}

export interface VerificationResult extends Errors {
    verified:         boolean,
    verifiedDocument: rdf.DatasetCore | null,
}

export interface KeyPair {
    public: JsonWebKey,
    private: JsonWebKey,
}

export interface KeyMetadata {
    controller?:  string,
    expires?:     string,
    revoked?:     string,
    cryptosuite?: string,
}

export interface KeyData extends KeyMetadata, KeyPair {}

/*****************************************************************************************
 * Errors
 *****************************************************************************************/

/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
export abstract class ProblemDetail extends Error {
    /** The vocabulary URL for the entry */
    type: string;
    /** The error code */
    code: number;
    /** Title (essentially the error type name) */
    title: string;
    /** More detailed description of the error condition */
    detail: string;

    constructor(detail: string, title: string, code: number) {
        super(detail);
        this.detail = detail;
        this.title = title;
        this.code = code;
        this.type = `https://w3id.org/security#${title.replace(' ', '_').toUpperCase()}`;
    }
}

export interface Errors {
    warnings: ProblemDetail[];
    errors: ProblemDetail[];
}

export class Proof_Generation_Error extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Proof generation error', -16);
    }
}

export class Malformed_Proof_Error extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Malformed proof error', -17);
    }
}

export class Mismatched_Proof_Purpose extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Mismatched proof purpose', -18);
    }
}

export class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Invalid verification method', -24);
    }
}

export class Unclassified_Error extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Unclassified error', -100);
    }
}