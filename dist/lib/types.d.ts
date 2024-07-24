/**
 * Common types and classes.
 *
 * @packageDocumentation
 */
import * as rdf from '@rdfjs/types';
export declare enum Cryptosuites {
    ecdsa = "ecdsa-rdfc-2019",
    eddsa = "eddsa-rdfc-2022",
    rsa_pss = "rsa-pss-rdfc-ih",
    rsa_ssa = "rsa-ssa-rdfc-ih"
}
export interface VerificationResult extends Errors {
    verified: boolean;
    verifiedDocument: rdf.DatasetCore | null;
}
export interface KeyPair {
    public: JsonWebKey;
    private: JsonWebKey;
}
export interface KeyMetadata {
    controller?: string;
    expires?: string;
    revoked?: string;
    cryptosuite?: string;
}
export interface KeyData extends KeyMetadata, KeyPair {
}
/*****************************************************************************************
 * Errors
 *****************************************************************************************/
/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
export declare abstract class ProblemDetail extends Error {
    /** The vocabulary URL for the entry */
    type: string;
    /** The error code */
    code: number;
    /** Title (essentially the error type name) */
    title: string;
    /** More detailed description of the error condition */
    detail: string;
    constructor(detail: string, title: string, code: number);
}
export interface Errors {
    warnings: ProblemDetail[];
    errors: ProblemDetail[];
}
export declare class Proof_Generation_Error extends ProblemDetail {
    constructor(detail: string);
}
export declare class Proof_Verification_Error extends ProblemDetail {
    constructor(detail: string);
}
export declare class Proof_Transformation_Error extends ProblemDetail {
    constructor(detail: string);
}
export declare class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail: string);
}
export declare class Unclassified_Error extends ProblemDetail {
    constructor(detail: string);
}
