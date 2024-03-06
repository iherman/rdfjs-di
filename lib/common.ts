import { Errors }                from './errors';
import { KeyPair }               from './crypto_utils';
export { KeyPair }               from './crypto_utils';
import * as rdf                  from '@rdfjs/types';

export enum Cryptosuites {
    ecdsa   = "ecdsa-2022",
    rsa_pss = "rsa-pss-2024",
    rsa_ssa = "rss-ssa-pkcs1-2024"
}

/** Values used internally for the crypto functions; they are defined by the WebCrypto spec. */
export enum Confidentiality {
    public = "public",
    secret = "secret"
}

export interface VerificationResult extends Errors {
    verified:         boolean,
    verifiedDocument: rdf.DatasetCore | null,
}


export interface SuiteMetadata {
    controller?: string,
    expires?:    string,
    revoked?:    string,
}

export interface Cryptosuite extends KeyPair, SuiteMetadata {
    cryptosuite: string;
    created:     string;
}

