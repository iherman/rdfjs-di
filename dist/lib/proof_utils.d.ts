/**
 * "Internal API" for handling proof graphs.
 *
 * Put into a separate file for an easier maintenance; not meant
 * to be part of the external API.
 * They are not exported (via `index.ts`) to
 * package users.
 *
 * @packageDocumentation
 */
import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
import { Errors, KeyData } from './types';
/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/
export declare const sec_prefix: (l: string) => rdf.NamedNode<string>;
export declare const rdf_prefix: (l: string) => rdf.NamedNode<string>;
export declare const xsd_prefix: (l: string) => rdf.NamedNode<string>;
export declare const rdf_type: rdf.NamedNode;
export declare const sec_proof: rdf.NamedNode;
export declare const sec_di_proof: rdf.NamedNode;
export declare const sec_proofValue: rdf.NamedNode;
export declare const sec_publicKeyJwk: rdf.NamedNode;
export declare const sec_proofPurpose: rdf.NamedNode;
export declare const sec_authenticationMethod: rdf.NamedNode;
export declare const sec_assertionMethod: rdf.NamedNode;
export declare const sec_verificationMethod: rdf.NamedNode;
export declare const sec_expires: rdf.NamedNode;
export declare const sec_revoked: rdf.NamedNode;
export declare const sec_created: rdf.NamedNode;
export declare const xsd_datetime: rdf.NamedNode;
/**
 * Generate a (separate) proof graph, per the DI spec. The signature is stored in
 * [multibase format](https://www.w3.org/TR/vc-data-integrity/#multibase-0), using base64url encoding.
 *
 * @param hashValue - this is the value of the Dataset's canonical hash
 * @param keyData
 * @returns
 */
export declare function generateAProofGraph(report: Errors, hashValue: string, keyData: KeyData): Promise<rdf.DatasetCore>;
/**
 * Check one proof graph, ie, whether the included signature corresponds to the hash value.
 *
 * The following checks are also made:
 *
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (in JWK)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 *
 * Errors are stored in the `report` structure. If any error occurs, the result is false.
 *
 * @param report
 * @param hash
 * @param proof
 * @returns
 */
export declare function verifyAProofGraph(report: Errors, hash: string, proof: n3.Store, proofId?: rdf.Quad_Graph): Promise<boolean>;
