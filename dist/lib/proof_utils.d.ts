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
import { Errors, KeyData } from './types';
import { GraphWithID } from './utils';
/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/
export declare const sec_prefix: (l: string) => rdf.NamedNode<string>;
export declare const rdf_prefix: (l: string) => rdf.NamedNode<string>;
export declare const xsd_prefix: (l: string) => rdf.NamedNode<string>;
export declare const rdf_type: rdf.NamedNode;
export declare const rdf_json: rdf.NamedNode;
export declare const sec_proof: rdf.NamedNode;
export declare const sec_di_proof: rdf.NamedNode;
export declare const sec_proofValue: rdf.NamedNode;
export declare const sec_publicKeyJwk: rdf.NamedNode;
export declare const sec_publicKeyMultibase: rdf.NamedNode;
export declare const sec_proofPurpose: rdf.NamedNode;
export declare const sec_authenticationMethod: rdf.NamedNode;
export declare const sec_assertionMethod: rdf.NamedNode;
export declare const sec_verificationMethod: rdf.NamedNode;
export declare const sec_expires: rdf.NamedNode;
export declare const sec_revoked: rdf.NamedNode;
export declare const sec_created: rdf.NamedNode;
export declare const xsd_datetime: rdf.NamedNode;
export declare const sec_previousProof: rdf.NamedNode;
/**
 * Generate a (separate) proof graph, per the DI spec. The signature is stored in
 * [multibase format](https://www.w3.org/TR/vc-data-integrity/#multibase-0), using base64url encoding.
 *
 * @param report - placeholder for error reports
 * @param hashValue - this is the value of the Dataset's canonical hash
 * @param keyData
 * @returns
 */
export declare function generateAProofGraph(report: Errors, hashValue: string, keyData: KeyData): Promise<rdf.DatasetCore>;
/**
 *  Check a series of proof graphs, ie, check whether the included signature of a proof graph corresponds to the hash value.
 *
 * The following checks are also made for each proof graph:
 *
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (in JWK)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 *
 * Errors are stored in the `report` structure.
 * If any error occurs in any proof graph the result is `false`; otherwise, result is the conjunction of each individual proof graph verifications.
 *
 * @param report - placeholder for error reports
 * @param hash
 * @param proofs
 * @returns
 */
export declare function verifyProofGraphs(report: Errors, hash: string, proofs: GraphWithID[]): Promise<boolean>;
