/**
 * Externally visible API level for the package.
 *
 *
 * @packageDocumentation
 */
import * as rdf from '@rdfjs/types';
import { KeyData, VerificationResult } from './lib/types';
export type { KeyData, VerificationResult, KeyMetadata } from './lib/types';
export type { KeyDetails } from './lib/crypto_utils';
export { Cryptosuites } from './lib/types';
export { generateKey, jwkToCrypto } from './lib/crypto_utils';
/**
 * Generate a (separate) proof graph (or graphs), per the DI spec. The signature is stored in
 * multibase format, using base64url encoding. Keys are accepted in WebCrypto Key format (and stored in JWK or in Multikey, depending on the crypto key).
 *
 * A single previous proof reference may also be set, although that really makes sense in the case of a single key only
 *
 * @param dataset
 * @param keyData
 * @param previous - A previous proof ID, when applicable; this is added as an extra statement in the proof graphs. This parameter is only relevant internally when a proof chain is generated.
 * @throws - Error if there was an issue while signing.
 * @returns
 */
export declare function generateProofGraph(dataset: rdf.DatasetCore, keyData: Iterable<KeyData>, previous?: rdf.Quad_Subject): Promise<rdf.DatasetCore[]>;
export declare function generateProofGraph(dataset: rdf.DatasetCore, keyData: KeyData, previous?: rdf.Quad_Subject): Promise<rdf.DatasetCore>;
/**
 * Verify the separate proof graph.
 *
 * The validity result is the conjunction of the validation result for each proof graphs separately.
 *
 * The following checks are made:
 *
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (either in JWK or in Multikey)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 *
 * If any of those errors are found, the validation result is `false`. The error reports themselves, with some more details, are part of the verification result structure.
 *
 * @param dataset
 * @param proofGraph
 * @returns
 */
export declare function verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore | rdf.DatasetCore[]): Promise<VerificationResult>;
/**
 * Create a new dataset with the copy of the original and the proof graph(s) as a separate graph(s) within the
 * dataset (a.k.a. "Embedded Proof" in the DI spec terminology).
 *
 * If the anchor is defined, then that will be the subject for quads with the `proof` property is added (one for each proof graph).
 * In the case of a VC, the ID of the credential itself is naturally the anchor, but there is no such "natural" node for a general
 * RDF dataset.
 *
 * If the `keyPair` argument is an Array, then the proof graphs are considered to define a Proof Chain. Otherwise,
 * (e.g., if it is a Set), it is a Proof Set.
 * Proof chains are somewhat restricted compared to the specification: proof chains and sets are not mixed. In other words, either
 * all proofs are part of a chain or form a chain; the case when a previous proof reference points at a set of proofs is not possible.
 *
 * The anchor should exist to create a proper chain per spec, because the spec requires it to sign over the previous proof reference. The chain
 * will be created in the absence of an anchor, but the result will not be conform to the specification (that _requires_ the addition of a proof
 * reference triple).)
 *
 * @param dataset
 * @param keyData
 * @param anchor
 * @returns
 */
export declare function embedProofGraph(dataset: rdf.DatasetCore, keyData: KeyData | Iterable<KeyData>, anchor?: rdf.Quad_Subject): Promise<rdf.DatasetCore>;
/**
 * Verify the dataset with embedded proof graph(s).
 *
 * If the anchor is present, the proof graphs are identified by the object terms of the corresponding [`proof`](https://www.w3.org/TR/vc-data-integrity/#proofs) quads.
 * Otherwise, the type relationship to [`DataIntegrityProof`](https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof) are considered.
 * Note that if no anchor is provided, this second choice
 * may lead to erroneous results because some of the embedded proof graphs are not meant to be a proof for the full dataset. (This may
 * be the case in a ["Verifiable Presentation" style datasets](https://www.w3.org/TR/vc-data-model-2.0/#presentations-0).)
 *
 * The validity result is the conjunction of the validation result for each proof graphs separately.
 *
 * The following checks are also made.
 *
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (either in JWK or in Multikey)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 *
 * If any of those errors occur, the overall validity result is `false`. The error reports themselves, with some more details, are part of the verification result structure.
 *
 * @param dataset
 * @param anchor
 * @returns
*/
export declare function verifyEmbeddedProofGraph(dataset: rdf.DatasetCore, anchor?: rdf.Quad_Subject): Promise<VerificationResult>;
