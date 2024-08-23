/**
 * Externally visible API level for the package.
 * 
 * 
 * @packageDocumentation
 */

// deno-lint-ignore-file no-inferrable-types
/// <reference types="node" />
import * as rdf   from '@rdfjs/types';
import * as n3    from 'n3';
import * as types from './lib/types';
import * as debug from './lib/debug';

import { Errors, KeyData, VerificationResult, KeyMetadata } from './lib/types';
import { 
    isKeyData, 
    isDatasetCore, convertToStore, refactorBnodes, extraChainQuads,
    DatasetMap, Proof, ProofStore, calculateDatasetHash
} from './lib/utils';
import { 
    generateAProofGraph, verifyProofGraphs,
    rdf_type, 
    sec_di_proof, 
    sec_proof, 
    sec_previousProof
} from './lib/proof_utils';

/* This file is also the entry module to the package; a number of exports are put here to be more friendly to users */
export type { KeyData, VerificationResult, KeyMetadata } from './lib/types';
export type { KeyDetails }                               from './lib/crypto_utils';
export { Cryptosuites }                                  from './lib/types';
export { generateKey, jwkToCrypto }                      from './lib/crypto_utils';

// n3.DataFactory is a namespace with some functions...
const { quad } = n3.DataFactory;

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
export async function generateProofGraph(dataset: rdf.DatasetCore, keyData: Iterable<KeyData>, previous?: rdf.Quad_Subject): Promise<rdf.DatasetCore[]>;
export async function generateProofGraph(dataset: rdf.DatasetCore, keyData: KeyData, previous ?: rdf.Quad_Subject): Promise<rdf.DatasetCore>;
export async function generateProofGraph(dataset: rdf.DatasetCore, keyData: KeyData | Iterable<KeyData>, previous?: rdf.Quad_Subject): Promise<rdf.DatasetCore | rdf.DatasetCore[]> {
    // Start fresh with results
    const report: Errors = { errors : [], warnings : [] }

    // This is not optimal. It will regenerate the hash for every key and, except for an occasional ECDSA+P-384, it will generate the same data. 
    // Some sort of a caching information on the hash values could replace this, but that is left for later...
    const signAndGenerate = async (keypair: KeyData): Promise<rdf.DatasetCore> => {
        const toBeSigned = await calculateDatasetHash(dataset, keypair.publicKey);
        return generateAProofGraph(report, toBeSigned, keypair, previous);
    }

    // prepare for the overload of arguments
    const keyPairs: Iterable<KeyData> = isKeyData(keyData) ? [keyData] : keyData;

    // execute the proof graph generation concurrently
    const promises: Promise<rdf.DatasetCore>[] = Array.from(keyPairs).map(signAndGenerate);
    const retval: rdf.DatasetCore[] = await Promise.all(promises);
    // return by taking care of overloading.
    if (report.errors.length !== 0) {
        // There were possible errors while generating the signatures
        const message: string = JSON.stringify(report.errors,null,4);
        throw new types.Proof_Generation_Error(`${message}`);
    } else {
        return isKeyData(keyData) ? retval[0] : retval;
    }
}


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
export async function verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore | rdf.DatasetCore[]): Promise<VerificationResult> {
    const report: Errors = { errors: [], warnings: [] }
    const proofGraphs: rdf.DatasetCore[] = isDatasetCore(proofGraph) ? [proofGraph] : proofGraph;
    const proofs = proofGraphs.map((pr: rdf.DatasetCore): ProofStore => {
        return {
            proofQuads: convertToStore(pr),
            proofGraph: undefined,
        };
    });
    const verified: boolean = await verifyProofGraphs(report, dataset, proofs);
    
    return {
        verified,
        verifiedDocument: verified ? dataset : null,
        errors: report.errors,
        warnings: report.warnings
    }
}

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
export async function embedProofGraph(dataset: rdf.DatasetCore, keyData: KeyData | Iterable<KeyData>, anchor?: rdf.Quad_Subject): Promise<rdf.DatasetCore> {
    const output: n3.Store = convertToStore(dataset);
    const keyPairs: KeyData[] = isKeyData(keyData) ? [keyData] : Array.from(keyData);

    // Essential: in this API, an array is automatically a key chain, otherwise a key set.
    // The peculiarity of the key chain embedding is that it requires the anchor to follow the official algorithm...
    const isKeyChain: boolean = keyPairs.length > 1 && Array.isArray(keyData);

    let allProofs: Proof[] = [];

    // Convert a proof graph, generated by the appropriate method, into a proof chain entry;
    // it extracts the data necessary to combine several proofs into what is necessary.
    const storeProofData = (proofTriples: rdf.DatasetCore): Proof | null => {
        // Look for the type statement among the graph entries
        for (const q of proofTriples) {
            if (q.predicate.value === rdf_type.value && q.object.value === sec_di_proof.value) {
                return {
                    proofId    : q.subject,
                    proofGraph : output.createBlankNode(),
                    // In fact, refactoring may not be necessary, because the proof graph generated by
                    // this package does not contain bnodes. But the user may decide to do it by hand and
                    // include extra stuff...
                    proofQuads: refactorBnodes(output, proofTriples), 
                    // This may be enough in most cases:
                    // proofQuads :  proofTriples,
                };
            }
        } 
        // This, in fact, does not happen. The proofTriples are generated by a function that does add a type triple...
        // Returning null is just a way of making the TS compiler happy
        return null;
    };

    // Unfortunately, the key chain and key set cases are fairly different
    if (isKeyChain) {
        for (let i = 0; i < keyPairs.length; i++) {
            // Generate the intermediate quads that are temporarily added to 
            // the core dataset before signing. This is, in effect,
            // the verbatim copy of the previous proof, which therefore
            // "signed over" by the current proof.
            const extraQuads: rdf.Quad[] = extraChainQuads(allProofs, i, anchor); 
            debug.log(extraQuads);
            
            // The intermediate quads added to the dataset to secure the chain
            // (This is an n3 specific API method!)
            output.addQuads(extraQuads);

            // We generate the relevant proof graph using the dedicated utility...
            const proofTriples: rdf.DatasetCore = await generateProofGraph(output, keyPairs[i], 
                i !== 0 ? allProofs[i - 1].proofId : undefined /* Reference to the previous proof, if applicable */
            );

            // Remove the intermediate quads
            // (This is an n3 specific API method!)
            output.removeQuads(extraQuads);

            // Generate a complete proof structure for the new proof...
            const newProof: Proof = storeProofData(proofTriples);

            //... and store it on the list of proofs.
            if (newProof !== null) {
                 allProofs.push(newProof);
            }
        }
    } else {
        // This is the key set case
        // All graphs can be generated in one step, making the processing way simpler...
        const proofGraphs: rdf.DatasetCore[] = await generateProofGraph(dataset, keyPairs);
        allProofs = proofGraphs.map(storeProofData);
    }

    // Merge all generated proof datasets into the result
    // The reference to the proof graph(s) from the dedicated anchor is added to the result
    for (const proof of allProofs) {
        if (anchor) {
            output.add(quad(anchor, sec_proof, proof.proofGraph as rdf.Quad_Object))
        }
        for (const q of proof.proofQuads) {
            // No need bnode reconciliation, because proof graphs never contain bnodes
            output.add(quad(q.subject, q.predicate, q.object, proof.proofGraph)); 
        }
    }
    return output;
}

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
export async function verifyEmbeddedProofGraph(dataset: rdf.DatasetCore, anchor?: rdf.Quad_Subject): Promise<VerificationResult> {
    const report: Errors = { errors: [], warnings: [] };
    const dataStore   = new n3.Store();
    const proofGraphs = new DatasetMap();
    let isProofChain: boolean = false;

    // First, identify the possible dataset graph IDs
    for (const q of dataset) {
        // Branching on whether there is an anchor explicitly setting the proof graphs
        if (anchor) {
            if (q.predicate.equals(sec_proof) && q.subject.equals(anchor)) {
                if (q.object.termType !== "Literal") {
                    proofGraphs.set(q.object as rdf.Quad_Graph);
                }               
            } 
        } else {
            // There is no anchor; we are looking for graphs whose type has been set
            // This branch is the reason we have to use a DatasetMap for the 
            // storage of graph IDs: we should not have duplicate entries.
            if (q.predicate.equals(rdf_type) && q.object.equals(sec_di_proof)) {
                if (q.graph.termType === "DefaultGraph") {
                    report.errors.push(new types.Proof_Verification_Error("Proof type cannot be the default graph"))
                } else {
                    proofGraphs.set(q.graph);
                }
            }
        }
    }

    // By now, we got the identification of all the proof graphs, we can separate the quads into 
    // the "real" data graph and the relevant proof graphs
    for (const q of dataset) {
        if (q.predicate.equals(sec_proof) && proofGraphs.has(q.object)) {
            // this is an extra entry, not part of the triples that were signed
            // neither it is part of any proof graphs
            continue;
        } else if(q.graph.termType === "DefaultGraph") {
            dataStore.add(q)
        } else if(proofGraphs.has(q.graph)) {
            // this quad belongs to one of the proof graphs!
            // Note that the separated proof graphs should contain only as they become
            // stand-alone RDF graphs now, not part of a dataset
            const proofStore: ProofStore = proofGraphs?.get(q.graph);

            // let us store the data itself first:
            proofStore.proofQuads.add(quad(q.subject, q.predicate, q.object));

            // see if this triple gives us the proof object ID;
            if (q.predicate.equals(rdf_type) && q.object.equals(sec_di_proof)) {
                proofStore.proofId = q.subject;
            // see if this is a previous proof statement; if so, store the reference for a subsequent ordering
            } else if (q.predicate.equals(sec_previousProof) && q.object.termType !== "Literal") {
                proofStore.previousProof = q.object;
                // marking the whole thing a chain!
                isProofChain = true;
            }
        } else {
            // This a bona fide data quad, to be stored as such
            dataStore.add(q);
        }
    }

    if (isProofChain) {
        // Get the proofs into a reference order, just like when it is submitted
        const allProofs: ProofStore[] = proofGraphs.orderedData();
        let verified: boolean;

        if (allProofs.length === 0) {
            report.errors.push(new types.Proof_Verification_Error("Proof Chain has no start."))
            verified = false;
        } else {
            const verified_list: boolean[] = [];
            if (anchor === undefined) {
                report.warnings.push(new types.Unclassified_Error("No anchor has been provided for a proof chain."));
            }
            for (let i = 0; i < allProofs.length; i++) {
                const extraQuads: rdf.Quad[] = extraChainQuads(allProofs, i, anchor); 

                // These are the intermediate quads added to the dataset to secure the chain
                // (This is an n3 specific API method!)
                dataStore.addQuads(extraQuads);

                const verifiedChainLink: boolean = await verifyProofGraphs(report, dataStore, [allProofs[i]]);
                verified_list.push(verifiedChainLink);

                dataStore.removeQuads(extraQuads);
            }
            verified = !verified_list.includes(false)
        }

        return {
            verified,
            verifiedDocument: verified ? dataStore : null,
            errors: report.errors,
            warnings: report.warnings
        }
    } else {
        // This is the simple case...

        const proofs: ProofStore[] = proofGraphs.data();
        const verified: boolean = await verifyProofGraphs(report, dataStore, proofs);
        return {
            verified,
            verifiedDocument: verified ? dataStore : null,
            errors: report.errors,
            warnings: report.warnings
        }
    }
}



