"use strict";
/**
 * Externally visible API level for the package.
 *
 *
 * @packageDocumentation
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyEmbeddedProofGraph = exports.embedProofGraph = exports.verifyProofGraph = exports.generateProofGraph = exports.generateKey = exports.Cryptosuites = void 0;
const n3 = require("n3");
const types = require("./lib/types");
const utils_1 = require("./lib/utils");
const proof_utils_1 = require("./lib/proof_utils");
var types_1 = require("./lib/types");
Object.defineProperty(exports, "Cryptosuites", { enumerable: true, get: function () { return types_1.Cryptosuites; } });
var crypto_utils_1 = require("./lib/crypto_utils");
Object.defineProperty(exports, "generateKey", { enumerable: true, get: function () { return crypto_utils_1.generateKey; } });
// n3.DataFactory is a namespace with some functions...
const { quad } = n3.DataFactory;
async function generateProofGraph(dataset, keyData) {
    // Start fresh with results
    const report = { errors: [], warnings: [] };
    // This is to be signed
    const toBeSigned = await (0, utils_1.calculateDatasetHash)(dataset);
    // prepare for the overload of arguments
    const keyPairs = (0, utils_1.isKeyData)(keyData) ? [keyData] : keyData;
    // execute the proof graph generation concurrently
    const promises = Array.from(keyPairs).map((keypair) => (0, proof_utils_1.generateAProofGraph)(report, toBeSigned, keypair));
    const retval = await Promise.all(promises);
    // return by taking care of overloading.
    if (report.errors.length !== 0) {
        // There were possible errors while generating the signatures
        const message = JSON.stringify(report.errors, null, 4);
        throw new types.Proof_Generation_Error(`${message}`);
    }
    else {
        return (0, utils_1.isKeyData)(keyData) ? retval[0] : retval;
    }
}
exports.generateProofGraph = generateProofGraph;
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
async function verifyProofGraph(dataset, proofGraph) {
    const report = { errors: [], warnings: [] };
    const hash = await (0, utils_1.calculateDatasetHash)(dataset);
    const proofGraphs = (0, utils_1.isDatasetCore)(proofGraph) ? [proofGraph] : proofGraph;
    const proofs = proofGraphs.map((pr) => {
        return {
            dataset: (0, utils_1.convertToStore)(pr),
            id: undefined,
        };
    });
    const verified = await (0, proof_utils_1.verifyProofGraphs)(report, hash, proofs);
    return {
        verified,
        verifiedDocument: verified ? dataset : null,
        errors: report.errors,
        warnings: report.warnings
    };
}
exports.verifyProofGraph = verifyProofGraph;
/**
 * Create a new dataset with the copy of the original and the proof graph(s) as a separate graph(s) within the
 * dataset (a.k.a. "Embedded Proof" in the DI spec terminology).
 *
 * If the anchor is defined, then that will be the subject for quads with the `proof` property is added (one for each proof graph).
 *
 * If the `keyPair` argument is an Array, then the proof graphs are considered to be a Proof Chain. Otherwise,
 * (e.g., if it is a Set), it is a Proof Set.
 *
 * @param dataset
 * @param keyData
 * @param anchor
 * @returns
 */
async function embedProofGraph(dataset, keyData, anchor) {
    const retval = (0, utils_1.convertToStore)(dataset);
    const keyPairs = (0, utils_1.isKeyData)(keyData) ? [keyData] : Array.from(keyData);
    const proofGraphs = await generateProofGraph(dataset, keyPairs);
    const isKeyChain = keyPairs.length > 1 && Array.isArray(keyData);
    const chain = [];
    for (let i = 0; i < proofGraphs.length; i++) {
        const proofTriples = proofGraphs[i];
        const proofGraphID = retval.createBlankNode();
        for (const q of proofTriples) {
            retval.add(quad(q.subject, q.predicate, q.object, proofGraphID));
            if (isKeyChain && q.predicate.value === proof_utils_1.rdf_type.value && q.object.value === proof_utils_1.sec_di_proof.value) {
                // Storing the values to create the proof chains in a subsequent step
                // The subject is the ID of the proof
                chain.push({
                    proofId: q.subject,
                    graph: proofGraphID,
                });
            }
        }
        ;
        if (anchor) {
            const q = quad(anchor, proof_utils_1.sec_proof, proofGraphID);
            retval.add(q);
        }
    }
    // Adding the chain statements, if required
    if (isKeyChain) {
        for (let i = 1; i < chain.length; i++) {
            const q = quad(chain[i].proofId, proof_utils_1.sec_previousProof, chain[i - 1].proofId, chain[i].graph);
            retval.add(q);
        }
    }
    return retval;
}
exports.embedProofGraph = embedProofGraph;
/**
 * Verify the dataset with embedded proof graph(s).
 *
 * If the anchor is present, the proof graphs are identified by the object terms of the corresponding [`proof`](https://www.w3.org/TR/vc-data-integrity/#proofs) quads.
 * Otherwise, the type relationship to [`DataIntegrityProof`](https://www.w3.org/TR/vc-data-integrity/#dataintegrityproof) are considered. Note that if no anchor is provided, this second choice
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
async function verifyEmbeddedProofGraph(dataset, anchor) {
    const dataStore = new n3.Store();
    const proofGraphs = new utils_1.DatasetMap();
    // First, identify the possible dataset graph IDs
    for (const q of dataset) {
        // Branching on whether there is an anchor explicitly setting the proof graphs
        if (anchor) {
            if (q.predicate.equals(proof_utils_1.sec_proof) && q.subject.equals(anchor)) {
                if (q.object.termType !== "Literal") {
                    proofGraphs.item(q.object);
                }
            }
        }
        else {
            // There is no anchor; we are looking for graphs whose type has been set
            // This branch is the reason we have to use a DatasetMap for the 
            // storage of graph IDs; we should not have duplicate entries.
            if (q.predicate.equals(proof_utils_1.rdf_type) && q.object.equals(proof_utils_1.sec_di_proof)) {
                proofGraphs.item(q.graph);
            }
        }
    }
    // By now, we got the identification of all the proof graphs, we can separate the quads among 
    // the data graph and the relevant proof graphs
    for (const q of dataset) {
        if (q.predicate.equals(proof_utils_1.sec_proof) && proofGraphs.has(q.graph)) {
            // this is an extra entry, not part of the triples that were signed
            // neither it is part of any proof graphs
            continue;
        }
        else if (q.predicate.equals(proof_utils_1.sec_previousProof)) {
            // Per the cryptosuite specifications, the "previous proof" statement is not part of the "proof options", ie,
            // should not be used for the generation of the final proof. It was not used to generate the proof graph when signing.
            continue;
        }
        else if (q.graph.termType === "DefaultGraph") {
            dataStore.add(q);
        }
        else if (proofGraphs.has(q.graph)) {
            // this quad belongs to a proof graph!
            // Note that the separated proof graphs contain only triples, they become
            // stand-alone RDF graphs now
            proofGraphs.item(q.graph).add(quad(q.subject, q.predicate, q.object));
        }
        else {
            // This a bona fide data quad, to be stored as such
            dataStore.add(q);
        }
    }
    const report = { errors: [], warnings: [] };
    const hash = await (0, utils_1.calculateDatasetHash)(dataStore);
    const proofs = proofGraphs.data();
    const verified = await (0, proof_utils_1.verifyProofGraphs)(report, hash, proofs);
    return {
        verified,
        verifiedDocument: verified ? dataStore : null,
        errors: report.errors,
        warnings: report.warnings
    };
}
exports.verifyEmbeddedProofGraph = verifyEmbeddedProofGraph;
