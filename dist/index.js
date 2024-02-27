"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DI_ECDSA = exports.Confidentiality = void 0;
const n3 = require("n3");
const uuid_1 = require("uuid");
const utils_1 = require("./lib/utils");
// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;
/** Values used internally for the crypto functions; they are defined by the WebCrypto spec. */
var Confidentiality;
(function (Confidentiality) {
    Confidentiality["public"] = "public";
    Confidentiality["secret"] = "secret";
})(Confidentiality || (exports.Confidentiality = Confidentiality = {}));
/**
 * Type guard to check if an object implements the KeyPair interface.
 *
 * @param obj
 * @returns
 */
function isKeyPair(obj) {
    return obj.public !== undefined && obj.private !== undefined;
}
/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/
/* Various namespaces, necessary when constructing a proof graph */
const sec_prefix = (0, utils_1.createPrefix)("https://w3id.org/security#");
const rdf_prefix = (0, utils_1.createPrefix)("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
const xsd_prefix = (0, utils_1.createPrefix)("http://www.w3.org/2001/XMLSchema#");
const rdf_type = rdf_prefix('type');
const sec_proof = sec_prefix('proof');
const sec_proofGraph = sec_prefix('ProofGraph');
const sec_di_proof = sec_prefix('DataIntegrityProof');
const sec_proofValue = sec_prefix('proofValue');
const sec_publicKeyJwk = sec_prefix('publicKeyJwk');
const xsd_datetime = xsd_prefix('dateTime');
/*****************************************************************************************
 * The real meat...
 *****************************************************************************************/
/**
 * Subclasses are supposed to set the right algorithm, cryptosuite, etc, names.
 *
 */
class DataIntegrity {
    _algorithm;
    _cryptosuite;
    _hash;
    _curve;
    constructor() {
        this._hash = "SHA-256";
    }
    // get algorithm(): string { return this._algorithm }
    // get cryptosuite(): string { return this._cryptosuite; }
    // get hash(): string { return this._hash; }
    // get curve(): string { return this._curve; }
    /**************************************************************************************************/
    /* Internal functions. All of them are protected, ie, usable by the concrete subclasses           */
    /**************************************************************************************************/
    /**
     * Import a JWK encoded key into a key usable by crypto.subtle.
     *
     * @param key - the key itself
     * @param type - whether this is a private or public key (usable to sign or verify, respectively)
     *
     * @returns
     * @throws - the key is invalid for some reasons
     */
    async importKey(key, type) {
        const retval = await crypto.subtle.importKey("jwk", key, {
            name: this._algorithm,
            namedCurve: this._curve,
        }, true, type === Confidentiality.public ? ["verify"] : ["sign"]);
        if (retval === null) {
            throw new Error(`Invalid key: ${JSON.stringify(key, null, 4)}`);
        }
        return retval;
    }
    ;
    /**
     * Generate a (separate) proof graph, per the DI spec. The signature is stored in
     * multibase format, using base64url encoding.
     *
     * @param hashValue - this is the value of the Dataset's canonical hash
     * @param keyPair
     * @returns
     */
    async generateAProofGraph(hashValue, keyPair) {
        // Calculate the hash of the dataset, and sign the hash with the secret key
        // This is the "core"...
        const signHashValue = async () => {
            const key = await this.importKey(keyPair.private, Confidentiality.secret);
            const raw_signature = await crypto.subtle.sign({
                name: this._algorithm,
                hash: this._hash
            }, key, (0, utils_1.textToArrayBuffer)(hashValue));
            return `u${(0, utils_1.arrayBufferToBase64Url)(raw_signature)}`;
        };
        // Create a proof graph. Just a boring set of quad generations...
        const createProofGraph = (proofValue) => {
            const retval = new n3.Store();
            // Unique URL-s, for the time being as uuid-s
            const proofGraphId = `urn:uuid:${(0, uuid_1.v4)()}`;
            const proofGraph = namedNode(proofGraphId);
            const verificationMethodId = `urn:uuid:${(0, uuid_1.v4)()}`;
            const keyGraph = namedNode(verificationMethodId);
            retval.addQuads([
                quad(proofGraph, rdf_type, sec_di_proof),
                quad(proofGraph, sec_prefix('cryptosuite'), literal(this._cryptosuite)),
                quad(proofGraph, sec_prefix('created'), literal((new Date()).toISOString(), xsd_datetime)),
                quad(proofGraph, sec_prefix('verificationMethod'), keyGraph),
                quad(proofGraph, sec_proofValue, literal(proofValue)),
                quad(proofGraph, sec_prefix('proofPurpose'), sec_prefix('authenticationMethod')),
                quad(keyGraph, rdf_type, sec_prefix('JsonWebKey')),
                quad(keyGraph, sec_publicKeyJwk, literal(JSON.stringify(keyPair.public), rdf_prefix('JSON'))),
            ]);
            if (keyPair.controller)
                retval.add(quad(keyGraph, sec_prefix('controller'), namedNode(keyPair.controller)));
            if (keyPair.expires)
                retval.add(quad(keyGraph, sec_prefix('expires'), literal(keyPair.expires, xsd_datetime)));
            if (keyPair.revoked)
                retval.add(quad(keyGraph, sec_prefix('revoked'), literal(keyPair.revoked, xsd_datetime)));
            return retval;
        };
        return createProofGraph(await signHashValue());
    }
    /**
     * Check one proof graph, ie, whether the included signature corresponds to the hash value
     *
     * @param hash
     * @param proof
     * @returns
     */
    async validateProofGraph(hash, proof) {
        // Verify the signature by check signature of the hash with the key
        // This is the "core"...
        const checkHashValue = async (proof_value, key_jwk) => {
            const key = await this.importKey(key_jwk, Confidentiality.public);
            const signature_array = (0, utils_1.base64UrlToArrayBuffer)(proof_value.slice(1));
            const data = (0, utils_1.textToArrayBuffer)(hash);
            const retval = await crypto.subtle.verify({
                name: this._algorithm,
                hash: this._hash
            }, key, signature_array, data);
            return retval;
        };
        const getProofValue = (store) => {
            // Retrieve the signature value per spec:
            const proof_values = store.getQuads(null, sec_proofValue, null, null);
            if (proof_values.length !== 1) {
                throw new Error("Incorrect proof values");
            }
            return proof_values[0].object.value;
        };
        const getPublicKey = (store) => {
            const keys = store.getQuads(null, sec_publicKeyJwk, null, null);
            if (keys.length !== 1) {
                throw new Error("Incorrect key values");
            }
            return JSON.parse(keys[0].object.value);
        };
        const proofValue = getProofValue(proof);
        const publicKey = getPublicKey(proof);
        // Here we go with checking...
        const retval = await checkHashValue(proofValue, publicKey);
        return retval;
    }
    async generateProofGraph(dataset, keyPair) {
        // This is to be signed
        const toBeSigned = await (0, utils_1.calculateDatasetHash)(dataset);
        // prepare for the overload of arguments
        const keyPairs = isKeyPair(keyPair) ? [keyPair] : keyPair;
        // execute the proof graph generation concurrently
        const promises = Array.from(keyPairs).map((keypair) => this.generateAProofGraph(toBeSigned, keypair));
        const retval = await Promise.all(promises);
        // return by taking care of overloading.
        return isKeyPair(keyPair) ? retval[0] : retval;
    }
    async verifyProofGraph(dataset, proofGraph) {
        // this is the value that must be checked...
        const hash = await (0, utils_1.calculateDatasetHash)(dataset);
        // just to make the handling uniform...
        const proofs = (0, utils_1.isDatasetCore)(proofGraph) ? [proofGraph] : proofGraph;
        // the "convertToStore" intermediate step is necessary; the proof graph checker needs a n3.Store
        const promises = proofs.map(utils_1.convertToStore).map((pr_graph) => this.validateProofGraph(hash, pr_graph));
        const results = await Promise.all(promises);
        return (0, utils_1.isDatasetCore)(proofGraph) ? results[0] : results;
    }
    /**
     * Create a new dataset with the copy of the original and the proof graph as a separate graph within the
     * dataset.
     *
     * The separate quad with the `proof` property is added; if the anchor is properly defined, then that
     * will be the subject, otherwise a new blank node. (The latter may be meaningless, but makes it easier
     * to find the proof graph for verification.)
     *
     * If the `keyPair` argument is an Array, then the proof graphs are considered to be a Proof Chain. Otherwise,
     * (e.g., if it is a Set), it is a Proof Set.
     *
     * Just wrapper around {@link generateProofGraph}.
     * @param dataset
     * @param keyPair
     * @param anchor
     * @returns
     */
    async embedProofGraph(dataset, keyPair, anchor) {
        const retval = (0, utils_1.convertToStore)(dataset);
        const keyPairs = isKeyPair(keyPair) ? [keyPair] : Array.from(keyPair);
        const proofGraphs = await this.generateProofGraph(dataset, keyPairs);
        const isKeyChain = keyPairs.length > 1 && Array.isArray(keyPair);
        const chain = [];
        for (let i = 0; i < proofGraphs.length; i++) {
            const proofTriples = proofGraphs[i];
            const proofGraphID = retval.createBlankNode();
            for (const q of proofTriples) {
                retval.add(quad(q.subject, q.predicate, q.object, proofGraphID));
                if (isKeyChain && q.predicate.value === rdf_type.value && q.object.value === sec_di_proof.value) {
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
                const q = quad(anchor, sec_proof, proofGraphID);
                retval.add(q);
            }
        }
        // Adding the chain statements, if required
        if (isKeyChain) {
            for (let i = 1; i < chain.length; i++) {
                const q = quad(chain[i].proofId, sec_prefix("previousProof"), chain[i - 1].proofId, chain[i].graph);
                retval.add(q);
            }
        }
        return retval;
    }
    /**
     * Verify the dataset with embedded proof graphs. The individual proof graphs are identified by the presence
     * of a type relationship to `DataIntegrityProof`; the result is the conjunction of the validation result for
     * each proof graphs separately.
     *
     * @param dataset
     * @returns
     */
    async verifyEmbeddedProofGraph(dataset) {
        const dataStore = new n3.Store();
        const proofGraphs = new utils_1.DatasetMap();
        // Separate the core data from the datasets;
        // First, identify the possible dataset graph IDs
        for (const q of dataset) {
            // A dataset can be identified with a proof property.
            if (q.predicate.equals(sec_proof)) {
                // the object refers to a proof graph (unless it is a literal, which is a bug!)
                if (q.object.termType !== "Literal") {
                    proofGraphs.item(q.object);
                }
                // The quad is not copied to the dataStore!
            }
            else if (q.predicate.equals(rdf_type) && q.object.equals(sec_di_proof)) {
                // the triple is in a proof graph!
                proofGraphs.item(q.graph);
            }
        }
        // By now, we got the identification of all the proof graphs, we can separate the quads among 
        // the data graph and the relevant proof graphs
        for (const q of dataset) {
            if (q.predicate.equals(sec_proof)) {
                // this is an extra entry, not part of the triples that were signed
                continue;
            }
            else if (q.graph.termType === "DefaultGraph") {
                dataStore.add(q);
            }
            else if (proofGraphs.has(q.graph)) {
                // this quad belongs to a proof graph!
                // Note that the proof graphs contain only triples, because they are 
                // separate entities now...
                proofGraphs.item(q.graph).add(quad(q.subject, q.predicate, q.object));
            }
            else {
                // This a bona fide data quad
                dataStore.add(q);
            }
        }
        const hash = await (0, utils_1.calculateDatasetHash)(dataStore);
        const proofs = proofGraphs.datasets();
        const promises = proofs.map((prGraph) => this.validateProofGraph(hash, prGraph));
        const results = await Promise.all(promises);
        return !results.includes(false);
    }
    ;
}
/**
 * Real instantiation of a DI cryptosuite: ecdsa-2022.
 */
class DI_ECDSA extends DataIntegrity {
    constructor() {
        super();
        this._algorithm = "ECDSA";
        this._cryptosuite = "ecdsa-2022";
        this._curve = "P-256";
    }
}
exports.DI_ECDSA = DI_ECDSA;
