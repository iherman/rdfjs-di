/// <reference types="node" />
import * as rdf       from '@rdfjs/types';
import * as n3        from 'n3';
import { v4 as uuid } from 'uuid';
import {
    createPrefix, 
    isDatasetCore, 
    textToArrayBuffer, calculateDatasetHash, arrayBufferToBase64Url, base64UrlToArrayBuffer,
    copyToStore, convertToStore,
    DatasetMap,
    write_quads
 }  from './lib/utils';

// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;

/** Values used internally for the crypto functions; they are defined by the WebCrypto spec. */
enum Confidentiality {
    public = "public",
    secret = "secret"
}

/**
 * Crypto key pair. The keys are stored in JWK format.
 * At the moment, this seems the dominant format for keys in WebCrypto.
 * 
 * The values for controller, expires, and revoked, are all optional (see spec for details)
 */
export interface KeyPair {
    public      : JsonWebKey,
    private     : JsonWebKey,
    controller ?: string,
    expires    ?: string,
    revoked    ?: string,
}

/**
 * Type guard to check if an object implements the KeyPair interface.
 * 
 * @param obj 
 * @returns 
 */
function isKeyPair(obj: any): obj is KeyPair {
    return (obj as KeyPair).public !== undefined && (obj as KeyPair).private !== undefined;
}

/***************************************************************************************
 * Namespace handling
 **************************************************************************************/

/* Various namespaces, necessary when constructing a proof graph */
const sec_prefix = createPrefix("https://w3id.org/security#");
const rdf_prefix = createPrefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
const xsd_prefix = createPrefix("http://www.w3.org/2001/XMLSchema#");

const rdf_type: rdf.NamedNode         = rdf_prefix('type');   
const sec_proof: rdf.NamedNode        = sec_prefix('proof');
const sec_proofGraph: rdf.NamedNode   = sec_prefix('ProofGraph');
const sec_di_proof: rdf.NamedNode     = sec_prefix('DataIntegrityProof');
const sec_proofValue: rdf.NamedNode   = sec_prefix('proofValue');
const sec_publicKeyJwk: rdf.NamedNode = sec_prefix('publicKeyJwk');
const xsd_datetime: rdf.NamedNode     = xsd_prefix('dateTime');



/*****************************************************************************************
 * 
 * The real meat...
 * 
 *****************************************************************************************/

/**
 * Subclasses are supposed to set the right algorithm, cryptosuite, etc, names.
 * 
 */
abstract class DataIntegrity {
    protected _algorithm   : string;
    protected _cryptosuite : string;
    protected _hash        : string;
    protected _curve       : string;

    constructor() {
        this._hash = "SHA-256";
    }

    get algorithm(): string { return this._algorithm }
    get cryptosuite(): string { return this._cryptosuite; }
    get hash(): string { return this._hash; }
    get curve(): string { return this._curve; }

    /**
     * Import a JWK encoded key into a key usable for crypto.subtle.
     * 
     * @param key - the key itself 
     * @param type - whether this is a private or public key (usable to sign or verify, respectively)
     * 
     * @returns
     * @throws - the key is invalid for some reasons
     */
    protected async importKey(key: JsonWebKey, type: Confidentiality): Promise<CryptoKey> {
        const retval = await crypto.subtle.importKey("jwk", key,
            {
                name: this._algorithm,
                namedCurve: this._curve,
            },
            true,
            type === Confidentiality.public ? ["verify"] : ["sign"]
        );
        if (retval === null) {
            throw new Error(`Invalid key: ${JSON.stringify(key,null,4)}`);
        }
        return retval;
    };

    /**
     * Generate a (separate) proof graph, per the DI spec. The signature is stored in 
     * multibase format, using base64url encoding.
     * 
     * @param hashValue - this is the value of the Dataset's canonical hash 
     * @param keyPair 
     * @returns 
     */
    protected async generateAProofGraph(hashValue: string, keyPair: KeyPair): Promise<rdf.DatasetCore> {
        // Calculate the hash of the dataset, and sign the hash with the secret key
        // This is the "core"...
        const signHashValue = async (): Promise<string> => {
            const key: CryptoKey = await this.importKey(keyPair.private, Confidentiality.secret);
            const raw_signature: ArrayBuffer = await crypto.subtle.sign(
                {
                    name: this._algorithm,
                    hash: this._hash
                },
                key,
                textToArrayBuffer(hashValue)
            );
            return `u${arrayBufferToBase64Url(raw_signature)}`;           
        };

        // Create a proof graph. Just a boring set of quad generations...
        const createProofGraph = (proofValue: string): rdf.DatasetCore => {
            const retval: n3.Store = new n3.Store();

            // Unique URL-s, for the time being as uuid-s
            const proofGraphId = `urn:uuid:${uuid()}`;
            const proofGraph = namedNode(proofGraphId);

            const verificationMethodId = `urn:uuid:${uuid()}`
            const keyGraph = namedNode(verificationMethodId);

            retval.addQuads([
                quad(
                    proofGraph, rdf_type, sec_di_proof
                ),
                quad(
                    proofGraph, sec_prefix('cryptosuite'), literal(this._cryptosuite)
                ),
                quad(
                    proofGraph, sec_prefix('created'), literal((new Date()).toISOString(), xsd_datetime)
                ),
                quad(
                    proofGraph, sec_prefix('verificationMethod'), keyGraph
                ),
                quad(
                    proofGraph, sec_proofValue, literal(proofValue)
                ),
                quad(
                    proofGraph, sec_prefix('proofPurpose'), sec_prefix('authenticationMethod')
                ),

                quad(
                    keyGraph, rdf_type, sec_prefix('JsonWebKey')
                ),
                quad(
                    keyGraph, sec_publicKeyJwk, literal(JSON.stringify(keyPair.public), rdf_prefix('JSON'))
                ),
            ]);
            if (keyPair.controller) retval.add(quad(keyGraph, sec_prefix('controller'), namedNode(keyPair.controller)));
            if (keyPair.expires) retval.add(quad(keyGraph, sec_prefix('expires'), literal(keyPair.expires, xsd_datetime)));
            if (keyPair.revoked) retval.add(quad(keyGraph, sec_prefix('revoked'), literal(keyPair.revoked, xsd_datetime)));
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
    protected async processOneProofGraph(hash: string, proof: n3.Store): Promise<boolean> {
        // Verify the signature by check signature of the hash with the key
        // This is the "core"...
        const checkHashValue = async (proof_value: string, key_jwk: JsonWebKey): Promise<boolean> => {
            const key: CryptoKey = await this.importKey(key_jwk, Confidentiality.public);
            const signature_array: ArrayBuffer = base64UrlToArrayBuffer(proof_value.slice(1));
            const data: ArrayBuffer = textToArrayBuffer(hash);
            const retval: boolean = await crypto.subtle.verify(
                {
                    name: this._algorithm,
                    hash: this._hash
                },
                key,
                signature_array,
                data
            );
            return retval;
        };

        const getProofValue = (store: n3.Store): string => {
            // Retrieve the signature value per spec:
            const proof_values: rdf.Quad[] = store.getQuads(null, sec_proofValue, null, null);
            if (proof_values.length !== 1) {
                throw new Error("Incorrect proof values");
            }
            return proof_values[0].object.value;
        };

        const getPublicKey = (store: n3.Store): JsonWebKey => {
            const keys: rdf.Quad[] = store.getQuads(null, sec_publicKeyJwk, null, null);
            if (keys.length !== 1) {
                throw new Error("Incorrect key values");
            }
            return JSON.parse(keys[0].object.value) as JsonWebKey;
        };

        const proofValue: string = getProofValue(proof);
        const publicKey: JsonWebKey = getPublicKey(proof);

        // Here we go with checking...
        const retval: boolean = await checkHashValue(proofValue, publicKey);
        return retval;
    }


    /**
     * Generate a (separate) proof graph (or graphs), per the DI spec. The signature is stored in 
     * multibase format, using base64url encoding.
     * 
     * This is just a wrapper around {@link generateAProofGraph} to take care of multiple key pairs.
     * 
     * @param dataset 
     * @param keyPair 
     * @returns 
     */
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: Iterable<KeyPair>): Promise<rdf.DatasetCore[]>;
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair): Promise<rdf.DatasetCore>;
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair | Iterable<KeyPair>): Promise<rdf.DatasetCore | rdf.DatasetCore[]> {
        // This is to be signed
        const toBeSigned = await calculateDatasetHash(dataset);
        // prepare for the overload of arguments
        const keyPairs: Iterable<KeyPair> = isKeyPair(keyPair) ? [keyPair] : keyPair;
        // execute the proof graph generation concurrently
        const promises: Promise<rdf.DatasetCore>[] = Array.from(keyPairs).map((keypair: KeyPair) => this.generateAProofGraph(toBeSigned, keypair));
        const retval: rdf.DatasetCore[] = await Promise.all(promises);
        // return by taking care of overloading.
        return isKeyPair(keyPair) ? retval[0] : retval;
    }


    /**
     * Verify the separate proof graph.
     * 
     * For now, this methods just does the minimum as a proof of concept. A more elaborate version will have
     * to verify all details of the proof graph.
     * 
     * @param dataset 
     * @param proofGraph 
     * @returns 
     */
    async verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore): Promise<boolean>;
    async verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore[]): Promise<boolean[]>;
    async verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore | rdf.DatasetCore[]): Promise<boolean|boolean[]> {
        // this is the value that must be checked...
        const hash = await calculateDatasetHash(dataset);

        // just to make the handling uniform...
        const proofs: rdf.DatasetCore[] = isDatasetCore(proofGraph) ? [proofGraph] : proofGraph;

        // the "convertToStore" intermediate step is necessary; the proof graph checker needs a n3.Store
        const promises: Promise<boolean>[] = proofs.map(convertToStore).map((pr_graph: n3.Store): Promise<boolean> => this.processOneProofGraph(hash,pr_graph));
        const results: boolean[] = await Promise.all(promises);

        return isDatasetCore(proofGraph) ? results[0] : results; 
    }

    /**
     * Create a new dataset with the copy of the original and the proof graph as a separate graph within the
     * dataset.
     * 
     * The separate quad with the `proof` property is added; if the anchor is properly defined, then that
     * will be the subject, otherwise a new blank node. (The latter may be meaningless, but makes it easier
     * to find the proof graph for verification.)
     * 
     * Just wrapper around {@link generateProofGraph}.
     * @param dataset 
     * @param keyPair 
     * @param anchor 
     * @returns 
     */
    async embedProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair | Iterable<KeyPair>, anchor ?: rdf.Quad_Subject): Promise<rdf.DatasetCore> {
        const retval: n3.Store = convertToStore(dataset);

        const keyPairs: KeyPair[] = isKeyPair(keyPair) ? [keyPair] : Array.from(keyPair);

        const proofGraphs: rdf.DatasetCore[] = await this.generateProofGraph(dataset, keyPairs);

        const key_chain: boolean = keyPairs.length > 1 && Array.isArray(keyPair);
        const chain: { graph: rdf.BlankNode, proof_id: rdf.Quad_Subject }[] = [];

        for (let i = 0; i < proofGraphs.length; i++) {
            const proofTriples = proofGraphs[i];
            const proofGraphID = retval.createBlankNode();
            for (const q of proofTriples) {
                retval.add(quad(q.subject, q.predicate, q.object, proofGraphID));
                if (key_chain && q.predicate.value === rdf_type.value && q.object.value === sec_di_proof.value) {
                    // Storing the values to create the proof chains in a subsequent step
                    // The subject is the ID of the proof
                    chain.push ({
                        proof_id: q.subject,
                        graph : proofGraphID,
                    });
                }
            };
            if (anchor) {
                const q = quad(anchor, sec_proof, proofGraphID);
                retval.add(q);
            }
        }

        // Adding the chain statements, if required
        if (key_chain) {
            for (let i = 1; i < chain.length; i++) {
                const q = quad(chain[i].proof_id, sec_prefix("previousProof"), chain[i - 1].proof_id, chain[i].graph);
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
    async verifyEmbeddedProofGraph(dataset: rdf.DatasetCore): Promise<boolean> {
        const dataStore   = new n3.Store();
        const proofGraphs = new DatasetMap();

        // Separate the core data from the datasets;
        // First, identify the possible dataset graph IDs
        for (const q of dataset) {
            // A dataset can be identified with a proof property.
            if (q.predicate.equals(sec_proof)) {
                // the object refers to a proof graph (unless it is a literal, which is a bug!)
                if (q.object.termType !== "Literal") {
                    proofGraphs.item(q.object as rdf.Quad_Graph);
                }
                // The quad is not copied to the dataStore!
            } else if (q.predicate.equals(rdf_type) && q.object.equals(sec_di_proof)) {
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
            } else if(q.graph.termType === "DefaultGraph") {
                dataStore.add(q)
            } else if(proofGraphs.has(q.graph)) {
                // this quad belongs to a proof graph!
                // Note that the proof graphs contain only triples, they are 
                // separate entities now...
                proofGraphs.item(q.graph).add(quad(q.subject, q.predicate, q.object));
            } else {
                // This a bona fide data quad
                dataStore.add(q);
            }
        }

        const hash = await calculateDatasetHash(dataStore);

        const proofs: n3.Store[] = proofGraphs.datasets(); 
        // the "convertToStore" intermediate step is necessary; the proof graph checker needs a n3.Store
        const promises: Promise<boolean>[] = proofs.map((pr_graph: n3.Store): Promise<boolean> => this.processOneProofGraph(hash, pr_graph));
        const results: boolean[] = await Promise.all(promises);

        console.log(results)

        return !results.includes(false);
    };
}

/**
 * Real instantiation of a DI cryptosuite: ecdsa-2022. 
 */
export class DI_ECDSA extends DataIntegrity {
    constructor() {
        super();
        this._algorithm   = "ECDSA";
        this._cryptosuite = "ecdsa-2022"
        this._curve       = "P-256"
    }
}


