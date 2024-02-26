/// <reference types="node" />
import * as rdf       from '@rdfjs/types';
import * as n3        from 'n3';
import { v4 as uuid } from 'uuid';
import { RDFC10 }     from 'rdfjs-c14n';
import base64url      from 'base64url';

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

function createPrefix(uri: string): (l: string) => rdf.NamedNode {
    class prefix {
        private _mapping: Record<string, rdf.NamedNode> = {};
        private _base: string;
        constructor(base: string) {
            this._base = base;
        }
        value(local: string): rdf.NamedNode {
            if (local in this._mapping) {
                return this._mapping[local];
            } else {
                const retval: rdf.NamedNode = namedNode(`${this._base}${local}`);
                this._mapping[local] = retval;
                return retval;
            }
        }
    }
    const mapping = new prefix(uri);
    const get_value = (local: string): rdf.NamedNode => {
        return mapping.value(local);
    };
    return get_value;
}

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
 * Utility Functions
 *****************************************************************************************/

/**
 * Type guard to check if an object implements the rdf.DatasetCore interface.
 * 
 * @param obj 
 * @returns 
 */
function isDatasetCore(obj: any): obj is rdf.DatasetCore {
    return  (obj as rdf.DatasetCore).add !== undefined && 
            (obj as rdf.DatasetCore).delete !== undefined &&
            (obj as rdf.DatasetCore).match !== undefined &&
            (obj as rdf.DatasetCore).has !== undefined;
}

/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Calculate the canonical hash of a dataset; this is based on the
 * implementation of RDFC 1.0
 * 
 * @param dataset 
 * @returns 
 */
async function calculateDatasetHash(dataset: rdf.DatasetCore): Promise<string> {
    const rdfc10 = new RDFC10();
    const canonical_quads: string = await rdfc10.canonicalize(dataset);
    const datasetHash: string = await rdfc10.hash(canonical_quads);
    return datasetHash;
}


/**
 * Convert an array buffer to base64url value.
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
    const bytes = new Uint8Array(arrayBuffer);

    let binary: string = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);

    return base64url.fromBase64(base64String);
}

/**
 * Convert a base64url value to an array buffer
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param string 
 * @returns 
 */
function base64UrlToArrayBuffer(url: string): ArrayBuffer {
    const base64string = base64url.toBase64(url);

    const binary = atob(base64string);

    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }

    return byteArray.buffer;
}

/**
 * Create and store the values in a dataset into a new n3 Store. This may be
 * necessary, because the methods are not supposed to modify the original
 * dataset.
 * 
 * The n3.Store objects includes functions to retrieve quads.
 * @param dataset 
 * @returns 
 */
function copyToStore(dataset: rdf.DatasetCore): n3.Store {
    const retval = new n3.Store();
    for (const q of dataset) retval.add(q);
    return retval;
}

/**
 * Convert the dataset into an n3.Store, unless it is already a store.
 * This is done to manage the various quads more efficiently.
 * 
 * @param dataset 
 * @returns 
 */
function convertToStore(dataset: rdf.DatasetCore): n3.Store {
    return (dataset instanceof n3.Store) ? dataset : copyToStore(dataset);
}

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

        // Verify the signature by hashing the dataset and check its signature with the key
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

        const processOneProofGraph = async (proof_graph: rdf.DatasetCore) : Promise<boolean> => {
            // Using an n3 store makes subsequent searches easier...
            const proof: n3.Store = convertToStore(proof_graph);

            const proofValue: string = getProofValue(proof);
            const publicKey: JsonWebKey = getPublicKey(proof);

            // Here we go with checking...
            const retval: boolean = await checkHashValue(proofValue, publicKey);
            return retval;
        }

        const proofs: rdf.DatasetCore[] = isDatasetCore(proofGraph) ? [proofGraph] : proofGraph;

        const promises: Promise<boolean>[] = proofs.map((pr_graph: rdf.DatasetCore) => processOneProofGraph(pr_graph));
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

    async verifyEmbeddedProofGraph(dataset: rdf.DatasetCore): Promise<boolean> {
        const datasetStore: n3.Store = convertToStore(dataset);
        const getProofGraphID = (): rdf.Term => {
            const statements: rdf.Quad[] = datasetStore.getQuads(null, sec_proof, null, null);
            if (statements.length > 1) {
                throw new Error(`Ambiguous proof graph ID`);
            } else if( statements.length === 0) {
                const alt_statements: rdf.Quad[] = datasetStore.getQuads(null, rdf_type, sec_di_proof, null);
                if( alt_statements.length === 0 ) {
                    throw new Error(`Non existent proof graph ID`);
                } else if (alt_statements.length >1 ) {
                    throw new Error(`Ambiguous proof graph ID`);
                }
                return alt_statements[0].graph;
            }
            return statements[0].object;
        } 

        const proofGraph = new n3.Store();
        const signedGraph = new n3.Store();
        const proofGraphID: rdf.Term = getProofGraphID();

        for (const q of datasetStore) {
            if (q.graph.equals(proofGraphID)) {
                proofGraph.add(quad(q.subject,q.predicate,q.object));
            } else if (q.object.equals(sec_proofGraph)) {
                continue;
            } else if (q.predicate.equals(sec_proof)) {
                continue;
            } else {
                signedGraph.add(q);
            }
        }
        return await this.verifyProofGraph(signedGraph, proofGraph);
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


