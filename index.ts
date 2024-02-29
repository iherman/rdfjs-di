/// <reference types="node" />
import * as rdf          from '@rdfjs/types';
import * as n3           from 'n3';
import { v4 as uuid }    from 'uuid';
import * as errors       from './lib/errors';
import { ProblemDetail } from './lib/errors';
export { ProblemDetail } from './lib/errors';
import {
    createPrefix, isDatasetCore, convertToStore, DatasetMap, MapContent,
    textToArrayBuffer, calculateDatasetHash, arrayBufferToBase64Url, base64UrlToArrayBuffer,
 }  from './lib/utils';

// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;

/** Values used internally for the crypto functions; they are defined by the WebCrypto spec. */
export enum Confidentiality {
    public = "public",
    secret = "secret"
}

export interface VerificationResult {
    verified         : boolean,
    verifiedDocument : rdf.DatasetCore,
    warnings         : ProblemDetail[]; 
    errors           : ProblemDetail[];
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
 * Namespaces and specific terms that are used several times
 **************************************************************************************/

/* Various namespaces, necessary when constructing a proof graph */
const sec_prefix = createPrefix("https://w3id.org/security#");
const rdf_prefix = createPrefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
const xsd_prefix = createPrefix("http://www.w3.org/2001/XMLSchema#");

const rdf_type: rdf.NamedNode                 = rdf_prefix('type');   
const sec_proof: rdf.NamedNode                = sec_prefix('proof');
const sec_proofGraph: rdf.NamedNode           = sec_prefix('ProofGraph');
const sec_di_proof: rdf.NamedNode             = sec_prefix('DataIntegrityProof');
const sec_proofValue: rdf.NamedNode           = sec_prefix('proofValue');
const sec_publicKeyJwk: rdf.NamedNode         = sec_prefix('publicKeyJwk');
const sec_proofPurpose: rdf.NamedNode         = sec_prefix('proofPurpose');
const sec_authenticationMethod: rdf.NamedNode = sec_prefix('authenticationMethod')
const sec_assertionMethod: rdf.NamedNode      = sec_prefix('assertionMethod');
const sec_verificationMethod: rdf.NamedNode   = sec_prefix('verificationMethod');
const sec_expires: rdf.NamedNode              = sec_prefix('expires');
const sec_revoked: rdf.NamedNode              = sec_prefix('revoked');
const sec_created: rdf.NamedNode              = sec_prefix('created');
const xsd_datetime: rdf.NamedNode             = xsd_prefix('dateTime');



/*****************************************************************************************
 * The real meat...
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
    protected _result      : VerificationResult;

    constructor() {
        this._hash = "SHA-256";
        this.initResults();
    }

    protected initResults() {
        this._result = {
            verified         : false,
            verifiedDocument : null,
            warnings         : [],
            errors           : [],
        }
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
     */
    protected async importKey(key: JsonWebKey, type: Confidentiality): Promise<CryptoKey | null> {
        try {
            const retval = await crypto.subtle.importKey("jwk", key,
                {
                    name: this._algorithm,
                    namedCurve: this._curve,
                },
                true,
                type === Confidentiality.public ? ["verify"] : ["sign"]
            );
            if (retval === null) {
                this._result.errors.push(new errors.Invalid_Verification_Method(`Invalid key: ${JSON.stringify(key,null,4)}`));
            }
            return retval;
        } catch(e) {
            this._result.errors.push(new errors.Invalid_Verification_Method(`Invalid key: ${JSON.stringify(key)} (${e.message})`));
            return null;
        }
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
            if (key === null) {
                return "";
            } else {
                const raw_signature: ArrayBuffer = await crypto.subtle.sign(
                    {
                        name: this._algorithm,
                        hash: this._hash
                    },
                    key,
                    textToArrayBuffer(hashValue)
                );
                return `u${arrayBufferToBase64Url(raw_signature)}`;
            }
        };

        // Create a proof graph. Just a boring set of quad generations...
        const createProofGraph = (proofValue: string): rdf.DatasetCore => {
            const retval: n3.Store = new n3.Store();

            // Unique URL-s, for the time being as uuid-s
            const proofGraphId = `urn:uuid:${uuid()}`;
            const proofGraph = namedNode(proofGraphId);

            const verificationMethodId = `urn:uuid:${uuid()}`
            const keyResource = namedNode(verificationMethodId);

            retval.addQuads([
                quad(
                    proofGraph, rdf_type, sec_di_proof
                ),
                quad(
                    proofGraph, sec_prefix('cryptosuite'), literal(this._cryptosuite)
                ),
                quad(
                    proofGraph, sec_created, literal((new Date()).toISOString(), xsd_datetime)
                ),
                quad(
                    proofGraph, sec_verificationMethod, keyResource
                ),
                quad(
                    proofGraph, sec_proofValue, literal(proofValue)
                ),
                quad(
                    proofGraph, sec_proofPurpose, sec_authenticationMethod
                ),
                quad(
                    proofGraph, sec_proofPurpose, sec_assertionMethod
                ),

                quad(
                    keyResource, rdf_type, sec_prefix('JsonWebKey')
                ),
                quad(
                    keyResource, sec_publicKeyJwk, literal(JSON.stringify(keyPair.public), rdf_prefix('JSON'))
                ),
            ]);
            if (keyPair.controller) retval.add(quad(keyResource, sec_prefix('controller'), namedNode(keyPair.controller)));
            if (keyPair.expires) retval.add(quad(keyResource, sec_expires, literal(keyPair.expires, xsd_datetime)));
            if (keyPair.revoked) retval.add(quad(keyResource, sec_revoked, literal(keyPair.revoked, xsd_datetime)));
            return retval;
        };
        return createProofGraph(await signHashValue());
    }

    /**
     * Check one proof graph, ie, whether the included signature corresponds to the hash value.
     * 
     * The following checks are also made and, possibly, exception are raised with errors according to 
     * the DI standard:
     * 
     * 1. There should be exactly one proof value
     * 2. There should be exactly one verification method, which should be a separate resource containing the key
     * 3. The key's possible expiration and revocation dates are checked and compared to the current time which should be
     * "before"
     * 4. The proof's creation date must be before the current time
     * 5. The proof purpose(s) must be set, and the values are either authentication or verification
     * 
     * @param hash 
     * @param proof 
     * @returns 
     */
    protected async verifyAProofGraph(hash: string, proof: n3.Store, proofId?: rdf.Quad_Graph): Promise<boolean> {
        let localErrors   : errors.ProblemDetail[] = [];
        let localWarnings : errors.ProblemDetail[] = [];

        // Verify the signature by check signature of the hash with the key
        // This is the "core"...
        const checkHashValue = async (proof_value: string, key_jwk: JsonWebKey): Promise<boolean> => {
            const key: CryptoKey = await this.importKey(key_jwk, Confidentiality.public);
            const signature_array: ArrayBuffer = base64UrlToArrayBuffer(proof_value.slice(1));
            const data: ArrayBuffer = textToArrayBuffer(hash);
            if (key === null) {
                return false;
            } else {
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
            }
        };

        const getProofValue = (store: n3.Store): string | null => {
            // Retrieve the signature value per spec:
            const proof_values: rdf.Quad[] = store.getQuads(null, sec_proofValue, null, null);
            if (proof_values.length === 0) {
                localErrors.push(new errors.Malformed_Proof_Error("No proof value"));
                return null;
            } else if(proof_values.length > 1) {
                localErrors.push(new errors.Malformed_Proof_Error("Several proof values"));
            }
            return proof_values[0].object.value;
        };

        const getPublicKey = (store: n3.Store): JsonWebKey | null => {
            // first see if the verificationMethod has been set properly
            const verificationMethod: rdf.Quad[] = store.getQuads(null, sec_verificationMethod, null, null);
            if (verificationMethod.length === 0) {
                localErrors.push(new errors.Malformed_Proof_Error("No verification method"));
                return null;
            } else if (verificationMethod.length > 1) {
                localErrors.push(new errors.Malformed_Proof_Error("Several verification methods"));
            }

            const publicKey = verificationMethod[0].object;
            const keys: rdf.Quad[] = store.getQuads(publicKey, sec_publicKeyJwk, null, null);
            if (keys.length === 0) {
                localErrors.push(new errors.Invalid_Verification_Method(`No key values`));
                return null;
            } else if (keys.length > 1) {
                localErrors.push(new errors.Invalid_Verification_Method("More than one keys provided"));
            }

            // Check the creation/expiration/revocation dates, if any...
            const now = new Date();
            const creationDates: rdf.Quad[] = store.getQuads(null, sec_created, null, null);
            for (const exp of creationDates) {
                if ((new Date(exp.object.value)) > now) {
                    localWarnings.push(new errors.Invalid_Verification_Method(`Proof was created in the future... ${exp.object.value}`));
                }
            }

            const expirationDates: rdf.Quad[] = store.getQuads(publicKey, sec_expires, null, null);
            for (const exp of expirationDates) {
                if ((new Date(exp.object.value)) < now) {
                    localErrors.push(new errors.Invalid_Verification_Method(`<${publicKey.value}> key expired on ${exp.object.value}`));
                    return null;
                }
            }
            const revocationDates: rdf.Quad[] = store.getQuads(publicKey, sec_revoked, null, null);
            for (const exp of revocationDates) {
                if ((new Date(exp.object.value)) < now) {
                    localErrors.push(new errors.Invalid_Verification_Method(`<${publicKey.value}> key was revoked on ${exp.object.value}`));
                    return null;
                }
            }

            try {
                return JSON.parse(keys[0].object.value) as JsonWebKey;
            } catch(e) {
                // This happens if there is a JSON parse error with the key...
                localWarnings.push(new errors.Malformed_Proof_Error(`Parsing error for JWK: ${e.message}`));
                return null;
            }
        };

        // Check the "proofPurpose" property value
        const checkProofPurposes = (store: n3.Store): void => {
            const purposes: rdf.Quad[] = store.getQuads(null, sec_proofPurpose, null, null);
            if (purposes.length === 0) {
                throw new errors.Invalid_Verification_Method("No proof purpose set");
            } else {
                const wrongPurposes: string[] = [];
                for (const q of purposes) {
                    if (!(q.object.equals(sec_authenticationMethod) || q.object.equals(sec_assertionMethod))) {
                        wrongPurposes.push(`<${q.object.value}>`);
                    }
                }
                if (wrongPurposes.length > 0) {
                    localErrors.push(new errors.Mismatched_Proof_Purpose(`Invalid proof purpose value(s): ${wrongPurposes.join(", ")}`));
                }
            }
        }

        // Retrieve necessary values with checks
        checkProofPurposes(proof);
        const publicKey: JsonWebKey = getPublicKey(proof);
        const proofValue: string = getProofValue(proof);

        // The final set of error/warning should be modified with the proof graph's ID, if applicable
        if (proofId) {
            localErrors.forEach((error) => {
                error.detail = `${error.detail} (graph ID: <${proofId.value}>)`;
            });
            localWarnings.forEach((warning) => {
                warning.detail = `${warning.detail} (<${proofId.value}>)`;
            })
        }
        this._result.errors  = [...this._result.errors, ...localErrors];
        this._result.warnings = [...this._result.warnings, ...localWarnings];

        // Here we go with checking...
        if (publicKey !== null && proofValue !== null) {
            const check_results: boolean = await checkHashValue(proofValue, publicKey);
            // the return value should nevertheless be false if there have been errors
            return check_results ? localErrors.length === 0 : true
        } else {
            return false;
        }
    }


    /**
     * Generate a (separate) proof graph (or graphs), per the DI spec. The signature is stored in 
     * multibase format, using base64url encoding.
     * 
     * This is just a wrapper around {@link generateAProofGraph} to take care of multiple key pairs.
     * 
     * @param dataset 
     * @param keyPair 
     * @throws - an error if there was a key issue while signing.
     * @returns 
     */
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: Iterable<KeyPair>): Promise<rdf.DatasetCore[]>;
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair): Promise<rdf.DatasetCore>;
    async generateProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair | Iterable<KeyPair>): Promise<rdf.DatasetCore | rdf.DatasetCore[]> {
        // Start fresh with results
        this.initResults();

        // This is to be signed
        const toBeSigned = await calculateDatasetHash(dataset);
        // prepare for the overload of arguments
        const keyPairs: Iterable<KeyPair> = isKeyPair(keyPair) ? [keyPair] : keyPair;
        // execute the proof graph generation concurrently
        const promises: Promise<rdf.DatasetCore>[] = Array.from(keyPairs).map((keypair: KeyPair) => this.generateAProofGraph(toBeSigned, keypair));
        const retval: rdf.DatasetCore[] = await Promise.all(promises);
        // return by taking care of overloading.
        if (this._result.errors.length !== 0) {
            // There were possible errors while generating the signatures
            const message: string = JSON.stringify(this._result.errors,null,2);
            throw new errors.Proof_Generation_Error(message);
        } else {
            return isKeyPair(keyPair) ? retval[0] : retval;
        }
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
        // start fresh with the results:
        this.initResults();
        
        // this is the value that must be checked...
        const hash = await calculateDatasetHash(dataset);

        // just to make the handling uniform...
        const proofs: rdf.DatasetCore[] = isDatasetCore(proofGraph) ? [proofGraph] : proofGraph;

        // the "convertToStore" intermediate step is necessary; the proof graph checker needs a n3.Store
        const promises: Promise<boolean>[] = proofs.map(convertToStore).map((pr_graph: n3.Store): Promise<boolean> => this.verifyAProofGraph(hash, pr_graph));
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
     * If the `keyPair` argument is an Array, then the proof graphs are considered to be a Proof Chain. Otherwise,
     * (e.g., if it is a Set), it is a Proof Set.
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

        const isKeyChain: boolean = keyPairs.length > 1 && Array.isArray(keyPair);
        const chain: { graph: rdf.BlankNode, proofId: rdf.Quad_Subject }[] = [];

        for (let i = 0; i < proofGraphs.length; i++) {
            const proofTriples = proofGraphs[i];
            const proofGraphID = retval.createBlankNode();
            for (const q of proofTriples) {
                retval.add(quad(q.subject, q.predicate, q.object, proofGraphID));
                if (isKeyChain && q.predicate.value === rdf_type.value && q.object.value === sec_di_proof.value) {
                    // Storing the values to create the proof chains in a subsequent step
                    // The subject is the ID of the proof
                    chain.push ({
                        proofId: q.subject,
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
     * The following checks are also made and, possibly, exception are raised with errors according to 
     * the DI standard:
     * 
     * 1. There should be exactly one proof value
     * 2. There should be exactly one verification method, which should be a separate resource containing the key
     * 3. The key's possible expiration and revocation dates are checked and compared to the current time which should be
     * "before"
     * 4. The proof's creation date must be before the current time
     * 5. The proof purpose(s) must be set, and the values are either authentication or verification

    * @param dataset 
     * @returns 
     */
    async verifyEmbeddedProofGraph(dataset: rdf.DatasetCore): Promise<VerificationResult> {
        // start fresh with the results:
        this.initResults();

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
                // Note that the proof graphs contain only triples, because they are 
                // separate entities now...
                proofGraphs.item(q.graph).add(quad(q.subject, q.predicate, q.object));
            } else {
                // This a bona fide data quad
                dataStore.add(q);
            }
        }

        const hash = await calculateDatasetHash(dataStore);

        const proofs: MapContent[] = proofGraphs.data(); 
        const promises: Promise<boolean>[] = proofs.map((prGraph: MapContent): Promise<boolean> => this.verifyAProofGraph(hash, prGraph.dataset, prGraph.id));
        const results: boolean[] = await Promise.all(promises);

        if (this._result.errors.length > 0) {
            this._result.verified = false;
        } else {
            this._result.verified = !results.includes(false);
        }
        this._result.verifiedDocument = this._result.verified ? dataStore : null;
        return this._result
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


