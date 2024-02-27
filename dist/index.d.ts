import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
/** Values used internally for the crypto functions; they are defined by the WebCrypto spec. */
export declare enum Confidentiality {
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
    public: JsonWebKey;
    private: JsonWebKey;
    controller?: string;
    expires?: string;
    revoked?: string;
}
/*****************************************************************************************
 * The real meat...
 *****************************************************************************************/
/**
 * Subclasses are supposed to set the right algorithm, cryptosuite, etc, names.
 *
 */
declare abstract class DataIntegrity {
    protected _algorithm: string;
    protected _cryptosuite: string;
    protected _hash: string;
    protected _curve: string;
    constructor();
    /**************************************************************************************************/
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
    protected importKey(key: JsonWebKey, type: Confidentiality): Promise<CryptoKey>;
    /**
     * Generate a (separate) proof graph, per the DI spec. The signature is stored in
     * multibase format, using base64url encoding.
     *
     * @param hashValue - this is the value of the Dataset's canonical hash
     * @param keyPair
     * @returns
     */
    protected generateAProofGraph(hashValue: string, keyPair: KeyPair): Promise<rdf.DatasetCore>;
    /**
     * Check one proof graph, ie, whether the included signature corresponds to the hash value
     *
     * @param hash
     * @param proof
     * @returns
     */
    protected validateProofGraph(hash: string, proof: n3.Store): Promise<boolean>;
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
    generateProofGraph(dataset: rdf.DatasetCore, keyPair: Iterable<KeyPair>): Promise<rdf.DatasetCore[]>;
    generateProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair): Promise<rdf.DatasetCore>;
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
    verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore): Promise<boolean>;
    verifyProofGraph(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore[]): Promise<boolean[]>;
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
    embedProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair | Iterable<KeyPair>, anchor?: rdf.Quad_Subject): Promise<rdf.DatasetCore>;
    /**
     * Verify the dataset with embedded proof graphs. The individual proof graphs are identified by the presence
     * of a type relationship to `DataIntegrityProof`; the result is the conjunction of the validation result for
     * each proof graphs separately.
     *
     * @param dataset
     * @returns
     */
    verifyEmbeddedProofGraph(dataset: rdf.DatasetCore): Promise<boolean>;
}
/**
 * Real instantiation of a DI cryptosuite: ecdsa-2022.
 */
export declare class DI_ECDSA extends DataIntegrity {
    constructor();
}
export {};
