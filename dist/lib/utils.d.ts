/**
 * Collection of smaller utilities needed for the DI implementation.
 *
 * Put into a separate file for an easier maintenance; not meant
 * to be part of the external API.
 * They are not exported (via `index.ts`) to
 * package users.
 *
 * @packageDocumentation
 *
 */
import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
/***************************************************************************************
 * Namespace handling
 **************************************************************************************/
/**
 * A simple namespace handler; I was not sure I fully understood the n3 version, and
 * I found no reliable documentation (...)
 *
 * This function returns a function that can be used to generate a proper URI for a given prefix.
 *
 * @param uri
 * @returns
 */
export declare function createPrefix(uri: string): (l: string) => rdf.NamedNode;
/***************************************************************************************
 * Map to help separating the content of a dataset into several different datasets.
 * Needed to separate the proof graphs from the "real" data
 **************************************************************************************/
/**
 * The general structure for a Proof
 */
export interface Proof {
    /**
     * A collection of statements for a proof is to be in its own graph, generally with a blank node.
     *
     * Note that the type restriction for this term is `Quad_Subject`, which stands for a term or a blank node, which is
     * more restrictive than a `Quad_Graph`, which may also have the value of a default graph. But proofs are always
     * real graphs.
     */
    proofGraph: rdf.Quad_Graph;
    /** The proof ID, which, in this implementation, is never a blank node, usually a UUID */
    proofId?: rdf.Quad_Subject;
    /** The proof statements themselves, a set of triples (not quads) */
    proofQuads: rdf.DatasetCore;
}
/**
 * The general structure for a Proof using n3.Store specifically; it also has a `perviousProof` key.
 * This subclass is used when key chains or sets are extracted from an embedded proof.
 */
export interface ProofStore extends Proof {
    proofQuads: n3.Store;
    previousProof?: rdf.Quad_Subject;
}
/**
 * A shell around a Map, which is indexed by the *value* of rdf Terms.
 *
 * (At the moment, the map value is a structure, that also includes
 * the original term; that may become unnecessary on long term.)
 */
export declare class DatasetMap {
    private index;
    constructor();
    /**
     * Create a new dataset, if needed, otherwise returns the
     * dataset already stored.
     *
     * See the remark above for the graph value's type constraint: it is o.k. to use `Quad_Subject`, because it
     * should never be a default graph.
     *
     * @param graph
     * @returns
     */
    item(graph: rdf.Quad_Graph): n3.Store;
    /**
     * Get a proof, or `undefined` if it has not been stored yet
     *
     * @param graph
     * @returns - the proof store data
     */
    get(graph: rdf.Quad_Graph): ProofStore | undefined;
    /**
     * Set a proof
     *
     * @param graph
     * @returns - the current dataset map
     */
    set(graph: rdf.Quad_Graph): DatasetMap;
    /**
     * Has a proof been stored with this graph reference/
     *
     * @param graph
     * @returns
     */
    has(graph: rdf.Term): boolean;
    /**
     * Get the dataset references (in no particular order)
     *
     * @returns - the datasets
     */
    datasets(): n3.Store[];
    /**
     * Get the proof entries (in no particular order)
     * @returns - the proof entries
     */
    data(): ProofStore[];
    /**
     * Get the proof entries, following the order imposed by the `previousProof` statements. First element is the one that has no previous proof defined. If there are no nodes with previous proof, an empty array is returned.
     *
     * This is equivalent to the way proof chains are passed on as arguments when embedded chains are created.
     *
     * @returns - the proofs entries
     */
    orderedData(): ProofStore[];
}
/*****************************************************************************************
 * Misc Utility Functions
 *****************************************************************************************/
/**
 * Type guard to check if an object implements the rdf.DatasetCore interface.
 *
 * @param obj
 * @returns
 */
export declare function isDatasetCore(obj: any): obj is rdf.DatasetCore;
/**
 * Type guard to check if an object implements the CryptoKeyPair interface.
 *
 * @param obj
 * @returns
 */
export declare function isKeyData(obj: any): obj is CryptoKeyPair;
/**
 * Calculate the canonical hash of a dataset using the implementation of RDFC 1.0.
 *
 * Note that the hash calculation's detail depend on the crypto key being used.
 * If the key belongs to an ECDSA key, and the corresponding curve is P-384, then
 * SHA-384 must be used by the algorithm. Hence the presence of the second
 * argument in the call.
 *
 * @param dataset
 * @param key - to decide whether SHA-384 should be used instead of the (default) SHA-256
 * @returns
 */
export declare function calculateDatasetHash(dataset: rdf.DatasetCore, key?: CryptoKey): Promise<string>;
/**
 * Create and store the values in a dataset in a new n3 Store. This may be
 * necessary because the methods are not supposed to modify the original
 * dataset.
 *
 * The n3.Store objects includes functions to retrieve quads, which is a great plus
 *
 * @param dataset
 * @returns
 */
export declare function copyToStore(dataset: rdf.DatasetCore): n3.Store;
/**
 * Convert the dataset into an n3.Store, unless it is already a store.
 * This is done to manage the various quads more efficiently.
 *
 * @param dataset
 * @returns
 */
export declare function convertToStore(dataset: rdf.DatasetCore): n3.Store;
/**
 * "Refactor" BNodes in a dataset: bnodes are replaced by new one to avoid a clash with the base dataset.
 * Extremely inefficient, but is used for very small graphs only (proof graphs), so efficiency is not really an issue.
 *
 * The trick is to use the bnode generator of the base dataset, and that should make it unique...
 *
 * @param base
 * @param toTransform
 */
export declare function refactorBnodes(base: n3.Store, toTransform: rdf.DatasetCore): rdf.DatasetCore;
/**
 * When handling proof chains, the dataset must be temporarily extended with a number of quads that
 * constitute the "previous" proof. This function calculates those extra quads.
 *
 * @param allProofs - the array of Proofs in chain order
 * @param index - current index into allProofs
 * @param anchor - the possible anchor that includes the `proof` reference triple
 * @returns
 */
export declare function extraChainQuads(allProofs: Proof[], index: number, anchor?: rdf.Quad_Subject): rdf.Quad[];
