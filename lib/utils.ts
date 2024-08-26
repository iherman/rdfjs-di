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

import { RDFC10 }               from 'rdfjs-c14n';
import * as rdf                 from '@rdfjs/types';
import * as n3                  from 'n3';
import * as debug               from './debug';

const { namedNode, quad } = n3.DataFactory;

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
export function createPrefix(uri: string): (l: string) => rdf.NamedNode {
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
    proofGraph : rdf.Quad_Graph, 

    /** The proof ID, which, in this implementation, is never a blank node, usually a UUID */
    proofId ?:   rdf.Quad_Subject,   

    /** The proof statements themselves, a set of triples (not quads) */
    proofQuads : rdf.DatasetCore,   
}

/**
 * The general structure for a Proof using n3.Store specifically; it also has a `perviousProof` key. 
 * This subclass is used when key chains or sets are extracted from an embedded proof.
 */
export interface ProofStore extends Proof {
    proofQuads : n3.Store,
    previousProof ?: rdf.Quad_Subject,
}

/**
 * A shell around a Map, which is indexed by the *value* of rdf Terms.
 * 
 * (At the moment, the map value is a structure, that also includes
 * the original term; that may become unnecessary on long term.)
 */
export class DatasetMap {
    private index: Map<string, ProofStore>;

    constructor() {
        this.index = new Map();
    }

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
    item(graph: rdf.Quad_Graph): n3.Store {
        const proofStore = this.get(graph);
        return proofStore?.proofQuads;
    }

    /**
     * Get a proof, or `undefined` if it has not been stored yet
     * 
     * @param graph 
     * @returns - the proof store data
     */
    get(graph: rdf.Quad_Graph): ProofStore | undefined {
        if (this.index.has(graph.value)) {
            return this.index.get(graph.value);
        } else {
            return undefined;
        }
    }

    /**
     * Set a proof
     * 
     * @param graph 
     * @returns - the current dataset map
     */
    set(graph: rdf.Quad_Graph): DatasetMap {
        if (!this.index.has(graph.value)) {
            const dataset = new n3.Store();
            const proofStore: ProofStore = {
                proofGraph: graph,
                proofQuads: dataset,
            };
            this.index.set(graph.value, proofStore);
        }
        return this
    }

    /**
     * Has a proof been stored with this graph reference/
     * 
     * @param graph 
     * @returns 
     */
    has(graph: rdf.Term): boolean {
        return this.index.has(graph.value);
    }

    /**
     * Get the dataset references (in no particular order)
     * 
     * @returns - the datasets
     */
    datasets(): n3.Store[] {
        return Array.from(this.index.values()).map((entry) => entry.proofQuads);
    }

    /**
     * Get the proof entries (in no particular order)
     * @returns - the proof entries
     */
    data(): ProofStore[] {
        return Array.from(this.index.values());
    }

    /**
     * Get the proof entries, following the order imposed by the `previousProof` statements. First element is the one that has no previous proof defined. If there are no nodes with previous proof, an empty array is returned.
     * 
     * This is equivalent to the way proof chains are passed on as arguments when embedded chains are created.
     * 
     * @returns - the proofs entries
     */
    orderedData(): ProofStore[] {
        const stores: ProofStore[] = this.data();

        // Look for the start of the chain
        const start: ProofStore = ((): ProofStore => {
            for (const proof of stores) {
                if (proof.previousProof === undefined) {
                    return proof;
                }
            }
            return undefined;
        })();

        if (start === undefined) {
            return [];
        } else {
            const output: ProofStore[] = [start];
            let current = start;
            nextInChain: for (; true;) {
                for (const q of stores) {
                    if (q.previousProof && q.previousProof.equals(current.proofId)) {
                        output.push(q);
                        current = q;
                        continue nextInChain;
                    }
                }
                // If we get there, we got to a proof that is never referred to as 'previous'
                // which should be the end of the chain...
                return output;
            }
        }    
    }
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
// deno-lint-ignore no-explicit-any
export function isDatasetCore(obj: any): obj is rdf.DatasetCore {
    return (obj as rdf.DatasetCore).add !== undefined &&
        (obj as rdf.DatasetCore).delete !== undefined &&
        (obj as rdf.DatasetCore).match !== undefined &&
        (obj as rdf.DatasetCore).has !== undefined;
}


/**
 * Type guard to check if an object implements the CryptoKeyPair interface.
 * 
 * @param obj 
 * @returns 
 */
// deno-lint-ignore no-explicit-any
export function isKeyData(obj: any): obj is CryptoKeyPair {
    return (obj as CryptoKeyPair).publicKey !== undefined && (obj as CryptoKeyPair).privateKey !== undefined;
}

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
export async function calculateDatasetHash(dataset: rdf.DatasetCore, key ?: CryptoKey): Promise<string> {
    const rdfc10 = new RDFC10();

    // Per cryptosuite specification if ECDSA+P-384 is used, the whole world should use SHA-384...
    if (key.algorithm.name === "ECDSA" && (key.algorithm as EcKeyAlgorithm)?.namedCurve === "P-384") {
        rdfc10.hash_algorithm = "sha384";
    }

    const canonical_quads: string = await rdfc10.canonicalize(dataset);
    const datasetHash: string = await rdfc10.hash(canonical_quads);
    return datasetHash;
}

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
export function copyToStore(dataset: rdf.DatasetCore): n3.Store {
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
export function convertToStore(dataset: rdf.DatasetCore): n3.Store {
    return (dataset instanceof n3.Store) ? dataset : copyToStore(dataset);
}

/**
 * "Refactor" BNodes in a dataset: bnodes are replaced by new one to avoid a clash with the base dataset.
 * Extremely inefficient, but is used for very small graphs only (proof graphs), so efficiency is not really an issue.
 * 
 * The trick is to use the bnode generator of the base dataset, and that should make it unique...
 * 
 * @param base 
 * @param toTransform
 */
export function refactorBnodes(base: n3.Store, toTransform: rdf.DatasetCore): rdf.DatasetCore {
    type BNodeId = string;
    const bNodeMapping: Map<BNodeId, rdf.BlankNode> = new Map();
    const newTerm = (term: rdf.Quad_Subject | rdf.Quad_Object): rdf.Quad_Subject | rdf.Quad_Object => {
        if (term.termType === "BlankNode") {
            if (bNodeMapping.has(term.value)) {
                return bNodeMapping.get(term.value);
            } else {
                const bnode = base.createBlankNode();
                bNodeMapping.set(term.value, bnode);
                return bnode;
            }
        } else {
            return term;
        }
    }

    const retval: n3.Store = new n3.Store();
    for(const q of toTransform) {
        let subject = newTerm(q.subject) as rdf.Quad_Subject;
        let predicate = q.predicate;
        let object = newTerm(q.object) as rdf.Quad_Object;
        retval.add(quad(subject,predicate,object));
    }
    return retval;
}


/**
 * When handling proof chains, the dataset must be temporarily extended with a number of quads that
 * constitute the "previous" proof. This function calculates those extra quads.
 * 
 * @param allProofs - the array of Proofs in chain order 
 * @param index - current index into allProofs
 * @param anchor - the possible anchor that includes the `proof` reference triple
 * @returns 
 */
export function extraChainQuads(allProofs: Proof[], index: number, anchor?: rdf.Quad_Subject): rdf.Quad[] {
    if (index !== 0) {
        // if there is an anchor, then the intermediate store gets an extra triple
        const previousProof = allProofs[index - 1];
        const output: rdf.Quad[] = Array.from(previousProof.proofQuads).map((q:rdf.Quad): rdf.Quad => {
            return quad(q.subject, q.predicate, q.object, previousProof.proofGraph);
        });
        if (anchor) output.push(quad(anchor, namedNode('https://w3id.org/security#proof'), previousProof.proofGraph as rdf.Quad_Object));
        return output;
    } else {
        return [];
    }
}
