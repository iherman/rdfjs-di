"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.extraChainQuads = exports.refactorBnodes = exports.convertToStore = exports.copyToStore = exports.calculateDatasetHash = exports.isKeyData = exports.isDatasetCore = exports.DatasetMap = exports.createPrefix = void 0;
const rdfjs_c14n_1 = require("rdfjs-c14n");
const n3 = require("n3");
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
function createPrefix(uri) {
    class prefix {
        _mapping = {};
        _base;
        constructor(base) {
            this._base = base;
        }
        value(local) {
            if (local in this._mapping) {
                return this._mapping[local];
            }
            else {
                const retval = namedNode(`${this._base}${local}`);
                this._mapping[local] = retval;
                return retval;
            }
        }
    }
    const mapping = new prefix(uri);
    const get_value = (local) => {
        return mapping.value(local);
    };
    return get_value;
}
exports.createPrefix = createPrefix;
/**
 * A shell around a Map, which is indexed by the *value* of rdf Terms.
 *
 * (At the moment, the map value is a structure, that also includes
 * the original term; that may become unnecessary on long term.)
 */
class DatasetMap {
    index;
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
    item(graph) {
        const proofStore = this.get(graph);
        return proofStore?.proofQuads;
    }
    /**
     * Get a proof, or `undefined` if it has not been stored yet
     *
     * @param graph
     * @returns - the proof store data
     */
    get(graph) {
        if (this.index.has(graph.value)) {
            return this.index.get(graph.value);
        }
        else {
            return undefined;
        }
    }
    /**
     * Set a proof
     *
     * @param graph
     * @returns - the current dataset map
     */
    set(graph) {
        if (!this.index.has(graph.value)) {
            const dataset = new n3.Store();
            const proofStore = {
                proofGraph: graph,
                proofQuads: dataset,
            };
            this.index.set(graph.value, proofStore);
        }
        return this;
    }
    /**
     * Has a proof been stored with this graph reference/
     *
     * @param graph
     * @returns
     */
    has(graph) {
        return this.index.has(graph.value);
    }
    /**
     * Get the dataset references (in no particular order)
     *
     * @returns - the datasets
     */
    datasets() {
        return Array.from(this.index.values()).map((entry) => entry.proofQuads);
    }
    /**
     * Get the proof entries (in no particular order)
     * @returns - the proof entries
     */
    data() {
        return Array.from(this.index.values());
    }
    /**
     * Get the proof entries, following the order imposed by the `previousProof` statements. First element is the one that has no previous proof defined. If there are no nodes with previous proof, an empty array is returned.
     *
     * This is equivalent to the way proof chains are passed on as arguments when embedded chains are created.
     *
     * @returns - the proofs entries
     */
    orderedData() {
        const stores = this.data();
        // Look for the start of the chain
        const start = (() => {
            for (const proof of stores) {
                if (proof.previousProof === undefined) {
                    return proof;
                }
            }
            return undefined;
        })();
        if (start === undefined) {
            return [];
        }
        else {
            const output = [start];
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
exports.DatasetMap = DatasetMap;
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
function isDatasetCore(obj) {
    return obj.add !== undefined &&
        obj.delete !== undefined &&
        obj.match !== undefined &&
        obj.has !== undefined;
}
exports.isDatasetCore = isDatasetCore;
/**
 * Type guard to check if an object implements the KeyPair interface.
 *
 * @param obj
 * @returns
 */
// deno-lint-ignore no-explicit-any
function isKeyData(obj) {
    return obj.public !== undefined && obj.private !== undefined;
}
exports.isKeyData = isKeyData;
/**
 * Calculate the canonical hash of a dataset using the implementation of RDFC 1.0.
 *
 * @param dataset
 * @returns
 */
async function calculateDatasetHash(dataset) {
    const rdfc10 = new rdfjs_c14n_1.RDFC10();
    const canonical_quads = await rdfc10.canonicalize(dataset);
    const datasetHash = await rdfc10.hash(canonical_quads);
    return datasetHash;
}
exports.calculateDatasetHash = calculateDatasetHash;
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
function copyToStore(dataset) {
    const retval = new n3.Store();
    for (const q of dataset)
        retval.add(q);
    return retval;
}
exports.copyToStore = copyToStore;
/**
 * Convert the dataset into an n3.Store, unless it is already a store.
 * This is done to manage the various quads more efficiently.
 *
 * @param dataset
 * @returns
 */
function convertToStore(dataset) {
    return (dataset instanceof n3.Store) ? dataset : copyToStore(dataset);
}
exports.convertToStore = convertToStore;
/**
 * "Refactor" BNodes in a dataset: bnodes are replaced by new one to avoid a clash with the base dataset.
 * Extremely inefficient, but is used for very small graphs only (proof graphs), so efficiency is not really an issue.
 *
 * The trick is to use the bnode generator of the base dataset, and that should make it unique...
 *
 * @param base
 * @param toTransform
 */
function refactorBnodes(base, toTransform) {
    const bNodeMapping = new Map();
    const newTerm = (term) => {
        if (term.termType === "BlankNode") {
            if (bNodeMapping.has(term.value)) {
                return bNodeMapping.get(term.value);
            }
            else {
                const bnode = base.createBlankNode();
                bNodeMapping.set(term.value, bnode);
                return bnode;
            }
        }
        else {
            return term;
        }
    };
    const retval = new n3.Store();
    for (const q of toTransform) {
        let subject = newTerm(q.subject);
        let predicate = q.predicate;
        let object = newTerm(q.object);
        retval.add(quad(subject, predicate, object));
    }
    return retval;
}
exports.refactorBnodes = refactorBnodes;
/**
 * When handling proof chains, the dataset must be temporarily extended with a number of quads that
 * constitute the "previous" proof. This function calculates those extra quads.
 *
 * @param allProofs - the array of Proofs in chain order
 * @param index - current index into allProofs
 * @param anchor - the possible anchor that includes the `proof` reference triple
 * @returns
 */
function extraChainQuads(allProofs, index, anchor) {
    if (index !== 0) {
        // if there is an anchor, then the intermediate store gets an extra triple
        const previousProof = allProofs[index - 1];
        const output = Array.from(previousProof.proofQuads).map((q) => {
            return quad(q.subject, q.predicate, q.object, previousProof.proofGraph);
        });
        if (anchor)
            output.push(quad(anchor, namedNode('https://w3id.org/security#proof'), previousProof.proofGraph));
        return output;
    }
    else {
        return [];
    }
}
exports.extraChainQuads = extraChainQuads;
