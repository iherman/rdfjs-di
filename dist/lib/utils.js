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
exports.convertToStore = exports.calculateDatasetHash = exports.isKeyData = exports.isDatasetCore = exports.DatasetMap = exports.createPrefix = void 0;
const rdfjs_c14n_1 = require("rdfjs-c14n");
const n3 = require("n3");
const { namedNode } = n3.DataFactory;
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
     * @param graph
     * @returns
     */
    item(graph) {
        if (this.index.has(graph.value)) {
            // The '?' operator is to make deno happy. By virtue of the 
            // test we know that the value cannot be undefined, but
            // the deno checker does not realize this...
            return this.index.get(graph.value)?.dataset;
        }
        else {
            const dataset = new n3.Store();
            this.index.set(graph.value, {
                id: graph,
                dataset
            });
            return dataset;
        }
    }
    has(graph) {
        return this.index.has(graph.value);
    }
    datasets() {
        return Array.from(this.index.values()).map((entry) => entry.dataset);
    }
    data() {
        return Array.from(this.index.values());
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
