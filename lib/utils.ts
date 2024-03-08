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

import { RDFC10 } from 'rdfjs-c14n';
import * as rdf   from '@rdfjs/types';
import * as n3    from 'n3';
import { KeyPair, KeyMetadata } from './types';
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
 * Structure with a separate store and its ID as a graph
 */
export interface GraphWithID {
    id:       rdf.Quad_Graph | undefined,
    dataset : n3.Store;
}

/**
 * A shell around a Map, which is indexed by the *value* of rdf Terms.
 * 
 * (At the moment, the map value is a structure, that also includes
 * the original term; that may become unnecessary on long term.)
 */
export class DatasetMap {
    private index: Map<string, GraphWithID>;

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
    item(graph: rdf.Quad_Graph): n3.Store {
        if (this.index.has(graph.value)) {
            // The '?' operator is to make deno happy. By virtue of the 
            // test we know that the value cannot be undefined, but
            // the deno checker does not realize this...
            return this.index.get(graph.value)?.dataset;
        } else {
            const dataset = new n3.Store();
            this.index.set(graph.value, {
                id: graph,
                dataset
            });
            return dataset;
        }
    }

    has(graph: rdf.Term): boolean {
        return this.index.has(graph.value);
    }

    datasets(): n3.Store[] {
        return Array.from(this.index.values()).map((entry) => entry.dataset);
    }

    data(): GraphWithID[] {
        return Array.from(this.index.values());
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
 * Type guard to check if an object implements the KeyPair interface.
 * 
 * @param obj 
 * @returns 
 */
// deno-lint-ignore no-explicit-any
export function isKeyData(obj: any): obj is KeyMetadata {
    return (obj as KeyPair).public !== undefined && (obj as KeyPair).private !== undefined;
}

/**
 * Calculate the canonical hash of a dataset using the implementation of RDFC 1.0.
 * 
 * @param dataset 
 * @returns 
 */
export async function calculateDatasetHash(dataset: rdf.DatasetCore): Promise<string> {
    const rdfc10 = new RDFC10();
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
export function convertToStore(dataset: rdf.DatasetCore): n3.Store {
    return (dataset instanceof n3.Store) ? dataset : copyToStore(dataset);
}

/*****************************************************************************************
 *  This is only used for debugging!!!!
*****************************************************************************************/

const prefixes = {
    sec: "https://w3id.org/security#",
    rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns",
    xsd: "http://www.w3.org/2001/XMLSchema#",
    rdfs: "http://www.w3.org/2000/01/rdf-schema#",
    dc: "http://purl.org/dc/terms/",
    foaf: "http://xmlns.com/foaf/0.1/",
    doap: "http://usefulinc.com/ns/doap#",
    earl: "http://www.w3.org/ns/earl#",
};

export function write_quads(dataset: rdf.DatasetCore) {
    const writer = new n3.Writer({ prefixes: prefixes });
    for (const q of dataset) writer.addQuad(q);
    // deno-lint-ignore no-explicit-any
    writer.end((_error: any, result: any) => console.log(result));
}
