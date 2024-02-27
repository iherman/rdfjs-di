import { RDFC10 } from 'rdfjs-c14n';
import base64url from 'base64url';
import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
import { v4 as uuid } from 'uuid';
const { namedNode, literal, quad } = n3.DataFactory;

/***************************************************************************************
 * Namespace handling
 **************************************************************************************/

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

/*****************************************************************************************
 * Utility Functions
 *****************************************************************************************/

/**
 * Type guard to check if an object implements the rdf.DatasetCore interface.
 * 
 * @param obj 
 * @returns 
 */
export function isDatasetCore(obj: any): obj is rdf.DatasetCore {
    return (obj as rdf.DatasetCore).add !== undefined &&
        (obj as rdf.DatasetCore).delete !== undefined &&
        (obj as rdf.DatasetCore).match !== undefined &&
        (obj as rdf.DatasetCore).has !== undefined;
}

/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
export function textToArrayBuffer(text: string): ArrayBuffer {
    return (new TextEncoder()).encode(text).buffer;
}

/**
 * Calculate the canonical hash of a dataset; this is based on the
 * implementation of RDFC 1.0
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
 * Convert an array buffer to base64url value.
 * 
 * (Created with the help of chatgpt...)
 * 
 * @param arrayBuffer 
 * @returns 
 */
export function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string {
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
export function base64UrlToArrayBuffer(url: string): ArrayBuffer {
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


interface MapContent {
    id      : rdf.Quad_Graph,
    dataset : n3.Store
}

export class DatasetMap {
    private index: Map<string, MapContent>;

    constructor() {
        this.index = new Map();
    }

    item(graph: rdf.Quad_Graph): n3.Store {
        if (this.index.has(graph.value)) {
            return this.index.get(graph.value).dataset
        } else {
            const dataset = new n3.Store();
            this.index.set(graph.value, {
                id      : graph,
                dataset
            });
            return dataset
        }
    }

    has(graph: rdf.Term): boolean {
        return this.index.has(graph.value)
    }

    datasets(): n3.Store[] {
        return Array.from(this.index.values()).map((entry) => entry.dataset);
    }
}


/*****************************************************************************************
 * This is only used for debugging!!!!
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
    writer.end((error, result) => console.log(result));
}
