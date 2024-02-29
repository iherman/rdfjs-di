"use strict";
/**
 * Collection of smaller utilities needed for the DI implementation. Put into a separate file for an easier maintenance; not meant
 * to be part of the external API
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.write_quads = exports.convertToStore = exports.base64UrlToArrayBuffer = exports.arrayBufferToBase64Url = exports.calculateDatasetHash = exports.textToArrayBuffer = exports.isDatasetCore = exports.DatasetMap = exports.createPrefix = void 0;
const rdfjs_c14n_1 = require("rdfjs-c14n");
const base64url_1 = require("base64url");
const n3 = require("n3");
const { namedNode, literal, quad } = n3.DataFactory;
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
            return this.index.get(graph.value).dataset;
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
function isDatasetCore(obj) {
    return obj.add !== undefined &&
        obj.delete !== undefined &&
        obj.match !== undefined &&
        obj.has !== undefined;
}
exports.isDatasetCore = isDatasetCore;
/**
 * Text to array buffer, needed for crypto operations
 * @param text
 */
function textToArrayBuffer(text) {
    return (new TextEncoder()).encode(text).buffer;
}
exports.textToArrayBuffer = textToArrayBuffer;
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
 * Convert an array buffer to a base64url value.
 *
 * (Created with the help of chatgpt...)
 *
 * @param arrayBuffer
 * @returns
 */
function arrayBufferToBase64Url(arrayBuffer) {
    const bytes = new Uint8Array(arrayBuffer);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);
    return base64url_1.default.fromBase64(base64String);
}
exports.arrayBufferToBase64Url = arrayBufferToBase64Url;
/**
 * Convert a base64url value to an array buffer
 *
 * (Created with the help of chatgpt...)
 *
 * @param url
 * @returns
 */
function base64UrlToArrayBuffer(url) {
    const base64string = base64url_1.default.toBase64(url);
    const binary = atob(base64string);
    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }
    return byteArray.buffer;
}
exports.base64UrlToArrayBuffer = base64UrlToArrayBuffer;
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
function write_quads(dataset) {
    const writer = new n3.Writer({ prefixes: prefixes });
    for (const q of dataset)
        writer.addQuad(q);
    writer.end((error, result) => console.log(result));
}
exports.write_quads = write_quads;
