/**
 * Collection of smaller utilities needed for the DI implementation. Put into a separate file for an easier maintenance; not meant
 * to be part of the external API
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
 * Structure with a separate store and its ID as a graph
 */
export interface MapContent {
    id: rdf.Quad_Graph;
    dataset: n3.Store;
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
     * @param graph
     * @returns
     */
    item(graph: rdf.Quad_Graph): n3.Store;
    has(graph: rdf.Term): boolean;
    datasets(): n3.Store[];
    data(): MapContent[];
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
 * Text to array buffer, needed for crypto operations
 * @param text
 */
export declare function textToArrayBuffer(text: string): ArrayBuffer;
/**
 * Calculate the canonical hash of a dataset using the implementation of RDFC 1.0.
 *
 * @param dataset
 * @returns
 */
export declare function calculateDatasetHash(dataset: rdf.DatasetCore): Promise<string>;
/**
 * Convert an array buffer to a base64url value.
 *
 * (Created with the help of chatgpt...)
 *
 * @param arrayBuffer
 * @returns
 */
export declare function arrayBufferToBase64Url(arrayBuffer: ArrayBuffer): string;
/**
 * Convert a base64url value to an array buffer
 *
 * (Created with the help of chatgpt...)
 *
 * @param url
 * @returns
 */
export declare function base64UrlToArrayBuffer(url: string): ArrayBuffer;
/**
 * Convert the dataset into an n3.Store, unless it is already a store.
 * This is done to manage the various quads more efficiently.
 *
 * @param dataset
 * @returns
 */
export declare function convertToStore(dataset: rdf.DatasetCore): n3.Store;
export declare function write_quads(dataset: rdf.DatasetCore): void;
