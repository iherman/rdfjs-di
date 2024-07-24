/**
 * Debugging tools.
 *
 * @packageDocumentation
 */
import * as rdf from '@rdfjs/types';
export declare function log(str: any, dataset?: rdf.DatasetCore): void;
/**
 * Parse a turtle/trig file and return the result in a set of RDF Quads. The prefix declarations are also added to the list of prefixes.
 * Input format is a permissive superset of Turtle, TriG, N-Triples, and N-Quads.
 *
 * An extra option is used to re-use the blank node id-s in the input without modification. This helps debugging...
 *
 * @param fname - file name
 * @returns
 */
export declare function get_quads(fname: string): Promise<rdf.DatasetCore>;
