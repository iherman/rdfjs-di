/**
 * Direct interface to the N3 Package, essentially relying on the TriG parser and the DataFactory 
 * implementation. All other parts of the library should only depend on the general
 * rdf-js package, ie, the using the semi-official data model specification only.
 * 
 * @packageDocumentation
 */

import * as n3                   from 'n3';
import * as rdf                  from '@rdfjs/types';
import * as fs                   from 'fs';
import { pipeline }              from 'node:stream/promises';

/**
 * Convert the graph into NQuads, more exactly into an array of individual NQuad statement
 * @param quads 
 * @returns 
 */
export function dataset_to_nquads(quads: Iterable<rdf.Quad>): string[] {
    const n3Writer = new n3.Writer();
    const quad_to_nquad = (quad: rdf.Quad): string => {
        const retval = n3Writer.quadToString(quad.subject, quad.predicate, quad.object, quad.graph);
        return retval.endsWith('  .') ? retval.replace(/  .$/, ' .') : retval;
    };

    let retval: string[] = [];
    for (const quad of quads) {
        retval.push(quad_to_nquad(quad));
    }
    return retval;
}

/**
 * Parse a turtle/trig file and return the result in a set of RDF Quads. The prefix declarations are also added to the list of prefixes.
 * Input format is a permissive superset of Turtle, TriG, N-Triples, and N-Quads.
 * 
 * An extra option is used to re-use the blank node id-s in the input without modification. This helps debugging...
 * 
 * @param fname - file name
 * @returns 
 */
export async function get_quads(fname: string): Promise<rdf.DatasetCore> {
    const trigStream = fs.createReadStream(`testing/tests/${fname}`, 'utf-8');
    const store = new n3.Store();
    const parser = new n3.StreamParser({ blankNodePrefix: '' });
    store.import(parser);
    await pipeline(trigStream, parser)
    return store;
}

const prefixes = {
    sec: "https://w3id.org/security#",
    rdf: "http://www.w3.org/1999/02/22-rdf-syntax-ns",
    xsd: "http://www.w3.org/2001/XMLSchema#",
    rdfs: "http://www.w3.org/2000/01/rdf-schema#",
    dc: "http://purl.org/dc/terms/",
    foaf: "http://xmlns.com/foaf/0.1/",
    doap: "http://usefulinc.com/ns/doap#",
    earl: "http://www.w3.org/ns/earl#",
}

export function write_quads(dataset: rdf.DatasetCore) {
    const writer = new n3.Writer( {prefixes: prefixes});
    for (const q of dataset) writer.addQuad(q);
    writer.end((error, result) => console.log(result));
}





export const DataFactory: rdf.DataFactory = n3.DataFactory;
