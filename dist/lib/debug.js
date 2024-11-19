"use strict";
/**
 * Debugging tools.
 *
 * @packageDocumentation
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.get_quads = exports.log = void 0;
const n3 = require("n3");
const fs = require("node:fs");
const promises_1 = require("node:stream/promises");
const DEBUG = false;
function log(str, dataset) {
    if (DEBUG) {
        if (typeof str === 'string') {
            console.error(str);
        }
        else {
            console.error(JSON.stringify(str, null, 4));
        }
        if (dataset !== undefined) {
            console.error('\n');
            write_quads(dataset, console.error);
        }
    }
}
exports.log = log;
/**
 * Convert the graph into NQuads, more exactly into an array of individual NQuad statement
 * @param quads
 * @returns
 */
function dataset_to_nquads(quads) {
    const n3Writer = new n3.Writer();
    const quad_to_nquad = (quad) => {
        const output = n3Writer.quadToString(quad.subject, quad.predicate, quad.object, quad.graph);
        // deno-lint-ignore no-regex-spaces
        return output.endsWith('  .') ? output.replace(/ {2}.$/, ' .') : output;
    };
    const output = [];
    for (const quad of quads) {
        output.push(quad_to_nquad(quad));
    }
    return output;
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
async function get_quads(fname) {
    const trigStream = fs.createReadStream(`testing/tests/${fname}`, 'utf-8');
    const store = new n3.Store();
    const parser = new n3.StreamParser({ blankNodePrefix: '' });
    store.import(parser);
    await (0, promises_1.pipeline)(trigStream, parser);
    return store;
}
exports.get_quads = get_quads;
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
function write_quads(dataset, output) {
    const writer = new n3.Writer({ prefixes });
    for (const q of dataset)
        writer.addQuad(q);
    // deno-lint-ignore no-explicit-any
    writer.end((_error, result) => output(result));
    // writer.end((_error: any, result: any) => console.log(result));
}
