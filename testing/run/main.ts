import * as rdf     from '@rdfjs/types';
import { Command }  from 'commander';
import * as process from 'node:process';


import { KeyData, VerificationResult, 
    generateProofGraph, verifyProofGraph, 
    embedProofGraph, verifyEmbeddedProofGraph,
} from '../../index';
import { get_quads, DataFactory, write_quads }  from './rdfn3';
import { get_keys, OSet }                       from './keys';

function displayVerificationResult(result: VerificationResult): void {
    console.log(`>>>> Verification result`);
    console.log(`    Signature: ${result.verified ? 'valid' : 'invalid'}.`);
    if (result.errors.length === 0) {
        console.log('    No errors.')
    } else {
        console.log('    Errors:')
        for (const entry of result.errors) {
            console.log(`        ${entry.title} (${entry.code}): ${entry.detail}`);
        }
    }
    if (result.warnings.length === 0) {
        console.log('    No warning.');
    } else {
        console.log('    Warnings:');
        for (const entry of result.warnings) {
            console.log(`        ${entry}`);
        }
    }
    console.log('')
}

/**
 * The test can be used to
 * - generate one or several proof graphs
 * - generate one or several embedded proofs, both as proof sets or proof chains
 * - validate all of the above
 * 
 * Note: the keys are stored in the separate "keys.json" files. It contains different keys; if a single
 * graph is used by the test, it will pick the first key, otherwise it picks all of them.
 * 
 * The keys include both public and private keys, so they should be used for debug purposes only!
 */
async function main() {
    const program = new Command();
    program
        .name('main [testfile]')
        .description('Make a round-trip for signing and verifying')
        .usage('[options] [file name]')
        .option('-a --anchor', 'Anchor the proof graph to the file name (if relevant)')
        .option('-e --embed',  'Create an embedded proof')
        .option('-q --quiet', 'No extra output')
        .option('-n --no', 'No graph output')
        .option('-v --verify', 'Verify the proof')
        .option('-c --chain','Use a key chain')
        .option('-s --set','Use a key set')
        .parse(process.argv)

    const options = program.opts();

    const embed  = !!options.embed ;
    const verify = !!options.verify ;
    const quiet = !!options.quiet;
    const no_output = !!options.no;
    const proof_set = !!options.set;
    const proof_chain = !!options.chain;

    const input = (program.args.length === 0) ? 'small.ttl' : program.args[0];
    const anchor = options.anchor ? DataFactory.namedNode(`file:///${input}`) : undefined ;

    const keyPairs: KeyData[] = await get_keys();
    const dataset = await get_quads(input);


    try {
        if (embed) {
            const finalKeys = (proof_set) ? new OSet<KeyData>(keyPairs) : ((proof_chain) ? keyPairs: keyPairs[0]);
            if (!quiet) console.log(`>>> Generating embedded proofs for "${input}", with anchor at "${JSON.stringify(anchor)}"\n`);
            const proof = await embedProofGraph(dataset, finalKeys, anchor);
            if (!no_output) write_quads(proof);
            if (verify) {
                const result = await verifyEmbeddedProofGraph(proof, anchor);
                if (!quiet) displayVerificationResult(result);
            } else {
                console.log(`>>> No verification was required`) 
            }
        } else {
            if (proof_set || proof_chain) {
                const proofs: rdf.DatasetCore[] = await generateProofGraph(dataset, keyPairs);
                if (verify) {
                    const result = await verifyProofGraph(dataset, proofs);
                    if (!quiet) displayVerificationResult(result);
                } else {
                    console.log(`>>> No verification was required`);
                }
                if (!no_output) for (const proof of proofs) write_quads(proof);
            } else {
                // Simplest alternative: single key, single output proof
                const keyPair: KeyData = keyPairs[0];
                const proof: rdf.DatasetCore = await generateProofGraph(dataset, keyPair);
                if (verify) {
                    const result = await verifyProofGraph(dataset, proof);
                    if (!quiet) displayVerificationResult(result);
                } else {
                    console.log(`>>> No verification was required`);
                }
                if (!no_output) write_quads(proof);
            }
        }
    } catch(e) {
        console.log(`${e.message}`);
    }
}

main();
