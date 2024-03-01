import * as rdf     from '@rdfjs/types';
import { Command }  from 'commander';
import * as process from 'node:process';


import { KeyPair, DI_ECDSA, VerificationResult } from '../../index';
import { get_quads, DataFactory, write_quads } from './rdfn3';
import { get_keys, OSet }                      from './keys';

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

async function main() {
    const program = new Command();
    program
        .name('main [testfile]')
        .description('Make a roundtrip for signing and verifying')
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

    const embed  = options.embed ? true : false ;
    const verify = options.verify ? true : false ;
    const quiet = options.quiet ? true : false;
    const no_output = options.no ? true : false;
    const proof_set = options.set ? true : false;
    const proof_chain = options.chain ? true : false;

    const input = (program.args.length === 0) ? 'small.ttl' : program.args[0];
    const anchor = options.anchor ? DataFactory.namedNode(`file:///${input}`) : undefined ;

    const keyPairs: KeyPair[] = await get_keys();
    // const keyPair = await generateKeys();
    const dataset = await get_quads(input);
    const di_ecdsa = new DI_ECDSA();


    if (embed) {
        const finalKeys = (proof_set) ? new OSet<KeyPair>(keyPairs) : ((proof_chain) ? keyPairs: keyPairs[0]);
        if (!quiet) console.log(`>>> Generating embedded proofs for "${input}", with anchor at "${JSON.stringify(anchor)}"\n`);
        const proof = await di_ecdsa.embedProofGraph(dataset, finalKeys, anchor);
        if (!no_output) write_quads(proof);
        if (verify) {
            const result = await di_ecdsa.verifyEmbeddedProofGraph(proof);
            if (!quiet) displayVerificationResult(result);
        } else {
            console.log(`>>> No verification was required`) 
        }
    } else {
        let result: boolean[];
        if (proof_set || proof_chain) {
            const proofs: rdf.DatasetCore[] = await di_ecdsa.generateProofGraph(dataset, keyPairs);
            result = (verify) ? await di_ecdsa.verifyProofGraph(dataset, proofs) : [false];
            if (!no_output) for (const proof of proofs) write_quads(proof);
        } else {
            const keyPair: KeyPair = keyPairs[0];
            const proof: rdf.DatasetCore = await di_ecdsa.generateProofGraph(dataset, keyPair);
            result = (verify) ? [await di_ecdsa.verifyProofGraph(dataset, proof)] : [false];
            if (!no_output) write_quads(proof);
        }
        if (!quiet) console.log(verify ? `>>> Verification result: ${result}` : `>>> No verification was required`);
    }
}

main();
