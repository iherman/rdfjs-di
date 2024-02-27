import * as rdf    from '@rdfjs/types';
import { Command } from 'commander';

import { KeyPair, DI_ECDSA } from '../../index';

import { get_quads, DataFactory, write_quads } from './rdfn3';
import { get_keys, OSet }                      from './keys';

async function main() {
    const program = new Command();
    program
        .name('main [testfile]')
        .description('Make a roundrip for signing and verifying')
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

    const keyPairs: Iterable<KeyPair> = await get_keys();
    // const keyPair = await generateKeys();
    const dataset = await get_quads(input);
    const di_ecdsa = new DI_ECDSA();

    if (proof_set || proof_chain) {
        const finalKeyPairs = proof_chain ? keyPairs : new OSet<KeyPair>(keyPairs);

        let results: boolean[] = [false];
        if (embed) {
            if (!quiet) console.log(`>>> Generating embedded proofs for "${input}", with anchor at "${JSON.stringify(anchor)}"\n`);
            const proof = await di_ecdsa.embedProofGraph(dataset, finalKeyPairs, anchor);
            results = (verify) ? [await di_ecdsa.verifyEmbeddedProofGraph(proof)] : [false];
            if (!no_output) write_quads(proof);
        } else {
            if (!quiet) console.log(`Generating a proof graphs for "${input}"\n`);
            const proofs: rdf.DatasetCore[] = await di_ecdsa.generateProofGraph(dataset, finalKeyPairs);
            results = (verify) ? await di_ecdsa.verifyProofGraph(dataset, proofs) : [false]
            if (!no_output) for (const proof of proofs) write_quads(proof)
        }
        if (!quiet) console.log(verify ? `>>> Verification results: ${results}` : `>>> No verification was required`);
    } else {
        const keyPair: KeyPair = keyPairs instanceof Array ? keyPairs[0] : null
        let proof: rdf.DatasetCore;
        let result: boolean = false;

        if (embed) {
            if (!quiet) console.log(`>>> Generating embedded proof for "${input}", with anchor at "${JSON.stringify(anchor,null,2)}"\n`);
            proof = await di_ecdsa.embedProofGraph(dataset, keyPair, anchor);
            result = (verify) ? await di_ecdsa.verifyEmbeddedProofGraph(proof) : false
        } else {
            if (!quiet) console.log(`Generating a proof graph for "${input}"\n`);
            proof = await di_ecdsa.generateProofGraph(dataset, keyPair);
            result = (verify) ? await di_ecdsa.verifyProofGraph(dataset, proof) : false
        }

        if (!no_output) write_quads(proof);
        if (!quiet) console.log(verify ? `>>> Verification result: ${result}` : `>>> No verification was required`);
    }
}


main();
