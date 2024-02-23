import * as rdf    from '@rdfjs/types';
import { Command } from 'commander';

import { KeyPair, DI_ECDSA } from '../../index';

import { get_quads, DataFactory, write_quads } from './rdfn3';

const myFoaf = "https://www.ivan-herman.net#me";

async function generateKeys(): Promise<KeyPair> {
    const newPair = await crypto.subtle.generateKey(
        {
            name: "ECDSA",
            namedCurve: "P-256"
        },
        true,
        ["sign", "verify"]
    );
    return {
        public: await crypto.subtle.exportKey("jwk", newPair.publicKey),
        private: await crypto.subtle.exportKey("jwk", newPair.privateKey)
    };
}

async function main() {
    const program = new Command();
    program
        .name('main [testfile]')
        .description('Make a roundrip for signing and verifying')
        .usage('[options] [file name]')
        .option('-a --anchor', 'Anchor the proof graph to the file name (if relevant)')
        .option('-e --embed',  'Create an embedded proof')
        .option('-s --silent', 'No extra output')
        .option('-n --no', 'No graph output')
        .option('-v --verify', 'Verify the proof')
        .parse(process.argv)

    const options = program.opts();

    const embed  = options.embed ? true : false ;
    const verify = options.verify ? true : false ;
    const silent = options.silent ? true : false;
    const no_output = options.no ? true : false;

    const input = (program.args.length === 0) ? 'small.ttl' : program.args[0];
    const anchor = options.anchor ? DataFactory.namedNode(`file:///${input}`) : undefined ;

    const keyPair = await generateKeys();
    const dataset = await get_quads(input);
    const di_ecdsa = new DI_ECDSA();

    let proof: rdf.DatasetCore;
    let result: boolean = false;

    if (embed) {
        if (!silent) console.log(`>>> Generating embedded proof for "${input}", with anchor at "${JSON.stringify(anchor,null,2)}"\n`);
        proof = await di_ecdsa.embedProofGraph(dataset, keyPair, myFoaf, anchor);
        result = (verify) ? await di_ecdsa.verifyEmbeddedProofGraph(proof) : false
    } else {
        if (!silent) console.log(`Generating a proof graph for "${input}"\n`);
        proof = await di_ecdsa.generateProofGraph(dataset, keyPair, myFoaf);
        result = (verify) ? await di_ecdsa.verifyProofGraph(dataset, proof) : false
    }

    if (!no_output) write_quads(proof);
    if (!silent) console.log(verify ? `>>> Verification result: ${result}` : `>>> No verification was required`);
}


main();
