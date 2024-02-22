import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
import * as di from '../../index';
import { get_quads, DataFactory, write_quads } from './rdfn3';
import { DI_ECDSA } from '../../lib/di';

async function generateKeys(): Promise<di.KeyPair> {
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
    const input   = (process.argv.length > 2) ? process.argv[2] : 'small.ttl';
    const keyPair = await generateKeys();
    const dataset = await get_quads(input);
    const anchor  = DataFactory.namedNode('file:///report.ttl');
    const di_ecdsa = new DI_ECDSA();

//    const proof: rdf.DatasetCore = await (new di.DI_ECDSA()).embedProofGraph(dataset, keyPair, anchor);
    const proofGraph: rdf.DatasetCore = await di_ecdsa.signDataset(dataset, keyPair);
    // console.log(`${JSON.stringify(keyPair,null,4)}`)
    write_quads(proofGraph);

    const result = await di_ecdsa.validateSignedDataset(dataset, proofGraph);
    console.log(`>>> Result of verification: ${result}`);
}


main();
