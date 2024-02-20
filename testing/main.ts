import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
import * as di from '../index';
import { get_quads, DataFactory, write_quads } from './rdfn3';

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
    const input = (process.argv.length > 2) ? process.argv[2] : 'tiny.ttl';
    const keyPair = await generateKeys();
    const dataset = await get_quads(input);

    const proof: rdf.DatasetCore = await (new di.DI_ECDSA()).signDataset(dataset, keyPair);
    write_quads(proof);
}


main();
