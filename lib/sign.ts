/// <reference types="node" />
import * as rdf       from '@rdfjs/types';
import * as n3        from 'n3';
import { RDFC10 }     from 'rdfjs-c14n';
import { v4 as uuid } from 'uuid';

import { KeyPair, dataFactory, importKey, Confidentiality, textToArrayBuffer, arrayBufferToBase64Url } from './common'; 
import { sec_prefix, rdf_prefix, xsd_prefix, myFoaf } from './constants';
const { namedNode, literal, blankNode, quad } = dataFactory


export abstract class DataIntegrity {
    protected algorithm   : string;
    protected cryptosuite : string;
    protected hash        : string;

    constructor() {
        this.hash = "SHA-256";
    }

    async signDataset(dataset: rdf.DatasetCore, keyPair: KeyPair): Promise<rdf.DatasetCore> {
        // 1. Canonicalize hash of the dataset.
        const calculateDatasetHash = async (): Promise<string> => {
            const rdfc10 = new RDFC10();
            const canonical_quads: string = await rdfc10.canonicalize(dataset);
            const datasetHash: string = await rdfc10.hash(canonical_quads);
            return datasetHash;
        } 

        // 2. Sign the hash with the secret key
        const signHashValue = async (toBeSigned: string): Promise<string> => {
            const key: CryptoKey | null = await importKey(keyPair.private, Confidentiality.secret);
            if (key === null) {
                throw new Error(`Invalid key: ${JSON.stringify(keyPair.private, null, 4)}`);
            }
            const raw_signature: ArrayBuffer = await crypto.subtle.sign(
                {
                    name: this.algorithm,
                    hash: this.hash
                },
                key,
                textToArrayBuffer(toBeSigned)
            );
            return `z${arrayBufferToBase64Url(raw_signature)}`;           
        }

        // 3. Create a proof graph 
        const createProofGraph = (proofValue: string): rdf.DatasetCore => {
            const retval: n3.Store = new n3.Store();

            // Unique URL-s, for the time being as uuid-s
            const proofGraphId = `urn:uuid:${uuid()}`;
            const proofGraph = namedNode(proofGraphId);

            const verificationMethodId = `urn:uuid:${uuid()}`
            const keyGraph = namedNode(verificationMethodId);
            const type = namedNode(`${rdf_prefix}type`);

            // const today = literal((new Date()).toISOString());
            // // today.datatype = `${xsd_prefix}dateTime`;

            // new Literal()

            retval.addQuads([
                quad(
                    proofGraph, type, namedNode(`${sec_prefix}DataIntegrityProof`)
                ),
                quad(
                    proofGraph, namedNode(`${sec_prefix}cryptosuite`), literal(this.cryptosuite)
                ),
                quad(
                    proofGraph, namedNode(`${sec_prefix}created`), literal((new Date()).toISOString(),namedNode(`${xsd_prefix}dateTime`))
                ),
                quad(
                    proofGraph, namedNode(`${sec_prefix}verificationMethod`), keyGraph
                ),
                quad(
                    proofGraph, namedNode(`${sec_prefix}proofValue`), literal(proofValue)
                ),
                quad(
                    proofGraph, namedNode(`${sec_prefix}proofPurpose`), namedNode(`${sec_prefix}authenticationMethod`)
                ),

                quad(
                    keyGraph, type, namedNode(`${sec_prefix}JsonWebKey`)
                ),
                quad(
                    keyGraph, namedNode(`${sec_prefix}controller`), literal(myFoaf)
                ),
                quad(
                    keyGraph, namedNode(`${sec_prefix}publicKeyJwk`), literal(JSON.stringify(keyPair.public),namedNode(`${rdf_prefix}JSON`))
                ),
            ]);
            return retval;
        }

        const hash = await calculateDatasetHash();
        const signature = await signHashValue(hash)
        return createProofGraph(signature)
    }
}

export class DI_ECDSA extends DataIntegrity {
    constructor() {
        super();
        this.algorithm   = "ECDSA";
        this.cryptosuite = "ecdsa-2022"
    }
}








