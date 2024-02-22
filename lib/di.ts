/// <reference types="node" />
import * as rdf       from '@rdfjs/types';
import * as n3        from 'n3';
import { v4 as uuid } from 'uuid';

import { 
    KeyPair, dataFactory, Confidentiality, textToArrayBuffer, 
    arrayBufferToBase64Url, base64UrlToArrayBuffer, 
    calculateDatasetHash 
} from './types_utils'; 

const { namedNode, literal, quad } = dataFactory

const sec_prefix = "https://w3id.org/security#";
const rdf_prefix = "http://www.w3.org/1999/02/22-rdf-syntax-ns#";
const xsd_prefix = "http://www.w3.org/2001/XMLSchema#";
const myFoaf     = "https://www.ivan-herman.net#me";


export abstract class DataIntegrity {
    protected algorithm   : string;
    protected cryptosuite : string;
    protected hash        : string;
    protected curve       : string;

    constructor() {
        this.hash = "SHA-256";
    }

    protected async importKey(key: JsonWebKey, type: Confidentiality): Promise<CryptoKey | null> {
        return await crypto.subtle.importKey("jwk", key,
            {
                name: this.algorithm,
                namedCurve: this.curve,
            },
            true,
            type === Confidentiality.public ? ["verify"] : ["sign"]
        );
    };

    protected convertToStore(dataset: rdf.DatasetCore): n3.Store {
        if (dataset instanceof n3.Store) {
            return dataset as n3.Store;
        } else {
            const retval = new n3.Store;
            for (const q of dataset) retval.add(q);
            return retval;
        }
    }

    async signDataset(dataset: rdf.DatasetCore, keyPair: KeyPair): Promise<rdf.DatasetCore> {
        // Sign the hash with the secret key
        const signHashValue = async (toBeSigned: string): Promise<string> => {
            const key: CryptoKey | null = await this.importKey(keyPair.private, Confidentiality.secret);
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
        };

        // Create a proof graph 
        const createProofGraph = (proofValue: string): rdf.DatasetCore => {
            const retval: n3.Store = new n3.Store();

            // Unique URL-s, for the time being as uuid-s
            const proofGraphId = `urn:uuid:${uuid()}`;
            const proofGraph = namedNode(proofGraphId);

            const verificationMethodId = `urn:uuid:${uuid()}`
            const keyGraph = namedNode(verificationMethodId);
            const type = namedNode(`${rdf_prefix}type`);

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
        };

        const hash = await calculateDatasetHash(dataset);
        const signature = await signHashValue(hash)
        return createProofGraph(signature)
    }

    async validateSignedDataset(dataset: rdf.DatasetCore, proofGraph: rdf.DatasetCore): Promise<boolean> {
        // This is, for now, just the basic set of operations. The detailed validation steps,
        // with all the possible issues, will come later.

        const checkHashValue = async (hash_value: string, proof_value: string, key_jwk: JsonWebKey): Promise<boolean> => {
            const key: CryptoKey | null = await this.importKey(key_jwk, Confidentiality.public);
            if (key === null) {
                throw new Error(`Invalid key: ${JSON.stringify(key_jwk, null, 4)}`);
            }
            const signature_array: ArrayBuffer = base64UrlToArrayBuffer(proof_value.slice(1));
            const data: ArrayBuffer = textToArrayBuffer(hash_value);
            const retval: boolean = await crypto.subtle.verify(
                {
                    name: this.algorithm,
                    hash: this.hash
                },
                key, 
                signature_array, 
                data
            );
            return retval;
        };

        const getProofValue = (store: n3.Store): string => {
            // Retrieve the signature value per spec:
            const proof_values: rdf.Quad[] = proof.getQuads(null, namedNode(`${sec_prefix}proofValue`), null, null);
            if (proof_values.length !== 1) {
                throw new Error("Incorrect proof values");
            }
            return proof_values[0].object.value;
        };

        const getPublicKey = (store: n3.Store): JsonWebKey => {
            const keys: rdf.Quad[] = proof.getQuads(null, `${sec_prefix}publicKeyJwk`, null, null);
            if (keys.length !== 1) {
                throw new Error("Incorrect key values");
            }
            return JSON.parse(keys[0].object.value) as JsonWebKey;
        };

        // Using an n3 store makes subsequent searches easier...
        const proof: n3.Store = this.convertToStore(proofGraph);

        // Calculate the hash value of the dataset; this is what was, supposedly, signed originally
        const hash = await calculateDatasetHash(dataset);

        const proofValue: string = getProofValue(proof);
        const publicKey: JsonWebKey = getPublicKey(proof);

        // Here we go with checking...
        const retval: boolean = await checkHashValue(hash, proofValue, publicKey)
        return retval;
    }

    async embedProofGraph(dataset: rdf.DatasetCore, keyPair: KeyPair, anchor: rdf.Quad_Subject = undefined): Promise<rdf.DatasetCore> {
        const retval = new n3.Store();
        for (const q of dataset) retval.add(q);

        const proofGraphID = retval.createBlankNode();
        const proofTriples = await this.signDataset(dataset, keyPair);
        for (const q of proofTriples) {
            retval.add(quad(q.subject, q.predicate, q.object, proofGraphID));
        };

        // Add the extra proof statement, if possible:
        if (anchor !== undefined) retval.add(quad(anchor, namedNode(`${sec_prefix}proof`), proofGraphID));
        return retval;
    }

}

export class DI_ECDSA extends DataIntegrity {
    constructor() {
        super();
        this.algorithm   = "ECDSA";
        this.cryptosuite = "ecdsa-2022"
        this.curve       = "P-256"
    }
}








