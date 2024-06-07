/**
 * "Internal API" for handling proof graphs.
 * 
 * Put into a separate file for an easier maintenance; not meant
 * to be part of the external API.
 * They are not exported (via `index.ts`) to
 * package users.
 * 
 * @packageDocumentation
 */


import * as rdf       from '@rdfjs/types';
import * as n3        from 'n3';
import { v4 as uuid } from 'uuid';
import { canonify }   from '@truestamp/canonify';

import * as types                                          from './types';
import { Errors, KeyData }                                 from './types';
import { createPrefix, GraphWithID, calculateDatasetHash } from './utils';
import { sign, verify, cryptosuiteId, algorithmData }      from './crypto_utils';
import { multikeyToKey, keyToMultikey }                    from './multikey';

// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;

/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/

/* Various namespaces, necessary when constructing a proof graph */
export const sec_prefix = createPrefix("https://w3id.org/security#");
export const rdf_prefix = createPrefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
export const xsd_prefix = createPrefix("http://www.w3.org/2001/XMLSchema#");

export const rdf_type: rdf.NamedNode                 = rdf_prefix('type');
export const rdf_json: rdf.NamedNode                 = rdf_prefix('JSON');
export const sec_proof: rdf.NamedNode                = sec_prefix('proof');
export const sec_di_proof: rdf.NamedNode             = sec_prefix('DataIntegrityProof');
export const sec_proofValue: rdf.NamedNode           = sec_prefix('proofValue');
export const sec_publicKeyJwk: rdf.NamedNode         = sec_prefix('publicKeyJwk');
export const sec_publicKeyMultibase: rdf.NamedNode   = sec_prefix('publicKeyMultibase');
export const sec_proofPurpose: rdf.NamedNode         = sec_prefix('proofPurpose');
export const sec_authenticationMethod: rdf.NamedNode = sec_prefix('authenticationMethod');
export const sec_assertionMethod: rdf.NamedNode      = sec_prefix('assertionMethod');
export const sec_verificationMethod: rdf.NamedNode   = sec_prefix('verificationMethod');
export const sec_expires: rdf.NamedNode              = sec_prefix('expires');
export const sec_revoked: rdf.NamedNode              = sec_prefix('revoked');
export const sec_created: rdf.NamedNode              = sec_prefix('created');
export const xsd_datetime: rdf.NamedNode             = xsd_prefix('dateTime');


/**
 * The proof option graph is the collection of all quads in a proof graph, except the proof
 * value. The hash of this graph is combined with the hash of the original data.
 * 
 * This function does one more step before hashing: it canonicalizes the (possible) JWK key. This
 * key is in a JSON Literal; this must be canonicalized to ensure a proper validation.
 * 
 * @param proofGraph 
 * @returns 
 */
async function calculateProofOptionsHash(proofGraph: rdf.DatasetCore): Promise<string> {
    const proofOptions = new n3.Store();
    // The proof option graph is a copy of the proof graph quads, except that:
    // 1. the proof value triple should be removed
    // 2. the value of the sec_publicKeyJwk must be canonicalized
    for (const q of proofGraph) {
        if (q.predicate.value === sec_proofValue.value){
            continue;
        } else if (q.predicate.value === sec_publicKeyJwk.value) {
            // get the JSON value from the object
            const jwk = JSON.parse(q.object.value);
            proofOptions.addQuad(q.subject, q.predicate, literal(canonify(jwk), rdf_json), q.graph);
        } else {
            proofOptions.add(q);
        }
    }

    // The return value must be the hash of the proof option graph
    return await calculateDatasetHash(proofGraph);
}


/**
 * Generate a (separate) proof graph, per the DI spec. The signature is stored in 
 * [multibase format](https://www.w3.org/TR/vc-data-integrity/#multibase-0), using base64url encoding.
 * 
 * @param report - placeholder for error reports
 * @param hashValue - this is the value of the Dataset's canonical hash 
 * @param keyData 
 * @returns 
 */
export async function generateAProofGraph(report: Errors, hashValue: string, keyData: KeyData): Promise <rdf.DatasetCore> {
    const cryptosuite = keyData?.cryptosuite || cryptosuiteId(report, keyData)

    // Generate the key data to be stored in the proof graph; either multikey or jwk, depending on the cryptosuite
    const addKeyResource = async (jsonKey: JsonWebKey, proofGraph: rdf.Quad_Subject, keyResource: rdf.Quad_Subject): Promise<rdf.Quad[]> => {
        let retval: rdf.Quad[] = [];
        if (jsonKey.kty === "OKP" || jsonKey.kty === "EC") {
            // We are in multikey land...
            const key = await crypto.subtle.importKey("jwk", jsonKey, algorithmData(report, jsonKey), true, ['verify']);
            const {cryptosuite, multikey} = await keyToMultikey(key);
            retval = [
                quad(proofGraph, sec_prefix('cryptosuite'), literal(cryptosuite)),
                quad(keyResource, rdf_type, sec_prefix('Multikey')),
                quad(keyResource, sec_publicKeyMultibase, literal(multikey)),
            ];
        } else {
            retval = [
                quad(proofGraph, sec_prefix('cryptosuite'), literal(cryptosuite)),
                quad(keyResource, rdf_type, sec_prefix('JsonWebKey')),
                quad(keyResource, sec_publicKeyJwk, literal(JSON.stringify(jsonKey), rdf_json)),
            ];
        }
        return retval;
    }

    // Create a proof graph. Just a boring set of quad generations...
    const createProofOptionGraph = async (): Promise<{ proofGraph: rdf.DatasetCore, proofGraphResource: rdf.NamedNode}> => {
        const proofGraph: n3.Store = new n3.Store();

        // Unique URL-s, for the time being as uuid-s
        const proofGraphResource = namedNode(`urn:uuid:${uuid()}`);

        const verificationMethodId = `urn:uuid:${uuid()}`;
        const keyResource = namedNode(verificationMethodId);

        // Create the resource for the proof graph itself, referring to a separate key resource
        proofGraph.addQuads([
            quad(
                proofGraphResource, rdf_type, sec_di_proof
            ),
            quad(
                proofGraphResource, sec_verificationMethod, keyResource
            ),
            quad(
                proofGraphResource, sec_created, literal((new Date()).toISOString(), xsd_datetime)
            ),
            quad(
                proofGraphResource, sec_proofPurpose, sec_authenticationMethod
            ),
            quad(
                proofGraphResource, sec_proofPurpose, sec_assertionMethod
            )
        ]);

        // Create the separate key resource triples (within the same graph)
        if (keyData.controller) proofGraph.add(quad(keyResource, sec_prefix('controller'), namedNode(keyData.controller)));
        if (keyData.expires) proofGraph.add(quad(keyResource, sec_expires, literal(keyData.expires, xsd_datetime)));
        if (keyData.revoked) proofGraph.add(quad(keyResource, sec_revoked, literal(keyData.revoked, xsd_datetime)));
        proofGraph.addQuads(await addKeyResource(keyData.public, proofGraphResource, keyResource));

        return { proofGraph, proofGraphResource }
    };

    // Put together the proof option graph and calculate its hash
    const { proofGraph, proofGraphResource } = await createProofOptionGraph();
    const proofOptionHashValue  = await calculateProofOptionsHash(proofGraph);

    // This is the extra trick in the cryptosuite specifications: the signature is upon the 
    // concatenation of the original dataset's hash and the hash of the proof option graph.
    const signature = await sign(report, hashValue + proofOptionHashValue, keyData.private);

    // Close up...
    if (signature === null) {
        // An error has occurred during signature; details are in the report.
        // No proof graph is generated
        return new n3.Store();
    } else {
        // Add the signature value to the proof graph
        proofGraph.add(quad(proofGraphResource, sec_proofValue, literal(signature)));
        return proofGraph;
    }
};

/**
 * Check a single proof graph, ie, whether the included signature corresponds to the hash value.
 * 
 * The following checks are also made:
 * 
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (in JWK)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and 
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 * 
 * Errors are stored in the `report` structure. If any error occurs, the result is false.
 * 
 * @param report - placeholder for error reports
 * @param hash 
 * @param proof - the proof graph
 * @param proofId - Id of the proof graph, if known; used in the error reports only
 * @returns 
 */
async function verifyAProofGraph(report: Errors, hash: string, proof: n3.Store, proofId: rdf.Quad_Graph | undefined): Promise < boolean> {
    const localErrors   : types.ProblemDetail[] = [];
    const localWarnings : types.ProblemDetail[] = [];

    const getProofValue = (store: n3.Store): string | null => {
        // Retrieve the signature value per spec:
        const proof_values: rdf.Quad[] = store.getQuads(null, sec_proofValue, null, null);
        if (proof_values.length === 0) {
            localErrors.push(new types.Malformed_Proof_Error("No proof value"));
            return null;
        } else if (proof_values.length > 1) {
            localErrors.push(new types.Malformed_Proof_Error("Several proof values"));
        }
        return proof_values[0].object.value;
    };

    const getPublicKey = async (store: n3.Store): Promise<JsonWebKey | null> => {
        // first see if the verificationMethod has been set properly
        const verificationMethod: rdf.Quad[] = store.getQuads(null, sec_verificationMethod, null, null);
        if (verificationMethod.length === 0) {
            localErrors.push(new types.Malformed_Proof_Error("No verification method"));
            return null;
        } else if (verificationMethod.length > 1) {
            localErrors.push(new types.Malformed_Proof_Error("Several verification methods"));
        }

        const publicKey = verificationMethod[0].object;
   
        // Check the creation/expiration/revocation dates, if any...
        const now = new Date();
        const creationDates: rdf.Quad[] = store.getQuads(null, sec_created, null, null);
        for (const exp of creationDates) {
            if ((new Date(exp.object.value)) > now) {
                localWarnings.push(new types.Invalid_Verification_Method(`Proof was created in the future... ${exp.object.value}`));
            }
        }

        const expirationDates: rdf.Quad[] = store.getQuads(publicKey, sec_expires, null, null);
        for (const exp of expirationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new types.Invalid_Verification_Method(`<${publicKey.value}> key expired on ${exp.object.value}`));
                return null;
            }
        }
        const revocationDates: rdf.Quad[] = store.getQuads(publicKey, sec_revoked, null, null);
        for (const exp of revocationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new types.Invalid_Verification_Method(`<${publicKey.value}> key was revoked on ${exp.object.value}`));
                return null;
            }
        }

        // All conditions are fulfilled, the key can now be retrieved and returned 
        // The key itself can be in JWK or in Multikey format
        const keys_jwk: rdf.Quad[]      = store.getQuads(publicKey, sec_publicKeyJwk, null, null);
        const keys_multikey: rdf.Quad[] = store.getQuads(publicKey, sec_publicKeyMultibase, null, null);

        // Both arrays cannot exist at the same time!
        if (keys_jwk.length > 0 && keys_multikey.length > 0) {
            localWarnings.push(new types.Malformed_Proof_Error(`JWK or Multikey formats can be used, but not both.`));
            return null;
        } else if (keys_jwk.length === 0) {
            // Trying Multikey, JWK is not used...
            if (keys_multikey.length === 0) {
                localErrors.push(new types.Invalid_Verification_Method(`No key values`));
                return null;
            } else if (keys_multikey.length === 1) {
                try {
                    const key: CryptoKey = await multikeyToKey(keys_multikey[0].object.value);
                    return crypto.subtle.exportKey('jwk', key);
                } catch(e) {
                    localWarnings.push(new types.Malformed_Proof_Error(`Parsing error for Multikey: ${e.message}`));
                    return null;
                }
            } else {
                localErrors.push(new types.Invalid_Verification_Method("More than one Multikey encoded keys"));
                return null;
            }
        } else if (keys_jwk.length === 1) {
            // We have a JWK key, we can return it if it parses o.k.
            try {
                return JSON.parse(keys_jwk[0].object.value) as JsonWebKey;
            } catch (e) {
                // This happens if there is a JSON parse error with the key...
                localWarnings.push(new types.Malformed_Proof_Error(`Parsing error for JWK: ${e.message}`));
                return null;
            }
        } else {
            localErrors.push(new types.Invalid_Verification_Method("More than one JWK encoded keys"));
            return null;
        }

    };

    // Check the "proofPurpose" property value
    const checkProofPurposes = (store: n3.Store): void => {
        const purposes: rdf.Quad[] = store.getQuads(null, sec_proofPurpose, null, null);
        if (purposes.length === 0) {
            localErrors.push(new types.Invalid_Verification_Method("No proof purpose set"))
        } else {
            const wrongPurposes: string[] = [];
            for (const q of purposes) {
                if (!(q.object.equals(sec_authenticationMethod) || q.object.equals(sec_assertionMethod))) {
                    wrongPurposes.push(`<${q.object.value}>`);
                }
            }
            if (wrongPurposes.length > 0) {
                localErrors.push(new types.Mismatched_Proof_Purpose(`Invalid proof purpose value(s): ${wrongPurposes.join(", ")}`));
            }
        }
    }

    // Retrieve necessary values with checks
    checkProofPurposes(proof);
    const publicKey: JsonWebKey | null = await getPublicKey(proof);
    const proofValue: string | null = getProofValue(proof);

    // The final set of error/warning should be modified with the proof graph's ID, if applicable
    if (proofId !== undefined) {
        localErrors.forEach((error) => {
            error.detail = `${error.detail} (graph ID: <${proofId.value}>)`;
        });
        localWarnings.forEach((warning) => {
            warning.detail = `${warning.detail} (graph ID: <${proofId.value}>)`;
        });
    }
    report.errors   = [...report.errors, ...localErrors];
    report.warnings = [...report.warnings, ...localWarnings];

    // Here we go with checking...
    if (publicKey !== null && proofValue !== null) {
        // First the proof option graph must be created and then hashed
        const proofOptionGraphHash = await calculateProofOptionsHash(proof);
        const check_results = await verify(report, hash + proofOptionGraphHash, proofValue, publicKey)
        // the return value should nevertheless be false if there have been errors
        return check_results ? localErrors.length === 0 : true;
    } else {
        return false;
    }
}

/**
 *  Check a series of proof graphs, ie, check whether the included signature of a proof graph corresponds to the hash value.
 * 
 * The following checks are also made for each proof graph:
 * 
 * 1. There should be exactly one [proof value](https://www.w3.org/TR/vc-data-integrity/#dfn-proofvalue)
 * 2. There should be exactly one [verification method](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod), which should be a separate resource containing the key (in JWK)
 * 3. The key's (optional) [expiration](https://www.w3.org/TR/vc-data-integrity/#defn-proof-expires) and 
 * [revocation](https://www.w3.org/TR/vc-data-integrity/#dfn-revoked) dates are checked and compared to the current time which should be "before"
 * 4. The proof's [creation date](https://www.w3.org/TR/vc-data-integrity/#dfn-created) must be before the current time
 * 5. The proof [purpose(s)](https://www.w3.org/TR/vc-data-integrity/#dfn-proofpurpose) must be set, and the values are either [authentication](https://www.w3.org/TR/vc-data-integrity/#dfn-authentication) or [verification](https://www.w3.org/TR/vc-data-integrity/#dfn-verificationmethod)
 * 
 * Errors are stored in the `report` structure.
 * If any error occurs in any proof graph the result is `false`; otherwise, result is the conjunction of each individual proof graph verifications. 
 * 
 * @param report - placeholder for error reports
 * @param hash 
 * @param proofs 
 * @returns 
 */
export async function verifyProofGraphs(report: Errors, hash: string, proofs: GraphWithID[]): Promise<boolean> {
    const allErrors: Errors[] = [];
    // deno-lint-ignore require-await
    const singleVerification = async (pr: GraphWithID): Promise<boolean> => {
        const singleReport: Errors = { errors: [], warnings: [] }
        allErrors.push(singleReport);
        return verifyAProofGraph(singleReport, hash, pr.dataset, pr.id);
    }

    const promises: Promise<boolean>[] = proofs.map(singleVerification);
    const result: boolean[] = await Promise.all(promises)

    // consolidate error messages. By using allErrors the error messages
    // follow the same order as the incoming proof graph references,
    // and are not possibly shuffled by the async calls
    for (const singleReport of allErrors) {
        report.errors = [...report.errors, ...singleReport.errors];
        report.warnings = [...report.warnings, ...singleReport.warnings]
    }
    return !result.includes(false)
}
