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

import * as types                      from './types';
import { Errors, KeyData }             from './types';
import { createPrefix, GraphWithID }   from './utils';
import { sign, verify, cryptosuiteId } from './crypto_utils';

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
export const sec_proof: rdf.NamedNode                = sec_prefix('proof');
export const sec_di_proof: rdf.NamedNode             = sec_prefix('DataIntegrityProof');
export const sec_proofValue: rdf.NamedNode           = sec_prefix('proofValue');
export const sec_publicKeyJwk: rdf.NamedNode         = sec_prefix('publicKeyJwk');
export const sec_proofPurpose: rdf.NamedNode         = sec_prefix('proofPurpose');
export const sec_authenticationMethod: rdf.NamedNode = sec_prefix('authenticationMethod');
export const sec_assertionMethod: rdf.NamedNode      = sec_prefix('assertionMethod');
export const sec_verificationMethod: rdf.NamedNode   = sec_prefix('verificationMethod');
export const sec_expires: rdf.NamedNode              = sec_prefix('expires');
export const sec_revoked: rdf.NamedNode              = sec_prefix('revoked');
export const sec_created: rdf.NamedNode              = sec_prefix('created');
export const xsd_datetime: rdf.NamedNode             = xsd_prefix('dateTime');


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

    // Create a proof graph. Just a boring set of quad generations...
    const createProofGraph = (proofValue: string): rdf.DatasetCore => {
        const retval: n3.Store = new n3.Store();

        // Unique URL-s, for the time being as uuid-s
        const proofGraphId = `urn:uuid:${uuid()}`;
        const proofGraph = namedNode(proofGraphId);

        const verificationMethodId = `urn:uuid:${uuid()}`;
        const keyResource = namedNode(verificationMethodId);

        retval.addQuads([
            quad(
                proofGraph, rdf_type, sec_di_proof
            ),
            quad(
                proofGraph, sec_prefix('cryptosuite'), literal(cryptosuite)
            ),
            quad(
                proofGraph, sec_verificationMethod, keyResource
            ),
            quad(
                proofGraph, sec_proofValue, literal(proofValue)
            ),
            quad(
                proofGraph, sec_created, literal((new Date()).toISOString(), xsd_datetime)
            ),
            quad(
                proofGraph, sec_proofPurpose, sec_authenticationMethod
            ),
            quad(
                proofGraph, sec_proofPurpose, sec_assertionMethod
            ),

            quad(
                keyResource, rdf_type, sec_prefix('JsonWebKey')
            ),
            quad(
                keyResource, sec_publicKeyJwk, literal(JSON.stringify(keyData.public), rdf_prefix('JSON'))
            ),
        ]);
        if (keyData.controller) retval.add(quad(keyResource, sec_prefix('controller'), namedNode(keyData.controller)));
        if (keyData.expires) retval.add(quad(keyResource, sec_expires, literal(keyData.expires, xsd_datetime)));
        if (keyData.revoked) retval.add(quad(keyResource, sec_revoked, literal(keyData.revoked, xsd_datetime)));
        return retval;
    };

    const signature = await sign(report, hashValue, keyData.private);
    if (signature === null) {
        // An error has occurred during signature; details are in the report.
        // No proof graph is generated
        return new n3.Store();
    } else {
        return createProofGraph(signature);
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

    const getPublicKey = (store: n3.Store): JsonWebKey | null => {
        // first see if the verificationMethod has been set properly
        const verificationMethod: rdf.Quad[] = store.getQuads(null, sec_verificationMethod, null, null);
        if (verificationMethod.length === 0) {
            localErrors.push(new types.Malformed_Proof_Error("No verification method"));
            return null;
        } else if (verificationMethod.length > 1) {
            localErrors.push(new types.Malformed_Proof_Error("Several verification methods"));
        }

        const publicKey = verificationMethod[0].object;
        const keys: rdf.Quad[] = store.getQuads(publicKey, sec_publicKeyJwk, null, null);
        if (keys.length === 0) {
            localErrors.push(new types.Invalid_Verification_Method(`No key values`));
            return null;
        } else if (keys.length > 1) {
            localErrors.push(new types.Invalid_Verification_Method("More than one keys provided"));
        }

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

        try {
            return JSON.parse(keys[0].object.value) as JsonWebKey;
        } catch (e) {
            // This happens if there is a JSON parse error with the key...
            localWarnings.push(new types.Malformed_Proof_Error(`Parsing error for JWK: ${e.message}`));
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
    const publicKey: JsonWebKey | null = getPublicKey(proof);
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
    report.errors = [...report.errors, ...localErrors];
    report.warnings = [...report.warnings, ...localWarnings];

    // Here we go with checking...
    if (publicKey !== null && proofValue !== null) {
        const check_results = await verify(report, hash, proofValue, publicKey)
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
