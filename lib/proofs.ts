import * as rdf from '@rdfjs/types';
import * as n3 from 'n3';
import { v4 as uuid } from 'uuid';

import * as errors from './errors';
import { ProblemDetail, Errors } from './errors';
import { createPrefix } from './utils';
import { sign, verify } from './crypto_utils';
// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;
import { Cryptosuite } from './common';

/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/

/* Various namespaces, necessary when constructing a proof graph */
const sec_prefix = createPrefix("https://w3id.org/security#");
const rdf_prefix = createPrefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
const xsd_prefix = createPrefix("http://www.w3.org/2001/XMLSchema#");

const rdf_type: rdf.NamedNode                 = rdf_prefix('type');
const sec_proof: rdf.NamedNode                = sec_prefix('proof');
const sec_di_proof: rdf.NamedNode             = sec_prefix('DataIntegrityProof');
const sec_proofValue: rdf.NamedNode           = sec_prefix('proofValue');
const sec_publicKeyJwk: rdf.NamedNode         = sec_prefix('publicKeyJwk');
const sec_proofPurpose: rdf.NamedNode         = sec_prefix('proofPurpose');
const sec_authenticationMethod: rdf.NamedNode = sec_prefix('authenticationMethod');
const sec_assertionMethod: rdf.NamedNode      = sec_prefix('assertionMethod');
const sec_verificationMethod: rdf.NamedNode   = sec_prefix('verificationMethod');
const sec_expires: rdf.NamedNode              = sec_prefix('expires');
const sec_revoked: rdf.NamedNode              = sec_prefix('revoked');
const sec_created: rdf.NamedNode              = sec_prefix('created');
const xsd_datetime: rdf.NamedNode             = xsd_prefix('dateTime');


/**
 * Generate a (separate) proof graph, per the DI spec. The signature is stored in 
 * multibase format, using base64url encoding.
 * 
 * @param hashValue - this is the value of the Dataset's canonical hash 
 * @param suite 
 * @returns 
 */
export async function generateAProofGraph(report: Errors, hashValue: string, suite: Cryptosuite): Promise < rdf.DatasetCore > {
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
                proofGraph, sec_prefix('cryptosuite'), literal(suite.cryptosuite)
            ),
            quad(
                proofGraph, sec_verificationMethod, keyResource
            ),
            quad(
                proofGraph, sec_proofValue, literal(proofValue)
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
                keyResource, sec_publicKeyJwk, literal(JSON.stringify(suite.public), rdf_prefix('JSON'))
            ),
        ]);
        if (suite.created) retval.add(quad(proofGraph, sec_revoked, literal(suite.created, xsd_datetime)))
        if (suite.controller) retval.add(quad(keyResource, sec_prefix('controller'), namedNode(suite.controller)));
        if (suite.expires) retval.add(quad(keyResource, sec_expires, literal(suite.expires, xsd_datetime)));
        if (suite.revoked) retval.add(quad(keyResource, sec_revoked, literal(suite.revoked, xsd_datetime)));
        return retval;
    };
    return createProofGraph(await sign(report, hashValue, suite.private));
};

/**
 * Check one proof graph, ie, whether the included signature corresponds to the hash value.
 * 
 * The following checks are also made and, possibly, exception are raised with errors according to 
 * the DI standard:
 * 
 * 1. There should be exactly one proof value
 * 2. There should be exactly one verification method, which should be a separate resource containing the key
 * 3. The key's possible expiration and revocation dates are checked and compared to the current time which should be
 * "before"
 * 4. The proof's creation date must be before the current time
 * 5. The proof purpose(s) must be set, and the values are either authentication or verification
 * 
 * @param hash 
 * @param proof 
 * @returns 
 */
async function verifyAProofGraph(report: Errors, hash: string, proof: n3.Store, proofId ?: rdf.Quad_Graph): Promise < boolean > {
    const localErrors   : errors.ProblemDetail[] = [];
    const localWarnings : errors.ProblemDetail[] = [];

    const getProofValue = (store: n3.Store): string | null => {
        // Retrieve the signature value per spec:
        const proof_values: rdf.Quad[] = store.getQuads(null, sec_proofValue, null, null);
        if (proof_values.length === 0) {
            localErrors.push(new errors.Malformed_Proof_Error("No proof value"));
            return null;
        } else if (proof_values.length > 1) {
            localErrors.push(new errors.Malformed_Proof_Error("Several proof values"));
        }
        return proof_values[0].object.value;
    };

    const getPublicKey = (store: n3.Store): JsonWebKey | null => {
        // first see if the verificationMethod has been set properly
        const verificationMethod: rdf.Quad[] = store.getQuads(null, sec_verificationMethod, null, null);
        if (verificationMethod.length === 0) {
            localErrors.push(new errors.Malformed_Proof_Error("No verification method"));
            return null;
        } else if (verificationMethod.length > 1) {
            localErrors.push(new errors.Malformed_Proof_Error("Several verification methods"));
        }

        const publicKey = verificationMethod[0].object;
        const keys: rdf.Quad[] = store.getQuads(publicKey, sec_publicKeyJwk, null, null);
        if (keys.length === 0) {
            localErrors.push(new errors.Invalid_Verification_Method(`No key values`));
            return null;
        } else if (keys.length > 1) {
            localErrors.push(new errors.Invalid_Verification_Method("More than one keys provided"));
        }

        // Check the creation/expiration/revocation dates, if any...
        const now = new Date();
        const creationDates: rdf.Quad[] = store.getQuads(null, sec_created, null, null);
        for (const exp of creationDates) {
            if ((new Date(exp.object.value)) > now) {
                localWarnings.push(new errors.Invalid_Verification_Method(`Proof was created in the future... ${exp.object.value}`));
            }
        }

        const expirationDates: rdf.Quad[] = store.getQuads(publicKey, sec_expires, null, null);
        for (const exp of expirationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new errors.Invalid_Verification_Method(`<${publicKey.value}> key expired on ${exp.object.value}`));
                return null;
            }
        }
        const revocationDates: rdf.Quad[] = store.getQuads(publicKey, sec_revoked, null, null);
        for (const exp of revocationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new errors.Invalid_Verification_Method(`<${publicKey.value}> key was revoked on ${exp.object.value}`));
                return null;
            }
        }

        try {
            return JSON.parse(keys[0].object.value) as JsonWebKey;
        } catch (e) {
            // This happens if there is a JSON parse error with the key...
            localWarnings.push(new errors.Malformed_Proof_Error(`Parsing error for JWK: ${e.message}`));
            return null;
        }
    };

    // Check the "proofPurpose" property value
    const checkProofPurposes = (store: n3.Store): void => {
        const purposes: rdf.Quad[] = store.getQuads(null, sec_proofPurpose, null, null);
        if (purposes.length === 0) {
            throw new errors.Invalid_Verification_Method("No proof purpose set");
        } else {
            const wrongPurposes: string[] = [];
            for (const q of purposes) {
                if (!(q.object.equals(sec_authenticationMethod) || q.object.equals(sec_assertionMethod))) {
                    wrongPurposes.push(`<${q.object.value}>`);
                }
            }
            if (wrongPurposes.length > 0) {
                localErrors.push(new errors.Mismatched_Proof_Purpose(`Invalid proof purpose value(s): ${wrongPurposes.join(", ")}`));
            }
        }
    }

    // Retrieve necessary values with checks
    checkProofPurposes(proof);
    const publicKey: JsonWebKey | null = getPublicKey(proof);
    const proofValue: string | null = getProofValue(proof);

    // The final set of error/warning should be modified with the proof graph's ID, if applicable
    if (proofId) {
        localErrors.forEach((error) => {
            error.detail = `${error.detail} (graph ID: <${proofId.value}>)`;
        });
        localWarnings.forEach((warning) => {
            warning.detail = `${warning.detail} (<${proofId.value}>)`;
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
