"use strict";
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
Object.defineProperty(exports, "__esModule", { value: true });
exports.verifyProofGraphs = exports.generateAProofGraph = exports.xsd_datetime = exports.sec_created = exports.sec_revoked = exports.sec_expires = exports.sec_verificationMethod = exports.sec_assertionMethod = exports.sec_authenticationMethod = exports.sec_proofPurpose = exports.sec_publicKeyMultibase = exports.sec_publicKeyJwk = exports.sec_proofValue = exports.sec_di_proof = exports.sec_proof = exports.rdf_json = exports.rdf_type = exports.xsd_prefix = exports.rdf_prefix = exports.sec_prefix = void 0;
const n3 = require("n3");
const uuid_1 = require("uuid");
const canonify_1 = require("@truestamp/canonify");
const types = require("./types");
const utils_1 = require("./utils");
const crypto_utils_1 = require("./crypto_utils");
const multikey_1 = require("./multikey");
// n3.DataFactory is a namespace with some functions...
const { namedNode, literal, quad } = n3.DataFactory;
/***************************************************************************************
 * Namespaces and specific terms that are used several times
 **************************************************************************************/
/* Various namespaces, necessary when constructing a proof graph */
exports.sec_prefix = (0, utils_1.createPrefix)("https://w3id.org/security#");
exports.rdf_prefix = (0, utils_1.createPrefix)("http://www.w3.org/1999/02/22-rdf-syntax-ns#");
exports.xsd_prefix = (0, utils_1.createPrefix)("http://www.w3.org/2001/XMLSchema#");
exports.rdf_type = (0, exports.rdf_prefix)('type');
exports.rdf_json = (0, exports.rdf_prefix)('JSON');
exports.sec_proof = (0, exports.sec_prefix)('proof');
exports.sec_di_proof = (0, exports.sec_prefix)('DataIntegrityProof');
exports.sec_proofValue = (0, exports.sec_prefix)('proofValue');
exports.sec_publicKeyJwk = (0, exports.sec_prefix)('publicKeyJwk');
exports.sec_publicKeyMultibase = (0, exports.sec_prefix)('publicKeyMultibase');
exports.sec_proofPurpose = (0, exports.sec_prefix)('proofPurpose');
exports.sec_authenticationMethod = (0, exports.sec_prefix)('authenticationMethod');
exports.sec_assertionMethod = (0, exports.sec_prefix)('assertionMethod');
exports.sec_verificationMethod = (0, exports.sec_prefix)('verificationMethod');
exports.sec_expires = (0, exports.sec_prefix)('expires');
exports.sec_revoked = (0, exports.sec_prefix)('revoked');
exports.sec_created = (0, exports.sec_prefix)('created');
exports.xsd_datetime = (0, exports.xsd_prefix)('dateTime');
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
async function calculateProofOptionsHash(proofGraph) {
    const proofOptions = new n3.Store();
    // The proof option graph is a copy of the proof graph quads, except that:
    // 1. the proof value triple should be removed
    // 2. the value of the sec_publicKeyJwk must be canonicalized
    for (const q of proofGraph) {
        if (q.predicate.value === exports.sec_proofValue.value) {
            continue;
        }
        else if (q.predicate.value === exports.sec_publicKeyJwk.value) {
            // get the JSON value from the object
            const jwk = JSON.parse(q.object.value);
            proofOptions.addQuad(q.subject, q.predicate, literal((0, canonify_1.canonify)(jwk), exports.rdf_json), q.graph);
        }
        else {
            proofOptions.add(q);
        }
    }
    // The return value must be the hash of the proof option graph
    return await (0, utils_1.calculateDatasetHash)(proofGraph);
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
async function generateAProofGraph(report, hashValue, keyData) {
    const cryptosuite = keyData?.cryptosuite || (0, crypto_utils_1.cryptosuiteId)(report, keyData);
    // Generate the key data to be stored in the proof graph; either multikey or jwk, depending on the cryptosuite
    const addKeyResource = async (jsonKey, proofGraph, keyResource) => {
        let retval = [];
        if (jsonKey.kty === "OKP" || jsonKey.kty === "EC") {
            // We are in multikey land...
            const key = await crypto.subtle.importKey("jwk", jsonKey, (0, crypto_utils_1.algorithmData)(report, jsonKey), true, ['verify']);
            const { cryptosuite, multikey } = await (0, multikey_1.keyToMultikey)(key);
            retval = [
                quad(proofGraph, (0, exports.sec_prefix)('cryptosuite'), literal(cryptosuite)),
                quad(keyResource, exports.rdf_type, (0, exports.sec_prefix)('Multikey')),
                quad(keyResource, exports.sec_publicKeyMultibase, literal(multikey)),
            ];
        }
        else {
            retval = [
                quad(proofGraph, (0, exports.sec_prefix)('cryptosuite'), literal(cryptosuite)),
                quad(keyResource, exports.rdf_type, (0, exports.sec_prefix)('JsonWebKey')),
                quad(keyResource, exports.sec_publicKeyJwk, literal(JSON.stringify(jsonKey), exports.rdf_json)),
            ];
        }
        return retval;
    };
    // Create a proof graph. Just a boring set of quad generations...
    const createProofOptionGraph = async () => {
        const proofGraph = new n3.Store();
        // Unique URL-s, for the time being as uuid-s
        const proofGraphResource = namedNode(`urn:uuid:${(0, uuid_1.v4)()}`);
        const verificationMethodId = `urn:uuid:${(0, uuid_1.v4)()}`;
        const keyResource = namedNode(verificationMethodId);
        // Create the resource for the proof graph itself, referring to a separate key resource
        proofGraph.addQuads([
            quad(proofGraphResource, exports.rdf_type, exports.sec_di_proof),
            quad(proofGraphResource, exports.sec_verificationMethod, keyResource),
            quad(proofGraphResource, exports.sec_created, literal((new Date()).toISOString(), exports.xsd_datetime)),
            quad(proofGraphResource, exports.sec_proofPurpose, exports.sec_authenticationMethod),
            quad(proofGraphResource, exports.sec_proofPurpose, exports.sec_assertionMethod)
        ]);
        // Create the separate key resource triples (within the same graph)
        if (keyData.controller)
            proofGraph.add(quad(keyResource, (0, exports.sec_prefix)('controller'), namedNode(keyData.controller)));
        if (keyData.expires)
            proofGraph.add(quad(keyResource, exports.sec_expires, literal(keyData.expires, exports.xsd_datetime)));
        if (keyData.revoked)
            proofGraph.add(quad(keyResource, exports.sec_revoked, literal(keyData.revoked, exports.xsd_datetime)));
        proofGraph.addQuads(await addKeyResource(keyData.public, proofGraphResource, keyResource));
        return { proofGraph, proofGraphResource };
    };
    // Put together the proof option graph and calculate its hash
    const { proofGraph, proofGraphResource } = await createProofOptionGraph();
    const proofOptionHashValue = await calculateProofOptionsHash(proofGraph);
    // This is the extra trick in the cryptosuite specifications: the signature is upon the 
    // concatenation of the original dataset's hash and the hash of the proof option graph.
    const signature = await (0, crypto_utils_1.sign)(report, hashValue + proofOptionHashValue, keyData.private);
    // Close up...
    if (signature === null) {
        // An error has occurred during signature; details are in the report.
        // No proof graph is generated
        return new n3.Store();
    }
    else {
        // Add the signature value to the proof graph
        proofGraph.add(quad(proofGraphResource, exports.sec_proofValue, literal(signature)));
        return proofGraph;
    }
}
exports.generateAProofGraph = generateAProofGraph;
;
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
async function verifyAProofGraph(report, hash, proof, proofId) {
    const localErrors = [];
    const localWarnings = [];
    const getProofValue = (store) => {
        // Retrieve the signature value per spec:
        const proof_values = store.getQuads(null, exports.sec_proofValue, null, null);
        if (proof_values.length === 0) {
            localErrors.push(new types.Malformed_Proof_Error("No proof value"));
            return null;
        }
        else if (proof_values.length > 1) {
            localErrors.push(new types.Malformed_Proof_Error("Several proof values"));
        }
        return proof_values[0].object.value;
    };
    const getPublicKey = async (store) => {
        // first see if the verificationMethod has been set properly
        const verificationMethod = store.getQuads(null, exports.sec_verificationMethod, null, null);
        if (verificationMethod.length === 0) {
            localErrors.push(new types.Malformed_Proof_Error("No verification method"));
            return null;
        }
        else if (verificationMethod.length > 1) {
            localErrors.push(new types.Malformed_Proof_Error("Several verification methods"));
        }
        const publicKey = verificationMethod[0].object;
        // Check the creation/expiration/revocation dates, if any...
        const now = new Date();
        const creationDates = store.getQuads(null, exports.sec_created, null, null);
        for (const exp of creationDates) {
            if ((new Date(exp.object.value)) > now) {
                localWarnings.push(new types.Invalid_Verification_Method(`Proof was created in the future... ${exp.object.value}`));
            }
        }
        const expirationDates = store.getQuads(publicKey, exports.sec_expires, null, null);
        for (const exp of expirationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new types.Invalid_Verification_Method(`<${publicKey.value}> key expired on ${exp.object.value}`));
                return null;
            }
        }
        const revocationDates = store.getQuads(publicKey, exports.sec_revoked, null, null);
        for (const exp of revocationDates) {
            if ((new Date(exp.object.value)) < now) {
                localErrors.push(new types.Invalid_Verification_Method(`<${publicKey.value}> key was revoked on ${exp.object.value}`));
                return null;
            }
        }
        // All conditions are fulfilled, the key can now be retrieved and returned 
        // The key itself can be in JWK or in Multikey format
        const keys_jwk = store.getQuads(publicKey, exports.sec_publicKeyJwk, null, null);
        const keys_multikey = store.getQuads(publicKey, exports.sec_publicKeyMultibase, null, null);
        // Both arrays cannot exist at the same time!
        if (keys_jwk.length > 0 && keys_multikey.length > 0) {
            localWarnings.push(new types.Malformed_Proof_Error(`JWK or Multikey formats can be used, but not both.`));
            return null;
        }
        else if (keys_jwk.length === 0) {
            // Trying Multikey, JWK is not used...
            if (keys_multikey.length === 0) {
                localErrors.push(new types.Invalid_Verification_Method(`No key values`));
                return null;
            }
            else if (keys_multikey.length === 1) {
                try {
                    const key = await (0, multikey_1.multikeyToKey)(keys_multikey[0].object.value);
                    return crypto.subtle.exportKey('jwk', key);
                }
                catch (e) {
                    localWarnings.push(new types.Malformed_Proof_Error(`Parsing error for Multikey: ${e.message}`));
                    return null;
                }
            }
            else {
                localErrors.push(new types.Invalid_Verification_Method("More than one Multikey encoded keys"));
                return null;
            }
        }
        else if (keys_jwk.length === 1) {
            // We have a JWK key, we can return it if it parses o.k.
            try {
                return JSON.parse(keys_jwk[0].object.value);
            }
            catch (e) {
                // This happens if there is a JSON parse error with the key...
                localWarnings.push(new types.Malformed_Proof_Error(`Parsing error for JWK: ${e.message}`));
                return null;
            }
        }
        else {
            localErrors.push(new types.Invalid_Verification_Method("More than one JWK encoded keys"));
            return null;
        }
    };
    // Check the "proofPurpose" property value
    const checkProofPurposes = (store) => {
        const purposes = store.getQuads(null, exports.sec_proofPurpose, null, null);
        if (purposes.length === 0) {
            localErrors.push(new types.Invalid_Verification_Method("No proof purpose set"));
        }
        else {
            const wrongPurposes = [];
            for (const q of purposes) {
                if (!(q.object.equals(exports.sec_authenticationMethod) || q.object.equals(exports.sec_assertionMethod))) {
                    wrongPurposes.push(`<${q.object.value}>`);
                }
            }
            if (wrongPurposes.length > 0) {
                localErrors.push(new types.Mismatched_Proof_Purpose(`Invalid proof purpose value(s): ${wrongPurposes.join(", ")}`));
            }
        }
    };
    // Retrieve necessary values with checks
    checkProofPurposes(proof);
    const publicKey = await getPublicKey(proof);
    const proofValue = getProofValue(proof);
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
        // First the proof option graph must be created and then hashed
        const proofOptionGraphHash = await calculateProofOptionsHash(proof);
        const check_results = await (0, crypto_utils_1.verify)(report, hash + proofOptionGraphHash, proofValue, publicKey);
        // the return value should nevertheless be false if there have been errors
        return check_results ? localErrors.length === 0 : true;
    }
    else {
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
async function verifyProofGraphs(report, hash, proofs) {
    const allErrors = [];
    // deno-lint-ignore require-await
    const singleVerification = async (pr) => {
        const singleReport = { errors: [], warnings: [] };
        allErrors.push(singleReport);
        return verifyAProofGraph(singleReport, hash, pr.dataset, pr.id);
    };
    const promises = proofs.map(singleVerification);
    const result = await Promise.all(promises);
    // consolidate error messages. By using allErrors the error messages
    // follow the same order as the incoming proof graph references,
    // and are not possibly shuffled by the async calls
    for (const singleReport of allErrors) {
        report.errors = [...report.errors, ...singleReport.errors];
        report.warnings = [...report.warnings, ...singleReport.warnings];
    }
    return !result.includes(false);
}
exports.verifyProofGraphs = verifyProofGraphs;
