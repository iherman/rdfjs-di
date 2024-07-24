"use strict";
/**
 * Common types and classes.
 *
 * @packageDocumentation
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.Unclassified_Error = exports.Invalid_Verification_Method = exports.Proof_Transformation_Error = exports.Proof_Verification_Error = exports.Proof_Generation_Error = exports.ProblemDetail = exports.Cryptosuites = void 0;
var Cryptosuites;
(function (Cryptosuites) {
    Cryptosuites["ecdsa"] = "ecdsa-rdfc-2019";
    Cryptosuites["eddsa"] = "eddsa-rdfc-2022";
    Cryptosuites["rsa_pss"] = "rsa-pss-rdfc-ih";
    Cryptosuites["rsa_ssa"] = "rsa-ssa-rdfc-ih";
})(Cryptosuites || (exports.Cryptosuites = Cryptosuites = {}));
/*****************************************************************************************
 * Errors
 *****************************************************************************************/
/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
class ProblemDetail extends Error {
    /** The vocabulary URL for the entry */
    type;
    /** The error code */
    code;
    /** Title (essentially the error type name) */
    title;
    /** More detailed description of the error condition */
    detail;
    constructor(detail, title, code) {
        super(detail);
        this.detail = detail;
        this.title = title;
        this.code = code;
        this.type = `https://w3id.org/security#${title.replace(' ', '_').toUpperCase()}`;
    }
}
exports.ProblemDetail = ProblemDetail;
class Proof_Generation_Error extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Proof generation error', -16);
    }
}
exports.Proof_Generation_Error = Proof_Generation_Error;
class Proof_Verification_Error extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Proof verification error', -17);
    }
}
exports.Proof_Verification_Error = Proof_Verification_Error;
class Proof_Transformation_Error extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Proof transformation error', -18);
    }
}
exports.Proof_Transformation_Error = Proof_Transformation_Error;
class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Invalid verification method', -24);
    }
}
exports.Invalid_Verification_Method = Invalid_Verification_Method;
class Unclassified_Error extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Unclassified error', -100);
    }
}
exports.Unclassified_Error = Unclassified_Error;
