"use strict";
/*****************************************************************************************
 * Errors
 *****************************************************************************************/
Object.defineProperty(exports, "__esModule", { value: true });
exports.Invalid_Verification_Method = exports.Mismatched_Proof_Purpose = exports.Malformed_Proof_Error = exports.Proof_Generation_Error = exports.ProblemDetail = void 0;
/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
class ProblemDetail {
    /** The vocabulary URL for the entry */
    type;
    /** The error code */
    code;
    /** Title (essentially the error type name) */
    title;
    /** More detailed description of the error condition */
    detail;
    constructor(detail, title, code) {
        // super(detail);
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
class Malformed_Proof_Error extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Malformed proof error', -17);
    }
}
exports.Malformed_Proof_Error = Malformed_Proof_Error;
class Mismatched_Proof_Purpose extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Mismatched proof purpose', -18);
    }
}
exports.Mismatched_Proof_Purpose = Mismatched_Proof_Purpose;
class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail) {
        super(detail, 'Invalid verification method', -24);
    }
}
exports.Invalid_Verification_Method = Invalid_Verification_Method;
