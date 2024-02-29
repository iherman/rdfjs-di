/*****************************************************************************************
 * Errors
 *****************************************************************************************/

/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
export abstract class ProblemDetail  {
    /** The vocabulary URL for the entry */
    type: string;
    /** The error code */
    code: number;
    /** Title (essentially the error type name) */
    title: string;
    /** More detailed description of the error condition */
    detail: string;

    constructor(detail: string, title: string, code: number) {
        // super(detail);
        this.detail = detail;
        this.title  = title;
        this.code   = code;
        this.type   = `https://w3id.org/security#${title.replace(' ', '_').toUpperCase()}`;
    }
}

export class Proof_Generation_Error extends ProblemDetail {
    constructor(detail: string) {
        super(detail,'Proof generation error', -16);
    }
}

export class Malformed_Proof_Error extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Malformed proof error', -17);
    }
}

export class Mismatched_Proof_Purpose extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Mismatched proof purpose', -18);
    }
}

export class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail: string) {
        super(detail, 'Invalid verification method', -24);
    }
}

