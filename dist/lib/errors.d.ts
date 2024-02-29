/*****************************************************************************************
 * Errors
 *****************************************************************************************/
/**
 * Superclass for the various error conditions. The entries are based on the DI specification.
 */
export declare abstract class ProblemDetail {
    /** The vocabulary URL for the entry */
    type: string;
    /** The error code */
    code: number;
    /** Title (essentially the error type name) */
    title: string;
    /** More detailed description of the error condition */
    detail: string;
    constructor(detail: string, title: string, code: number);
}
export declare class Proof_Generation_Error extends ProblemDetail {
    constructor(detail: string);
}
export declare class Malformed_Proof_Error extends ProblemDetail {
    constructor(detail: string);
}
export declare class Mismatched_Proof_Purpose extends ProblemDetail {
    constructor(detail: string);
}
export declare class Invalid_Verification_Method extends ProblemDetail {
    constructor(detail: string);
}
