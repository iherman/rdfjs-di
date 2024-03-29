# Data Integrity algorithms for RDF Datasets — Proof of concepts implementation

This is a proof-of-concept implementation (in Typescript) of the [Verifiable Credentials Data Integrity (DI)](https://www.w3.org/TR/vc-data-integrity/) specification of the W3C. The DI specification is primarily aimed at [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) (i.e., JSON-LD based data structures to express credentials) but the approach is such that it can be used for any kind of RDF Datasets. This implementation does that.

It is proof-of-concepts, because, primarily at validation time it doesn't do all the checks that the DI specification describes, and have not (yet) been cross-checked with other DI implementations. What it proves, however, is that the DI specification may indeed be used to provide a proof for an RDF Dataset in the form of a separate "Proof Graph", i.e., an RDF Graph containing a signature that can be separated by a verifier.

## Some details

The steps for signature follow the "usual" approach for signing data, namely:

1. The input RDF Dataset is canonicalized, using the [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/), as defined by the W3C.
2. The resulting canonical N-Quads are sorted, and hashed to yield a canonical hash of the Dataset (the W3C specification relies on SHA-256 for hashing by default, which is used here).
3. The hash is signed using a secret key. The signature value is stored as a base64url value following the [Multibase](https://datatracker.ietf.org/doc/draft-multiformats-multibase) format.
4. A separate "proof graph" is generated, that includes the signature value, some basic metadata, and the public key of for the signature, stored in [JWK format](https://www.rfc-editor.org/rfc/rfc7517).

The package has separate API entries to generate, and validate, such proof graphs. It is also possible, following the DI spec, to provide "embedded" proofs, i.e., a new dataset, containing the original data, as well as the proof graph(s), each as a separate graph within the dataset. If a separate "anchor" resource is provided, then this new dataset will also contain additional RDF triples connecting the anchor to the proof graphs.

The crypto layer for the package relies on the Web Crypto API specification, and its implementation in `node.js` or `deno`. Accordingly, the following crypto algorithms are available for this implementation

- [ECDSA](https://w3c.github.io/webcrypto/#ecdsa)
- [RSA-PSS](https://w3c.github.io/webcrypto/#rsa-pss)
- [RSASSA-PKCS1-v1_5](https://w3c.github.io/webcrypto/#rsassa-pkcs1)

Although not strictly necessary for this package, a separate method is available as part of the API to generate cryptography keys for one of these three algorithms. Note that only ECDSA is part of the [VC Working Groups' specification](https://www.w3.org/TR/vc-di-ecdsa/), identified by the cryptosuite name `ecdsa-2022`; the other two are non-standard, and are identified with the temporary cryptosuite name of `rdfjs-di-rsa-pss` and `rdfjs-di-rsa-ssa`, respectively.

For more details, see:

- [Separate document for the API](https://iherman.github.io/rdfjs-di/modules/index.html)
- [A small RDF graph](https://github.com/iherman/rdfjs-di/blob/main/examples/small.ttl) and its ["verifiable" version with embedded proof graphs](https://github.com/iherman/rdfjs-di/blob/main/examples/small_with_proofs.ttl) 

(Note that the API works on an RDF Data model level, and does not include a Turtle/TriG parser or serializer; that should be done separately.)
