# Data Integrity algorithms for RDF Datasets — Proof of concepts implementation

This is a proof-of-concept implementation (in Typescript) of the [Verifiable Credentials Data Integrity (DI)](https://www.w3.org/TR/vc-data-integrity/) specification of the W3C. The DI specification is primarily aimed at [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) (i.e., JSON-LD based RDF Datasets to express credentials), but the approach is general enough so that it can be used for any kind of RDF Datasets. This implementation does that.

It is proof-of-concepts because, primarily at validation time, it doesn't do all the checks that the DI specification describes. 
Also, and in contrast with the DI specification, the Verification Method (ie, the public key) is expected to be _part of the proof graph_. In other words, the package does not 
retrieve the keys through a URL, if that is provided.
Finally, it has not (yet) been cross-checked with other DI implementations and, in general, should be much more thoroughly tested.
What it proves, however, is that the _DI specification may indeed be used to provide a proof for an RDF Dataset in the form of a separate "Proof Graph"_, i.e., an RDF Graph containing a signature that can be separated by a verifier.

## Some details

The steps for signature follow the "usual" approach for signing data, namely:

1. The input RDF Dataset is canonicalized, using the [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/), as defined by the W3C.
2. The resulting canonical N-Quads are sorted, and hashed to yield a canonical hash of the Dataset (the W3C specification relies on SHA-256 for hashing by default, which is used here).
3. The hash is signed using a secret key. The signature value is stored as a base64url value following the [Multibase](https://datatracker.ietf.org/doc/draft-multiformats-multibase) format.
4. A separate "proof graph" is generated, that includes the signature value, some basic metadata, and the public key of for the signature. The key is stored in [JWK format](https://www.rfc-editor.org/rfc/rfc7517) or in Multikey: the former is used for RSA keys (for which no Multikey encoding has been specified) and the latter is used for ECDSA and EdDSA, as required by the respective cryptosuite specifications.

The package has separate API entries to generate, and validate, such proof graphs. It is also possible, following the DI spec, to provide "embedded" proofs, i.e., a new dataset, containing the original data, as well as the proof graph(s), each as a separate graph within the dataset. If a separate "anchor" resource is provided, then this new dataset will also contain additional RDF triples connecting the anchor to the proof graphs.

> Note that this separate "anchor" is automatically provided in a Verifiable Credential Dataset, but this is generally not true and, in the current DI structure, must be provided explicitly.

The crypto layer for the package relies on the Web Crypto API specification, and its implementation in `node.js` or `deno`. Accordingly, the following crypto algorithms are available for this implementation

- EDDSA, a.k.a. Ed25519, not official in the WebCrypto specification, but implemented both in `node.js` and `deno`. See also the [EdDSA cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) specification.
- [ECDSA](https://w3c.github.io/webcrypto/#ecdsa). See also the [ECDSA cryptosuite](https://www.w3.org/TR/vc-di-ecdsa/) specification.
- [RSA-PSS](https://w3c.github.io/webcrypto/#rsa-pss). No DI cryptosuite specification exists.
- [RSASSA-PKCS1-v1_5](https://w3c.github.io/webcrypto/#rsassa-pkcs1). No DI cryptosuite specification exists.

Although not strictly necessary for this package, a separate method is available as part of the API to generate cryptography keys for one of these four algorithms. 
The first two algorithms are specified by cryptosuites, identified as `eddsa-rdfc-2019` and `ecdsa-rdfc-2019`, respectively.
The other two are non-standard, and are identified with the temporary cryptosuite name of `rsa-pss-rdfc-ih` and `rsa-ssa-rdfc-ih`, respectively.

For more details, see:

- [Separate document for the API](https://iherman.github.io/rdfjs-di/modules/index.html)
- [A small RDF graph](https://github.com/iherman/rdfjs-di/blob/main/examples/small.ttl) and its ["verifiable" version with embedded proof graphs](https://github.com/iherman/rdfjs-di/blob/main/examples/small_with_proofs.ttl) 

(Note that the API works on an RDF Data model level, and does not include a Turtle/TriG parser or serializer; that should be done separately.)
