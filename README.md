--- NOT PRODUCTION READY ---

# Data Integrity algorithms for RDF Datasets — Proof of concepts implementation

This is a ***proof-of-concept*** implementation (in Typescript) of the [Verifiable Credentials Data Integrity (DI)](https://www.w3.org/TR/vc-data-integrity/) specification of the W3C, adapted to RDF Datasets.

The DI specification is primarily aimed at [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/) (i.e., JSON-LD based RDF Datasets to express credentials), but the approach is general enough for any kind of RDF Datasets. 
This implementation is an attempt to implement that.

It is proof-of-concepts, meaning that it is not production ready, and there are also minor discrepancies with the official specification. These are:

- Primarily at validation time, it doesn't do all the checks that the DI specification defines.
- In contrast with the DI specification, the Verification Method (ie, the public key) is expected to be be present in the input. In other words, the package does not retrieve the keys through a URL, it looks for the respective quads in the input dataset.
- Although it implements the the [EdDSA](https://www.w3.org/TR/vc-di-eddsa/) and [ECDSA](https://www.w3.org/TR/vc-di-ecdsa/) cryptosuites, the Multikey encoding of the latter is not yet conform to the Multikey specification.
The difference is that the Multikey encoding is done on the uncompressed crypto key as opposed to the compressed one, which is required by the specification.
(I have not yet found a reliable package, that also works with TypeScript, to uncompress a compressed key.)
- The management of proof chains is a bit restricted compared to the specification: proof chains and sets are not mixed. In other words, either all proofs are part of a chain or form a chain; the case when a previous proof reference points at a set of proofs has not been implemented.
- It has not (yet) been cross-checked with other DI implementations and, in general, should be much more thoroughly tested.

There is also a missing feature in the DI specification regarding the usage for Datasets in general. For a Verifiable Credential there is a natural "anchor" Resource used to "connect" the input dataset with its proof.
This is generally not true (see, e.g. [separate discussion](https://github.com/w3c/vc-data-model/issues/1248)) and, in this implementation, it must be provided explicitly to embed the proof into the dataset.

What the implementation proves, however, is that the 
_DI specification may indeed be used, with minor adjustment on the "anchor", to provide proofs for an RDF Dataset in the form of separate "Proof Graphs"_, i.e., RDF Graphs containing a signature and its metadata that can be separately verified.

## Some details

The steps for signature follow the "usual" approach for signing data, namely:

1. The input RDF Dataset is canonicalized, using the [RDF Dataset Canonicalization](https://www.w3.org/TR/rdf-canon/).
2. The resulting canonical N-Quads are sorted, and hashed to yield a canonical hash of the Dataset (the W3C specification relies on SHA-256 for hashing by default, which is used here).
3. A "proof option graph" is created, which includes crypto keys and some metadata. The key is stored in [JWK](https://www.rfc-editor.org/rfc/rfc7517) or in Multikey formats: the former is used for RSA keys (for which no Multikey encoding has been specified) and the latter is used for ECDSA and EdDSA, as required by the respective cryptosuite specifications. This separate graph is also canonicalized, sorted, and hashed.
4. The the two hash values are concatenated (in the order of the proof option graph and the original dataset), and signed using a secret key. The signature value is stored as a base64url value following the [Multibase](https://datatracker.ietf.org/doc/draft-multiformats-multibase) format, and its value is added to the proof option graph (turning it into a proof graph).

An extra complication occurs for proof chains: the specification requires that the previous proof in the chain is also "signed over", i.e., the dataset is expanded to include, for the purpose of a signature, the previous proof graph in its entirety.

The package has separate API entries to generate, and validate, such proof graphs. It is also possible, following the DI spec, to provide "embedded" proofs, i.e., a new dataset, containing the original data, as well as the proof graph(s), each as a separate graph within an RDF dataset. If a separate "anchor" resource is provided, then this new dataset will also contain additional RDF triples connecting the anchor to the proof graphs.

The crypto layer for the package relies on the Web Crypto API specification, and its implementation in `node.js` or `deno`. Accordingly, the following crypto algorithms are available for this implementation

- EDDSA, a.k.a. Ed25519. It is not official in the WebCrypto specification, but implemented both in `node.js` and `deno`. See also the [EdDSA cryptosuite](https://www.w3.org/TR/vc-di-eddsa/) specification.
- [ECDSA](https://w3c.github.io/webcrypto/#ecdsa). See also the [ECDSA cryptosuite](https://www.w3.org/TR/vc-di-ecdsa/) specification.
- [RSA-PSS](https://w3c.github.io/webcrypto/#rsa-pss). No DI cryptosuite specification exists.
- [RSASSA-PKCS1-v1_5](https://w3c.github.io/webcrypto/#rsassa-pkcs1). No DI cryptosuite specification exists.

Although not strictly necessary for this package, a separate method is available as part of the API to generate cryptography keys for one of these four algorithms.
The first two algorithms are specified by cryptosuites, identified as `eddsa-rdfc-2022` and `ecdsa-rdfc-2019`, respectively.
The other two are non-standard, and are identified with the temporary cryptosuite name of `rsa-pss-rdfc-ih` and `rsa-ssa-rdfc-ih`, respectively.
Note that there is no Multikey encoding for RSA keys, so the keys are stored in JWK format as a literal with an `rdf:JSON` datatype.

The user facing APIs use the JWK encoding of the keys only. This makes it easier for the user; Web Crypto provides JWK export "out of the box", and it becomes more complicated for Multikey. This may be changed in future.

For more details, see:

- [Separate document for the API](https://iherman.github.io/rdfjs-di/modules/index.html)
- [A small RDF graph](https://github.com/iherman/rdfjs-di/blob/main/examples/small.ttl) and its ["verifiable" version with embedded proof graphs](https://github.com/iherman/rdfjs-di/blob/main/examples/small_with_proofs.ttl).

(Note that the API works on an RDF Data model level, and does not include a Turtle/TriG parser or serializer; that should be done separately.)

## Examples

```typescript
import * as rdf from '@rdfjs/types';
import { KeyData, generateProofGraph, VerificationResult } from 'rdfjs-di';

const dataset: rdf.DatasetCore = generateYourDataset();
const keyPair: KeyData = generateYourWebCryptoKeyPair();

// 'proof' is a separate RDF graph with the keys, metadata, and the signature
const proof: rdf.DatasetCore = await generateProofGraph(dataset, keyPair)

// You can verify the information
const result: VerificationResult = await verifyProofGraph(dataset, proof);

// If everything is fine, this should be true
console.log(result.verified);

// The proof can also be embedded into the result
const embeddedProof: rdf.DatasetCore = await embedProofGraph(dataset, keyPair, anchorResource);

// This can be verified as before
const embeddedResult: VerificationResult = await verifyEmbeddedProofGraph(proof, anchor);

// There may be several keys, in which case an array of proofs are created:
const keypairs: KeyData[] = generateYourWebCryptoKeyPairs();

// The function interfaces are all overloaded, so the call format does not really change:
const proofs: rdf.DatasetCore[] = await generateProofGraph(dataset, keyPairs);

// etc.
```
