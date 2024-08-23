import { canonify }     from '@truestamp/canonify';
import * as fs          from 'node:fs/promises';
import { KeyData }   from '../../index';


interface KeyPair {
    public: JsonWebKey,
    private: JsonWebKey,
}

interface KeyMetadata {
    controller?: string,
    expires?: string,
    revoked?: string,
    cryptosuite?: string,
}

interface jwkKeyData extends KeyMetadata, KeyPair {};

const RsaAlgs: Record<string, any> = {
    "PS256": { name: 'RSA-PSS', hash: 'SHA-256', saltLength: 32 },
    "PS384": { name: 'RSA-PSS', hash: 'SHA-384', saltLength: 32 },
    "RS256": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    "RS384": { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384' },
}

function algorithmDataJWK(key: JsonWebKey): any | null {
    switch (key.kty) {
        case "RSA": {
            try {
                return RsaAlgs[key.alg ?? ""]; // this will generate an exception, but it is caught below.
            } catch (e) {
                throw new Error(`Key's error in 'alg': ${e.message}`);
            }
        }
        case "EC": {
            return {
                name: "ECDSA",
                namedCurve: key.crv,
                hash: (key.crv) === "P-256" ? "SHA-256" : "SHA-384",
            };
        }
        case "OKP": default: {
            return {
                name: "Ed25519"
            };
        }
    }
}


export async function get_keys(): Promise<KeyData[]> {
    const raw_keys: string = await fs.readFile('testing/keys.json', 'utf-8');
    const jwkKeyData: jwkKeyData[] = JSON.parse(raw_keys);
    const output: KeyData[] = [];

    for (const key of jwkKeyData) {
        const jwkKey: JsonWebKey = key.public;
        const algorithm = algorithmDataJWK(jwkKey);
        const publ = await crypto.subtle.importKey("jwk", jwkKey, algorithm, true, ["verify"]);
        const secr = await crypto.subtle.importKey("jwk", key.private, algorithm, true, ["sign"]);
        const newItem: KeyData = {
            publicKey: publ,
            privateKey: secr,
        };
        if (key.controller)  newItem.controller = key.controller;
        if (key.expires)     newItem.expires = key.expires;
        if (key.revoked)     newItem.revoked = key.revoked;
        if (key.cryptosuite) newItem.cryptosuite = key.cryptosuite;
        output.push(newItem)
    }
    return output;
} 

interface ObjectSet<T> extends Iterable<T> {
    readonly size: number;
    add(term: T): ObjectSet<T>;
    has(term: T): boolean;
    delete(term: T): ObjectSet<T>;
    clear(term: T): ObjectSet<T>;
}

// Simple Set-like object for any (simple) objects:
export class OSet<T> implements ObjectSet<T> {
    private index: Map<string, T>;

    constructor(initial?: Iterable<T>) {
        this.index = new Map();
        if (initial) {
            for (const t of initial) this.add(t);
        }
    }

    private canon(term: T): string {
        return canonify(term);
    }

    get size(): number {
        return this.index.size;
    }

    add(term: T): OSet<T> {
        const key = this.canon(term);
        if (!this.index.has(key)) {
            this.index.set(key, term);
        }
        return this;
    }

    has(term: T): boolean {
        const key = this.canon(term);
        return this.index.has(key);
    }

    delete(term: T): OSet<T> {
        const key = this.canon(term);
        this.index.delete(key);
        return this;
    }

    clear(): OSet<T> {
        this.index = new Map();
        return this;
    }

    [Symbol.iterator]() {
        return this.index.values();
    }
}
