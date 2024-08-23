import { canonify } from '@truestamp/canonify';
import * as fs      from 'node:fs/promises';
import { KeyData, jwkToCrypto }  from '../../index';

interface KeyPair {
    publicKey: JsonWebKey,
    privateKey: JsonWebKey,
}

interface KeyMetadata {
    controller?: string,
    expires?: string,
    revoked?: string,
    cryptosuite?: string,
}
interface jwkKeyData extends KeyMetadata, KeyPair {};

export async function get_keys(): Promise<KeyData[]> {
    const raw_keys: string = await fs.readFile('testing/keys.json', 'utf-8');
    const jwkKeyData: jwkKeyData[] = JSON.parse(raw_keys);
    const output: KeyData[] = [];

    for (const key of jwkKeyData) {
        const publ: CryptoKey = await jwkToCrypto(key.publicKey);
        const secr: CryptoKey = await jwkToCrypto(key.privateKey, true)
        const newItem: KeyData = {
            publicKey: publ,
            privateKey: secr,
        };
        if (key.controller)  newItem.controller = key.controller;
        if (key.expires)     newItem.expires = key.expires;
        if (key.revoked)     newItem.revoked = key.revoked;
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
