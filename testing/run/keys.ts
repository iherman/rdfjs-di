import { canonicalize } from "@tufjs/canonical-json";
import * as fs          from 'node:fs/promises';
import { KeyPair }      from '../../index';


export async function get_keys(): Promise<KeyPair[]> {
        const raw_keys: string = await fs.readFile('testing/keys.json', 'utf-8');
        return JSON.parse(raw_keys);
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
        return canonicalize(term);
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
