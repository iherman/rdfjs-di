/// <reference types="node" />

import * as rdf from '@rdfjs/types';
import { KeyPair } from './lib/common';
import { DI_ECDSA } from './lib/sign';

export { KeyPair }  from './lib/common';
export { DI_ECDSA, DataIntegrity } from './lib/sign';
export { DatasetCore } from '@rdfjs/types';

