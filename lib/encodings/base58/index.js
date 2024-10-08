/** 
 * Base58url functions. This code
 * 
 * 
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import {
  encode as _encode,
  decode as _decode
} from './baseN.js';

// base58 characters (Bitcoin alphabet)
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Encoder function for base58url, needed for the Multikey encoding
 * 
 * @param {*} input 
 * @param {*} maxline 
 * @returns 
 */
export function encode(input, maxline) {
  return _encode(input, alphabet, maxline);
}

/**
 * Encoder function for base58url, needed for the Multikey encoding
 * 
 * @param {*} input 
 * @param {*} maxline 
 * @returns 
 */
export function decode(input) {
  return _decode(input, alphabet);
}
