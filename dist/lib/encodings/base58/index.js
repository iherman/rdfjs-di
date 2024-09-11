"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.encode = void 0;
/**
 * Base58url functions. This code
 *
 *
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
const baseN_js_1 = require("./baseN.js");
// base58 characters (Bitcoin alphabet)
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/**
 * Encoder function for base58url, needed for the Multikey encoding
 *
 * @param {*} input
 * @param {*} maxline
 * @returns
 */
function encode(input, maxline) {
    return (0, baseN_js_1.encode)(input, alphabet, maxline);
}
exports.encode = encode;
/**
 * Encoder function for base58url, needed for the Multikey encoding
 *
 * @param {*} input
 * @param {*} maxline
 * @returns
 */
function decode(input) {
    return (0, baseN_js_1.decode)(input, alphabet);
}
exports.decode = decode;
