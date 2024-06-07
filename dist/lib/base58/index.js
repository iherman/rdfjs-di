"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.encode = void 0;
/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
const baseN_js_1 = require("./baseN.js");
// base58 characters (Bitcoin alphabet)
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function encode(input, maxline) {
    return (0, baseN_js_1.encode)(input, alphabet, maxline);
}
exports.encode = encode;
function decode(input) {
    return (0, baseN_js_1.decode)(input, alphabet);
}
exports.decode = decode;
