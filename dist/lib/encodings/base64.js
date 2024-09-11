"use strict";
/**
 * Base 64 encoding/decoding
 *
 * @module
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.decode = exports.encode = void 0;
/*
 * These two came from perplexity.io, hopefully it is correct...
 */
const base64ToUrl = (base64String) => {
    return base64String.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};
const urlToBase64 = (base64Url) => {
    return base64Url.replace(/-/g, '+').replace(/_/g, '/');
};
/**
 * Convert an array buffer to base64url value.
 *
 * (Created with the help of perplexity.io...)
 *
 * @param arrayBuffer
 * @returns
 */
function encode(bytes) {
    let binary = "";
    for (let i = 0; i < bytes.length; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    const base64String = btoa(binary);
    return base64ToUrl(base64String);
}
exports.encode = encode;
/**
 * Convert a base64url value to Uint8Array
 *
 * (Created with the help of perplexity.io...)
 *
 * @param string
 * @returns
 */
function decode(url) {
    const base64string = urlToBase64(url);
    const binary = atob(base64string);
    const byteArray = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        byteArray[i] = binary.charCodeAt(i);
    }
    return byteArray;
}
exports.decode = decode;
