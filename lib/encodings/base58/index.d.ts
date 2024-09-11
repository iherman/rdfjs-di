
/// <reference types="node" />
/**
 * Encoder function for base58url, needed for the Multikey encoding
 * 
 * @param input 
 * @param maxline 
 * @returns 
 */
export function encode(input: Uint8Array, maxline?: number): string;

/**
 * Decoder function for base58url, needed for the Multikey encoding
 * 
 * @param input 
 * @param maxline 
 * @returns 
 */
export function decode(input: string): Uint8Array;
