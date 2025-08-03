/**
 * Secure Signature Traversal Module
 * 
 * This module provides functionality to verify multi-signature documents
 * using a hash chain approach. It ensures both cryptographic authenticity
 * and data integrity throughout the signing process.
 */

export { traverse, createSignerRegistry } from './traversal';
export { testDataGenerator, TestDataGenerator } from './test-data-generator';
export * from './types';
export * from './crypto-utils';
