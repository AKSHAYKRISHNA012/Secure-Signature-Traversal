import { ethers } from 'ethers';
import { Payload, Signature } from './types';

/**
 * Creates a SHA-256 hash of the given data
 * @param data - The data to hash
 * @returns The hash as a hex string
 */
export function createHash(data: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(data));
}

/**
 * Serializes the payload to a consistent string format for hashing
 * @param payload - The document payload
 * @returns Serialized string representation
 */
export function serializePayload(payload: Payload): string {
  // Create a deterministic string representation
  return JSON.stringify(payload, Object.keys(payload).sort());
}

/**
 * Serializes a signature block to a consistent string format
 * @param signature - The signature object
 * @returns Serialized string representation
 */
export function serializeSignature(signature: Signature): string {
  // Create a deterministic string representation
  const sortedKeys = Object.keys(signature).sort();
  return JSON.stringify(signature, sortedKeys);
}

/**
 * Calculates the hash that should have been signed at a given step in the chain
 * @param payload - The original document payload
 * @param previousSignatures - All signatures that came before this one
 * @returns The hash that should be signed
 */
export function calculateExpectedHash(payload: Payload, previousSignatures: Signature[]): string {
  let dataToHash = serializePayload(payload);
  
  // Add each previous signature to the hash chain
  for (const sig of previousSignatures) {
    dataToHash += serializeSignature(sig);
  }
  
  return createHash(dataToHash);
}

/**
 * Verifies that a signature was created by the expected signer
 * @param message - The original message that was signed
 * @param signature - The signature to verify
 * @param expectedAddress - The expected signer's address
 * @returns True if the signature is valid
 */
export function verifySignature(message: string, signature: string, expectedAddress: string): boolean {
  try {
    const messageBytes = ethers.toUtf8Bytes(message);
    const messageHash = ethers.hashMessage(messageBytes);
    const recoveredAddress = ethers.recoverAddress(messageHash, signature);
    return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
  } catch (error) {
    return false;
  }
}

/**
 * Signs a message using a wallet's private key
 * @param message - The message to sign
 * @param wallet - The ethers wallet to sign with
 * @returns The signature as a hex string
 */
export async function signMessage(message: string, wallet: ethers.Wallet): Promise<string> {
  const messageBytes = ethers.toUtf8Bytes(message);
  return await wallet.signMessage(messageBytes);
}
