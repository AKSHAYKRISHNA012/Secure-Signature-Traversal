import {
  SignedDocument,
  VerificationResult,
  SignatureVerificationResult,
  SignerRegistry
} from './types';
import {
  calculateExpectedHash,
  verifySignature
} from './crypto-utils';

/**
 * Performs secure signature traversal verification on a signed document
 * 
 * This function verifies the integrity of a multi-signature document by:
 * 1. Working backwards through the signature chain (last to first)
 * 2. Verifying each signature's cryptographic authenticity
 * 3. Ensuring the hash chain is intact (no tampering)
 * 
 * @param document - The signed document to verify
 * @param signerRegistry - Mapping of signer IDs to their public addresses
 * @returns Verification result with detailed information
 */
export function traverse(document: SignedDocument, signerRegistry: SignerRegistry): VerificationResult {
  const result: VerificationResult = {
    isValid: true,
    signatureResults: []
  };

  // Validate input
  if (!document?.signatures || document.signatures.length === 0) {
    return {
      isValid: false,
      error: 'Document has no signatures',
      signatureResults: []
    };
  }

  if (!document.payload) {
    return {
      isValid: false,
      error: 'Document has no payload',
      signatureResults: []
    };
  }

  // Process signatures in reverse order (last signature first)
  const signatures = [...document.signatures];
  
  for (let i = signatures.length - 1; i >= 0; i--) {
    const currentSignature = signatures[i];
    const previousSignatures = signatures.slice(0, i);
    
    const sigResult = verifySignatureAtIndex(
      document.payload,
      currentSignature,
      previousSignatures,
      signerRegistry
    );
    
    // Add to results (maintain chronological order in results)
    result.signatureResults.unshift(sigResult);
    
    // If any signature fails, the entire chain is invalid
    if (!sigResult.isValid) {
      result.isValid = false;
      if (!result.error) {
        result.error = `Signature chain broken at signer: ${currentSignature.signerId}`;
      }
    }
  }

  return result;
}

/**
 * Verifies a single signature in the chain
 */
function verifySignatureAtIndex(
  payload: any,
  signature: any,
  previousSignatures: any[],
  signerRegistry: SignerRegistry
): SignatureVerificationResult {
  const result: SignatureVerificationResult = {
    signerId: signature.signerId,
    isValid: true,
    hashChainValid: false,
    signatureValid: false
  };

  // Check if signer is in registry
  const signerAddress = signerRegistry[signature.signerId];
  if (!signerAddress) {
    result.isValid = false;
    result.error = `Signer ${signature.signerId} not found in registry`;
    return result;
  }

  // Step 1: Verify hash chain integrity
  const expectedHash = calculateExpectedHash(payload, previousSignatures);
  const hashChainValid = expectedHash === signature.signedHash;
  result.hashChainValid = hashChainValid;

  if (!hashChainValid) {
    result.isValid = false;
    result.error = `Hash chain broken: expected ${expectedHash}, got ${signature.signedHash}`;
    return result;
  }

  // Step 2: Verify cryptographic signature
  const signatureValid = verifySignature(
    signature.signedHash,
    signature.signature,
    signerAddress
  );
  result.signatureValid = signatureValid;

  if (!signatureValid) {
    result.isValid = false;
    result.error = `Invalid cryptographic signature for ${signature.signerId}`;
    return result;
  }

  // Both checks passed
  result.isValid = true;
  return result;
}

/**
 * Creates a simple signer registry for testing
 * @param signerMappings - Array of [signerId, address] pairs
 * @returns A signer registry object
 */
export function createSignerRegistry(signerMappings: [string, string][]): SignerRegistry {
  const registry: SignerRegistry = {};
  for (const [signerId, address] of signerMappings) {
    registry[signerId] = address;
  }
  return registry;
}
