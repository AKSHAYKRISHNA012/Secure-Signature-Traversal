/**
 * Represents a digital signature in the chain
 */
export interface Signature {
  /** Unique identifier of the signer */
  signerId: string;
  /** The actual cryptographic signature */
  signature: string;
  /** Timestamp when the signature was created */
  signedAt: string;
  /** Hash of the data that was signed */
  signedHash: string;
}

/**
 * Represents the document payload
 */
export interface Payload {
  /** Unique document identifier */
  documentId: string;
  /** The actual document content */
  content: string;
  [key: string]: any; // Allow additional properties
}

/**
 * Represents a complete signed document with signature chain
 */
export interface SignedDocument {
  /** The original document data */
  payload: Payload;
  /** Array of signatures in chronological order (first signer to last signer) */
  signatures: Signature[];
}

/**
 * Result of signature traversal verification
 */
export interface VerificationResult {
  /** Whether the entire signature chain is valid */
  isValid: boolean;
  /** Detailed error message if validation fails */
  error?: string;
  /** Details about each signature verification */
  signatureResults: SignatureVerificationResult[];
}

/**
 * Result of individual signature verification
 */
export interface SignatureVerificationResult {
  /** The signer ID */
  signerId: string;
  /** Whether this specific signature is valid */
  isValid: boolean;
  /** Error message for this signature if invalid */
  error?: string;
  /** Whether the hash chain is intact up to this point */
  hashChainValid: boolean;
  /** Whether the cryptographic signature is valid */
  signatureValid: boolean;
}

/**
 * Registry for mapping signer IDs to their public addresses
 */
export interface SignerRegistry {
  [signerId: string]: string; // signerId -> public address
}
