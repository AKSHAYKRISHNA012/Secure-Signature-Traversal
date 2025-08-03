import { ethers } from 'ethers';
import { SignedDocument, Payload, Signature, SignerRegistry } from './types';
import { calculateExpectedHash, signMessage } from './crypto-utils';

/**
 * Test data generator for creating valid multi-signed documents
 */
export class TestDataGenerator {
  private wallets: { [signerId: string]: ethers.Wallet } = {};

  /**
   * Creates test wallets for signers
   */
  constructor() {
    // Create deterministic wallets for consistent testing
    this.wallets = {
      'developer-alice': new ethers.Wallet('0x1234567890123456789012345678901234567890123456789012345678901234'),
      'qa-bob': new ethers.Wallet('0x2345678901234567890123456789012345678901234567890123456789012345'),
      'manager-charlie': new ethers.Wallet('0x3456789012345678901234567890123456789012345678901234567890123456')
    };
  }

  /**
   * Gets the signer registry for all test wallets
   */
  getSignerRegistry(): SignerRegistry {
    const registry: SignerRegistry = {};
    for (const [signerId, wallet] of Object.entries(this.wallets)) {
      registry[signerId] = wallet.address;
    }
    return registry;
  }

  /**
   * Creates a valid multi-signed document
   */
  async generateValidDocument(): Promise<SignedDocument> {
    const payload: Payload = {
      documentId: 'CONTRACT-XYZ-123',
      content: 'This is the legal agreement text that must remain unchanged throughout the signing process.'
    };

    const signatures: Signature[] = [];
    const signerOrder = ['developer-alice', 'qa-bob', 'manager-charlie'];

    for (const signerId of signerOrder) {
      const wallet = this.wallets[signerId];
      const previousSignatures = [...signatures]; // Copy current signatures
      
      // Calculate what this signer should sign
      const expectedHash = calculateExpectedHash(payload, previousSignatures);
      
      // Sign the hash
      const signature = await signMessage(expectedHash, wallet);
      
      // Create signature object
      const signatureObj: Signature = {
        signerId,
        signature,
        signedAt: new Date(Date.now() + signatures.length * 90 * 60 * 1000).toISOString(), // 90 minutes apart
        signedHash: expectedHash
      };
      
      signatures.push(signatureObj);
    }

    return {
      payload,
      signatures
    };
  }

  /**
   * Creates a document with a tampered payload
   */
  async generateDocumentWithTamperedPayload(): Promise<SignedDocument> {
    const validDoc = await this.generateValidDocument();
    
    // Tamper with the payload after signing
    validDoc.payload.content = 'This content has been maliciously altered!';
    
    return validDoc;
  }

  /**
   * Creates a document with an invalid signature
   */
  async generateDocumentWithInvalidSignature(): Promise<SignedDocument> {
    const validDoc = await this.generateValidDocument();
    
    // Corrupt one of the signatures
    if (validDoc.signatures.length > 1) {
      validDoc.signatures[1].signature = validDoc.signatures[1].signature.replace('a', 'b');
    }
    
    return validDoc;
  }

  /**
   * Creates a document with a broken hash chain
   */
  async generateDocumentWithBrokenHashChain(): Promise<SignedDocument> {
    const validDoc = await this.generateValidDocument();
    
    // Corrupt one of the signed hashes
    if (validDoc.signatures.length > 1) {
      validDoc.signatures[1].signedHash = validDoc.signatures[1].signedHash.replace('a', 'b');
    }
    
    return validDoc;
  }

  /**
   * Gets a wallet by signer ID (for testing)
   */
  getWallet(signerId: string): ethers.Wallet | undefined {
    return this.wallets[signerId];
  }
}

// Export a default instance for easy use
export const testDataGenerator = new TestDataGenerator();
