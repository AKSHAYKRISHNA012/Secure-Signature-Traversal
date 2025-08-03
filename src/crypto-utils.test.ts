import { ethers } from 'ethers';
import {
  createHash,
  serializePayload,
  serializeSignature,
  calculateExpectedHash,
  verifySignature,
  signMessage
} from './crypto-utils';
import { Payload, Signature } from './types';

describe('Crypto Utilities', () => {
  let testWallet: ethers.Wallet;

  beforeAll(() => {
    testWallet = new ethers.Wallet('0x1234567890123456789012345678901234567890123456789012345678901234');
  });

  describe('createHash', () => {
    it('should create consistent hashes for the same input', () => {
      const input = 'test data';
      const hash1 = createHash(input);
      const hash2 = createHash(input);
      
      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^0x[a-f0-9]{64}$/); // Should be a valid hex hash
    });

    it('should create different hashes for different inputs', () => {
      const hash1 = createHash('data1');
      const hash2 = createHash('data2');
      
      expect(hash1).not.toBe(hash2);
    });

    it('should be sensitive to small changes', () => {
      const hash1 = createHash('test data');
      const hash2 = createHash('test data '); // Added space
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('serializePayload', () => {
    it('should create deterministic serialization', () => {
      const payload: Payload = {
        documentId: 'test-123',
        content: 'test content',
        metadata: { author: 'Alice' }
      };

      const serialized1 = serializePayload(payload);
      const serialized2 = serializePayload(payload);
      
      expect(serialized1).toBe(serialized2);
    });

    it('should handle property order consistently', () => {
      const payload1: Payload = {
        documentId: 'test',
        content: 'content'
      };

      const payload2: Payload = {
        content: 'content',
        documentId: 'test'
      };

      const serialized1 = serializePayload(payload1);
      const serialized2 = serializePayload(payload2);
      
      expect(serialized1).toBe(serialized2);
    });
  });

  describe('serializeSignature', () => {
    it('should create deterministic serialization', () => {
      const signature: Signature = {
        signerId: 'alice',
        signature: '0x123',
        signedAt: '2025-01-01T00:00:00Z',
        signedHash: '0xabc'
      };

      const serialized1 = serializeSignature(signature);
      const serialized2 = serializeSignature(signature);
      
      expect(serialized1).toBe(serialized2);
    });
  });

  describe('calculateExpectedHash', () => {
    it('should calculate hash for payload only when no previous signatures', () => {
      const payload: Payload = {
        documentId: 'test',
        content: 'content'
      };

      const hash = calculateExpectedHash(payload, []);
      const expectedHash = createHash(serializePayload(payload));
      
      expect(hash).toBe(expectedHash);
    });

    it('should include previous signatures in hash calculation', () => {
      const payload: Payload = {
        documentId: 'test',
        content: 'content'
      };

      const previousSig: Signature = {
        signerId: 'alice',
        signature: '0x123',
        signedAt: '2025-01-01T00:00:00Z',
        signedHash: '0xabc'
      };

      const hash = calculateExpectedHash(payload, [previousSig]);
      
      // Should be different from payload-only hash
      const payloadOnlyHash = calculateExpectedHash(payload, []);
      expect(hash).not.toBe(payloadOnlyHash);
    });

    it('should be order-sensitive for signatures', () => {
      const payload: Payload = { documentId: 'test', content: 'content' };
      
      const sig1: Signature = {
        signerId: 'alice',
        signature: '0x123',
        signedAt: '2025-01-01T00:00:00Z',
        signedHash: '0xabc'
      };

      const sig2: Signature = {
        signerId: 'bob',
        signature: '0x456',
        signedAt: '2025-01-01T01:00:00Z',
        signedHash: '0xdef'
      };

      const hash1 = calculateExpectedHash(payload, [sig1, sig2]);
      const hash2 = calculateExpectedHash(payload, [sig2, sig1]);
      
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('signMessage and verifySignature', () => {
    it('should create and verify valid signatures', async () => {
      const message = 'test message';
      const signature = await signMessage(message, testWallet);
      
      expect(signature).toMatch(/^0x[a-f0-9]{130}$/); // Valid signature format
      
      const isValid = verifySignature(message, signature, testWallet.address);
      expect(isValid).toBe(true);
    });

    it('should reject signatures from wrong signer', async () => {
      const message = 'test message';
      const signature = await signMessage(message, testWallet);
      
      const wrongAddress = '0x742d35Cc6464C4532D2c1234567890abcdef1234';
      const isValid = verifySignature(message, signature, wrongAddress);
      expect(isValid).toBe(false);
    });

    it('should reject tampered signatures', async () => {
      const message = 'test message';
      const signature = await signMessage(message, testWallet);
      
      // Tamper with the signature
      const tamperedSignature = signature.replace('a', 'b');
      
      const isValid = verifySignature(message, tamperedSignature, testWallet.address);
      expect(isValid).toBe(false);
    });

    it('should reject signatures for different messages', async () => {
      const originalMessage = 'original message';
      const signature = await signMessage(originalMessage, testWallet);
      
      const differentMessage = 'different message';
      const isValid = verifySignature(differentMessage, signature, testWallet.address);
      expect(isValid).toBe(false);
    });

    it('should handle invalid signature gracefully', () => {
      const message = 'test message';
      const invalidSignature = 'not-a-signature';
      
      const isValid = verifySignature(message, invalidSignature, testWallet.address);
      expect(isValid).toBe(false);
    });
  });
});
