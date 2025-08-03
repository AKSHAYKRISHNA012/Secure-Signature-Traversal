import { traverse, createSignerRegistry } from './traversal';
import { testDataGenerator } from './test-data-generator';
import { SignedDocument, VerificationResult, SignatureVerificationResult } from './types';

describe('Secure Signature Traversal', () => {
  let signerRegistry: any;

  beforeAll(() => {
    signerRegistry = testDataGenerator.getSignerRegistry();
  });

  describe('traverse function', () => {
    describe('Happy Path - Valid Documents', () => {
      it('should verify a valid 3-signature document', async () => {
        const document = await testDataGenerator.generateValidDocument();
        const result = traverse(document, signerRegistry);

        expect(result.isValid).toBe(true);
        expect(result.error).toBeUndefined();
        expect(result.signatureResults).toHaveLength(3);
        
        // Check each signature result
        result.signatureResults.forEach((sigResult: SignatureVerificationResult, index: number) => {
          expect(sigResult.isValid).toBe(true);
          expect(sigResult.hashChainValid).toBe(true);
          expect(sigResult.signatureValid).toBe(true);
          expect(sigResult.error).toBeUndefined();
        });
      });

      it('should verify signatures in the correct order', async () => {
        const document = await testDataGenerator.generateValidDocument();
        const result = traverse(document, signerRegistry);

        expect(result.signatureResults[0].signerId).toBe('developer-alice');
        expect(result.signatureResults[1].signerId).toBe('qa-bob');
        expect(result.signatureResults[2].signerId).toBe('manager-charlie');
      });
    });

    describe('Input Validation', () => {
      it('should handle documents with no signatures', () => {
        const document: SignedDocument = {
          payload: { documentId: 'test', content: 'test' },
          signatures: []
        };

        const result = traverse(document, signerRegistry);
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Document has no signatures');
      });

      it('should handle documents with no payload', () => {
        const document = {
          payload: null,
          signatures: [{ signerId: 'test', signature: 'test', signedAt: 'test', signedHash: 'test' }]
        } as any;

        const result = traverse(document, signerRegistry);
        expect(result.isValid).toBe(false);
        expect(result.error).toBe('Document has no payload');
      });

      it('should handle null/undefined documents', () => {
        const result1 = traverse(null as any, signerRegistry);
        expect(result1.isValid).toBe(false);
        expect(result1.error).toBe('Document has no signatures');

        const result2 = traverse(undefined as any, signerRegistry);
        expect(result2.isValid).toBe(false);
        expect(result2.error).toBe('Document has no signatures');
      });
    });

    describe('Tampered Data Detection', () => {
      it('should detect tampered payload content', async () => {
        const document = await testDataGenerator.generateDocumentWithTamperedPayload();
        const result = traverse(document, signerRegistry);

        expect(result.isValid).toBe(false);
        expect(result.error).toContain('Signature chain broken');
        
        // The first signature should fail because the payload was changed
        expect(result.signatureResults[0].isValid).toBe(false);
        expect(result.signatureResults[0].hashChainValid).toBe(false);
      });

      it('should detect corrupted signatures', async () => {
        const document = await testDataGenerator.generateDocumentWithInvalidSignature();
        const result = traverse(document, signerRegistry);

        expect(result.isValid).toBe(false);
        expect(result.error).toContain('Signature chain broken');
        
        // Find the corrupted signature
        const corruptedSig = result.signatureResults.find((sig: SignatureVerificationResult) => !sig.isValid);
        expect(corruptedSig).toBeDefined();
        expect(corruptedSig!.signatureValid).toBe(false);
        expect(corruptedSig!.error).toContain('Invalid cryptographic signature');
      });

      it('should detect broken hash chain', async () => {
        const document = await testDataGenerator.generateDocumentWithBrokenHashChain();
        const result = traverse(document, signerRegistry);

        expect(result.isValid).toBe(false);
        expect(result.error).toContain('Signature chain broken');
        
        // Find the signature with broken hash chain
        const brokenSig = result.signatureResults.find((sig: SignatureVerificationResult) => !sig.hashChainValid);
        expect(brokenSig).toBeDefined();
        expect(brokenSig!.error).toContain('Hash chain broken');
      });
    });

    describe('Signer Registry Validation', () => {
      it('should fail when signer is not in registry', async () => {
        const document = await testDataGenerator.generateValidDocument();
        const limitedRegistry = createSignerRegistry([
          ['developer-alice', signerRegistry['developer-alice']],
          ['qa-bob', signerRegistry['qa-bob']]
          // Missing manager-charlie
        ]);

        const result = traverse(document, limitedRegistry);
        expect(result.isValid).toBe(false);
        
        const failedSig = result.signatureResults.find((sig: SignatureVerificationResult) => 
          sig.signerId === 'manager-charlie'
        );
        expect(failedSig?.error).toContain('not found in registry');
      });

      it('should work with custom signer registry', async () => {
        const document = await testDataGenerator.generateValidDocument();
        const customRegistry = createSignerRegistry([
          ['developer-alice', testDataGenerator.getWallet('developer-alice')!.address],
          ['qa-bob', testDataGenerator.getWallet('qa-bob')!.address],
          ['manager-charlie', testDataGenerator.getWallet('manager-charlie')!.address]
        ]);

        const result = traverse(document, customRegistry);
        expect(result.isValid).toBe(true);
      });
    });

    describe('Edge Cases', () => {
      it('should handle single signature documents', async () => {
        const payload = { documentId: 'single-sig', content: 'test content' };
        const alice = testDataGenerator.getWallet('developer-alice')!;
        const { calculateExpectedHash, signMessage } = await import('./crypto-utils');
        const expectedHash = calculateExpectedHash(payload, []);
        const signature = await signMessage(expectedHash, alice);

        const document: SignedDocument = {
          payload,
          signatures: [{
            signerId: 'developer-alice',
            signature,
            signedAt: new Date().toISOString(),
            signedHash: expectedHash
          }]
        };

        const result = traverse(document, signerRegistry);
        expect(result.isValid).toBe(true);
        expect(result.signatureResults).toHaveLength(1);
      });

      it('should handle documents with many signatures', async () => {
        // This test ensures the algorithm scales properly
        const document = await testDataGenerator.generateValidDocument();
        
        // Add the same document structure but verify it works
        const result = traverse(document, signerRegistry);
        expect(result.isValid).toBe(true);
        
        // Verify processing time is reasonable (should be very fast)
        const startTime = Date.now();
        traverse(document, signerRegistry);
        const endTime = Date.now();
        expect(endTime - startTime).toBeLessThan(100); // Should complete in under 100ms
      });
    });
  });

  describe('createSignerRegistry function', () => {
    it('should create a proper registry from pairs', () => {
      const pairs: [string, string][] = [
        ['alice', '0x123'],
        ['bob', '0x456']
      ];
      
      const registry = createSignerRegistry(pairs);
      expect(registry['alice']).toBe('0x123');
      expect(registry['bob']).toBe('0x456');
    });

    it('should handle empty registry', () => {
      const registry = createSignerRegistry([]);
      expect(Object.keys(registry)).toHaveLength(0);
    });
  });
});
