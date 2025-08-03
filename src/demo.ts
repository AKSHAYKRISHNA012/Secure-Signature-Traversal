/**
 * Demo script showing the Secure Signature Traversal module in action
 */

import { traverse } from './traversal';
import { testDataGenerator } from './test-data-generator';

/**
 * Prints verification results in a user-friendly format
 */
function printVerificationResult(result: any, title: string) {
  console.log(`\n🔍 ${title}`);
  console.log('=' .repeat(50));
  
  if (result.isValid) {
    console.log('✅ VALID - Document verification passed!');
  } else {
    console.log('❌ INVALID - Document verification failed!');
    console.log(`   Error: ${result.error}`);
  }
  
  console.log('\nSignature Details:');
  result.signatureResults.forEach((sig: any, index: number) => {
    const status = sig.isValid ? '✅' : '❌';
    console.log(`  ${index + 1}. ${status} ${sig.signerId}`);
    
    if (!sig.isValid && sig.error) {
      console.log(`     └─ Error: ${sig.error}`);
    } else if (sig.isValid) {
      console.log(`     └─ Hash Chain: ✅  Signature: ✅`);
    }
  });
}

/**
 * Main demo function
 */
async function runDemo() {
  console.log('🛡️  Secure Signature Traversal Demo');
  console.log('=====================================\n');
  
  console.log('Setting up test environment...');
  const signerRegistry = testDataGenerator.getSignerRegistry();
  
  console.log('📋 Signer Registry:');
  Object.entries(signerRegistry).forEach(([id, address]) => {
    console.log(`   ${id}: ${address}`);
  });

  try {
    // Demo 1: Valid Document
    console.log('\n🔷 Generating valid 3-signature document...');
    const validDocument = await testDataGenerator.generateValidDocument();
    
    console.log('📄 Document Structure:');
    console.log(`   Document ID: ${validDocument.payload.documentId}`);
    console.log(`   Content: "${validDocument.payload.content.substring(0, 50)}..."`);
    console.log(`   Signatures: ${validDocument.signatures.length}`);
    
    const validResult = traverse(validDocument, signerRegistry);
    printVerificationResult(validResult, 'Verifying Valid Document');

    // Demo 2: Tampered Payload
    console.log('\n🔷 Testing tampered document...');
    const tamperedDocument = await testDataGenerator.generateDocumentWithTamperedPayload();
    const tamperedResult = traverse(tamperedDocument, signerRegistry);
    printVerificationResult(tamperedResult, 'Verifying Tampered Document');

    // Demo 3: Invalid Signature
    console.log('\n🔷 Testing document with corrupted signature...');
    const invalidSigDocument = await testDataGenerator.generateDocumentWithInvalidSignature();
    const invalidSigResult = traverse(invalidSigDocument, signerRegistry);
    printVerificationResult(invalidSigResult, 'Verifying Document with Invalid Signature');

    // Demo 4: Broken Hash Chain
    console.log('\n🔷 Testing document with broken hash chain...');
    const brokenChainDocument = await testDataGenerator.generateDocumentWithBrokenHashChain();
    const brokenChainResult = traverse(brokenChainDocument, signerRegistry);
    printVerificationResult(brokenChainResult, 'Verifying Document with Broken Hash Chain');

    // Demo 5: Performance Test
    console.log('\n🔷 Performance test...');
    const startTime = Date.now();
    for (let i = 0; i < 100; i++) {
      traverse(validDocument, signerRegistry);
    }
    const endTime = Date.now();
    console.log(`✅ Verified 100 documents in ${endTime - startTime}ms (avg: ${(endTime - startTime) / 100}ms per document)`);

  } catch (error) {
    console.error('❌ Demo failed:', error);
  }

  console.log('\n🎉 Demo completed!');
  console.log('\nKey Takeaways:');
  console.log('• ✅ Valid documents pass all checks');
  console.log('• 🚫 Any tampering is immediately detected');
  console.log('• 🔗 Hash chain ensures document integrity');
  console.log('• 🔐 Cryptographic signatures prove authenticity');
  console.log('• ⚡ Fast verification suitable for production use');
}

// Run the demo if this file is executed directly
if (require.main === module) {
  runDemo().catch(console.error);
}

export { runDemo };
