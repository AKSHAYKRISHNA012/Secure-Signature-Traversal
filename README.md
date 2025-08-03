# Secure Signature Traversal

A TypeScript module for verifying multi-signature documents using cryptographic hash chains. This module ensures both data integrity and signature authenticity throughout a multi-step signing process.

## 🔐 What It Does

When documents are signed by multiple parties in sequence, this module verifies:

1. **Cryptographic Authenticity** - Each signature was created by the claimed signer
2. **Data Integrity** - The document hasn't been tampered with at any step
3. **Chain Integrity** - The complete signing sequence is valid from start to finish

## 🏗️ How It Works

The module implements a "hash chain" approach:

1. **First Signer (Alice)**: Signs `hash(document)`
2. **Second Signer (Bob)**: Signs `hash(document + Alice's signature)`
3. **Third Signer (Charlie)**: Signs `hash(document + Bob's signature)`

To verify, the module works **backwards** from the last signature to the first, ensuring each link in the chain is valid.

## 🚀 Installation

```bash
# Clone the repository
git clone <repository-url>
cd secure-signature-traversal

# Install dependencies
npm install

# Build the project
npm run build
```

## 📋 Requirements

- Node.js 16+
- TypeScript 5+
- ethers.js 6+

## 🧪 Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch
```

## 💻 Usage

### Basic Example

```typescript
import { traverse, createSignerRegistry, testDataGenerator } from './src';

// Generate test data
const document = await testDataGenerator.generateValidDocument();
const signerRegistry = testDataGenerator.getSignerRegistry();

// Verify the document
const result = traverse(document, signerRegistry);

if (result.isValid) {
  console.log('✅ Document is valid!');
} else {
  console.log('❌ Document verification failed:', result.error);
}
```

### Document Structure

```typescript
interface SignedDocument {
  payload: {
    documentId: string;
    content: string;
    // ... other properties
  };
  signatures: [
    {
      signerId: "developer-alice",
      signature: "0x...", // Cryptographic signature
      signedAt: "2025-07-28T10:00:00Z",
      signedHash: "0x..." // Hash that was signed
    },
    // ... more signatures
  ];
}
```

### Creating a Signer Registry

```typescript
import { createSignerRegistry } from './src';

const registry = createSignerRegistry([
  ['developer-alice', '0x742d35Cc6...'], // [signerId, publicAddress]
  ['qa-bob', '0x8ba1f109e...'],
  ['manager-charlie', '0x1234567890...']
]);
```

## 🧬 API Reference

### `traverse(document, signerRegistry)`

Main verification function that validates a complete signature chain.

**Parameters:**
- `document: SignedDocument` - The document to verify
- `signerRegistry: SignerRegistry` - Mapping of signer IDs to public addresses

**Returns:**
- `VerificationResult` - Detailed verification results

### `VerificationResult`

```typescript
interface VerificationResult {
  isValid: boolean;                    // Overall validity
  error?: string;                      // Error message if invalid
  signatureResults: SignatureVerificationResult[]; // Per-signature details
}
```

### Test Data Generation

```typescript
import { testDataGenerator } from './src';

// Generate valid document
const validDoc = await testDataGenerator.generateValidDocument();

// Generate documents with specific issues for testing
const tamperedDoc = await testDataGenerator.generateDocumentWithTamperedPayload();
const invalidSigDoc = await testDataGenerator.generateDocumentWithInvalidSignature();
const brokenChainDoc = await testDataGenerator.generateDocumentWithBrokenHashChain();
```

## 🎯 Key Features

### ✅ **Comprehensive Verification**
- Cryptographic signature validation
- Hash chain integrity checking  
- Timestamp validation
- Signer registry verification

### ✅ **Attack Detection**
- Detects document tampering
- Identifies forged signatures
- Catches broken hash chains
- Validates signer authenticity

### ✅ **Robust Error Handling**
- Detailed error messages
- Per-signature validation results
- Graceful handling of edge cases

### ✅ **High Test Coverage**
- 90%+ code coverage
- Comprehensive test suite
- Edge case validation
- Performance testing

## 🔍 Testing Strategy

The module includes extensive tests covering:

- **Happy Path**: Valid multi-signature documents
- **Tampering Detection**: Modified payloads, signatures, and hash chains
- **Edge Cases**: Single signatures, empty documents, invalid registries
- **Performance**: Scalability with multiple signatures

## 🛡️ Security Considerations

- Uses industry-standard **ethers.js** for cryptographic operations
- Implements **deterministic serialization** to prevent hash collisions
- **Case-insensitive address comparison** for Ethereum addresses
- **Graceful error handling** prevents information leakage

## 📊 Performance

- **Fast verification**: Typical 3-signature document verified in <10ms
- **Memory efficient**: Minimal memory footprint
- **Scalable**: Linear complexity O(n) for n signatures

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and add tests
4. Ensure all tests pass: `npm test`
5. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details

## 🎬 Demo

Run the following to see a live demonstration:

```bash
# Generate and verify test documents
npm run dev

# This will show:
# - Creating valid documents
# - Verification process
# - Detection of various tampering attempts
```

---

**Built with ❤️ for secure document workflows**
