import { EcdsaSecp256k1VerificationKey2019 } from '@bloomprotocol/ecdsa-secp256k1-verification-key-2019';
import jsonld from 'jsonld';
import jsigs from 'jsonld-signatures';

const context = {
  '@context': {
    id: '@id',
    type: '@type',
    '@protected': true,
    proof: {
      '@id': 'https://w3id.org/security#proof',
      '@type': '@id',
      '@container': '@graph'
    },
    EcdsaSecp256k1VerificationKey2019: {
      '@id': 'https://w3id.org/security#EcdsaSecp256k1VerificationKey2019',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        controller: {
          '@id': 'https://w3id.org/security#controller',
          '@type': '@id'
        },
        revoked: {
          '@id': 'https://w3id.org/security#revoked',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        },
        blockchainAccountId: {
          '@id': 'https://w3id.org/security#blockchainAccountId'
        },
        publicKeyJwk: {
          '@id': 'https://w3id.org/security#publicKeyJwk',
          '@type': '@json'
        },
        publicKeyBase58: {
          '@id': 'https://w3id.org/security#publicKeyBase58'
        },
        publicKeyMultibase: {
          '@id': 'https://w3id.org/security#publicKeyMultibase',
          '@type': 'https://w3id.org/security#multibase'
        }
      }
    },
    EcdsaSecp256k1Signature2019: {
      '@id': 'https://w3id.org/security#EcdsaSecp256k1Signature2019',
      '@context': {
        '@protected': true,
        id: '@id',
        type: '@type',
        challenge: 'https://w3id.org/security#challenge',
        created: {
          '@id': 'http://purl.org/dc/terms/created',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        },
        domain: 'https://w3id.org/security#domain',
        expires: {
          '@id': 'https://w3id.org/security#expiration',
          '@type': 'http://www.w3.org/2001/XMLSchema#dateTime'
        },
        nonce: 'https://w3id.org/security#nonce',
        proofPurpose: {
          '@id': 'https://w3id.org/security#proofPurpose',
          '@type': '@vocab',
          '@context': {
            '@protected': true,
            id: '@id',
            type: '@type',
            assertionMethod: {
              '@id': 'https://w3id.org/security#assertionMethod',
              '@type': '@id',
              '@container': '@set'
            },
            authentication: {
              '@id': 'https://w3id.org/security#authenticationMethod',
              '@type': '@id',
              '@container': '@set'
            },
            capabilityInvocation: {
              '@id': 'https://w3id.org/security#capabilityInvocationMethod',
              '@type': '@id',
              '@container': '@set'
            },
            capabilityDelegation: {
              '@id': 'https://w3id.org/security#capabilityDelegationMethod',
              '@type': '@id',
              '@container': '@set'
            },
            keyAgreement: {
              '@id': 'https://w3id.org/security#keyAgreementMethod',
              '@type': '@id',
              '@container': '@set'
            }
          }
        },
        jws: {
          '@id': 'https://w3id.org/security#jws'
        },
        verificationMethod: {
          '@id': 'https://w3id.org/security#verificationMethod',
          '@type': '@id'
        }
      }
    }
  }
};

// @ts-nocheck
const SUITE_CONTEXT_URL = 'https://ns.did.ai/suites/secp256k1-2019/v1';

const includesContext = ({
  document,
  contextUrl
}) => {
  const context = document['@context'];
  return context === contextUrl || Array.isArray(context) && context.includes(contextUrl);
};

const includesCompatibleContext = ({
  document
}) => {
  const credContext = 'https://www.w3.org/2018/credentials/v1';
  const securityContext = 'https://w3id.org/security/v2';
  const hasSecp256k12019 = includesContext({
    document,
    contextUrl: SUITE_CONTEXT_URL
  });
  const hasCred = includesContext({
    document,
    contextUrl: credContext
  });
  const hasSecV2 = includesContext({
    document,
    contextUrl: securityContext
  });

  if (hasSecp256k12019 && hasCred) {
    // eslint-disable-next-line no-console
    console.warn('Warning: The secp256k1-2019/v1 and credentials/v1 contexts are incompatible.'); // eslint-disable-next-line no-console

    console.warn('For VCs using EcdsaSecp256k1Signature2019 suite, using the credentials/v1 context is sufficient.');
    return false;
  }

  if (hasSecp256k12019 && hasSecV2) {
    // eslint-disable-next-line no-console
    console.warn('Warning: The secp256k1-2019/v1 and security/v2 contexts are incompatible.'); // eslint-disable-next-line no-console

    console.warn('For VCs using EcdsaSecp256k1Signature2019 suite, using the security/v2 context is sufficient.');
    return false;
  }

  return hasSecp256k12019 || hasCred || hasSecV2;
};

class EcdsaSecp256k1Signature2019 extends jsigs.suites.LinkedDataSignature {
  constructor(options = {}) {
    super({
      type: 'EcdsaSecp256k1Signature2019',
      LDKeyClass: EcdsaSecp256k1VerificationKey2019,
      contextUrl: SUITE_CONTEXT_URL,
      ...options
    });
    this.requiredKeyType = void 0;
    this.requiredKeyType = 'EcdsaSecp256k1VerificationKey2019';
  }

  async sign({
    verifyData,
    proof
  }) {
    if (!(this.signer && typeof this.signer.sign === 'function')) {
      throw new Error('A signer API has not been specified.');
    }

    const jws = await this.signer.sign({
      data: verifyData
    });
    return { ...proof,
      jws
    };
  }

  async verifySignature({
    verifyData,
    verificationMethod,
    proof
  }) {
    const {
      jws
    } = proof;

    if (!(jws && typeof jws === 'string')) {
      throw new TypeError('The proof does not include a valid "jws" property.');
    }

    let {
      verifier
    } = this;

    if (!verifier) {
      const key = await this.LDKeyClass.from(verificationMethod);
      verifier = key.verifier();
    }

    return verifier.verify({
      data: verifyData,
      signature: jws
    });
  }

  async assertVerificationMethod({
    verificationMethod
  }) {
    if (!includesCompatibleContext({
      document: verificationMethod
    })) {
      throw new TypeError(`The verification method (key) must contain "${this.contextUrl}".`);
    }

    if (!jsonld.hasValue(verificationMethod, 'type', this.requiredKeyType)) {
      throw new Error(`Invalid key type. Key type must be "${this.requiredKeyType}".`);
    }

    if (verificationMethod.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }
  }

  async getVerificationMethod({
    proof,
    documentLoader
  }) {
    if (this.key) {
      return this.key.export({
        publicKey: true
      });
    }

    const verificationMethod = typeof proof.verificationMethod === 'object' ? proof.verificationMethod.id : proof.verificationMethod;

    if (!verificationMethod) {
      throw new Error('No "verificationMethod" found in proof.');
    }

    const framed = await jsonld.frame(verificationMethod, {
      '@context': this.contextUrl,
      '@embed': '@always',
      id: verificationMethod
    }, {
      documentLoader,
      compactToRelative: false
    });

    if (!framed) {
      throw new Error(`Verification method ${verificationMethod} not found.`);
    }

    if (framed.revoked !== undefined) {
      throw new Error('The verification method has been revoked.');
    }

    await this.assertVerificationMethod({
      verificationMethod: framed
    });
    return framed;
  }

  async matchProof({
    proof,
    document,
    purpose,
    documentLoader,
    expansionMap
  }) {
    if (!includesCompatibleContext({
      document
    })) {
      return false;
    }

    if (!(await super.matchProof({
      proof,
      document,
      purpose,
      documentLoader,
      expansionMap
    }))) {
      return false;
    }

    if (!this.key) {
      // no key specified, so assume this suite matches and it can be retrieved
      return true;
    }

    const {
      verificationMethod
    } = proof;

    if (typeof verificationMethod === 'object') {
      return verificationMethod.id === this.key.id;
    }

    return verificationMethod === this.key.id;
  }

  ensureSuiteContext({
    document,
    addSuiteContext
  }) {
    if (includesCompatibleContext({
      document
    })) {
      return;
    }

    super.ensureSuiteContext({
      document,
      addSuiteContext
    });
  }

}
EcdsaSecp256k1Signature2019.CONTEXT_URL = SUITE_CONTEXT_URL;
EcdsaSecp256k1Signature2019.CONTEXT = context;

export { EcdsaSecp256k1Signature2019 };
//# sourceMappingURL=ecdsa-secp256k1-signature-2019.esm.js.map
