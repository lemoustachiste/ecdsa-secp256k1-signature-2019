import { EcdsaSecp256k1VerificationKey2019 } from '@bloomprotocol/ecdsa-secp256k1-verification-key-2019';
import jsigs from 'jsonld-signatures';
declare type EcdsaSecp256k1Signature2019Options = {
    key?: EcdsaSecp256k1VerificationKey2019;
    signer?: {
        sign: Function;
        id: string;
    };
    verifier?: {
        verify: Function;
        id: string;
    };
    proof?: Record<string, unknown>;
    date?: Date | string;
    useNativeCanonize?: boolean;
};
export declare class EcdsaSecp256k1Signature2019 extends jsigs.suites.LinkedDataSignature {
    private requiredKeyType;
    constructor(options?: EcdsaSecp256k1Signature2019Options);
    sign({ verifyData, proof }: {
        verifyData: Uint8Array;
        proof: Record<string, any>;
    }): Promise<{
        jws: any;
    }>;
    verifySignature({ verifyData, verificationMethod, proof, }: {
        verifyData: Uint8Array;
        verificationMethod: Record<string, unknown>;
        proof: Record<string, unknown>;
    }): Promise<any>;
    assertVerificationMethod({ verificationMethod }: {
        verificationMethod: Record<string, unknown>;
    }): Promise<void>;
    getVerificationMethod({ proof, documentLoader, }: {
        proof: {
            verificationMethod: string | {
                id: string;
            } | undefined;
        };
        documentLoader: Function;
    }): Promise<any>;
    matchProof({ proof, document, purpose, documentLoader, expansionMap, }: {
        proof: Record<string, any>;
        document: Record<string, any>;
        purpose: Record<string, any>;
        documentLoader: Function;
        expansionMap: Function;
    }): Promise<boolean>;
    ensureSuiteContext({ document, addSuiteContext }: {
        document: Record<string, unknown>;
        addSuiteContext?: boolean;
    }): void;
}
export {};
