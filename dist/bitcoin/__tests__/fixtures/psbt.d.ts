/// <reference types="node" />
export declare const transaction: {
    from: string;
    to: string;
    value: number;
    network: string;
    fee: number;
    changeAddress: string;
};
export declare const psbtFixture: {
    tx: {
        inputs: {
            hash: Buffer;
            index: number;
            sequence: number;
        }[];
        outputs: {
            script: Buffer;
            value: number;
            address: string;
        }[];
    };
    data: {
        inputs: {
            nonWitnessUtxo: Buffer;
            witnessUtxo: {
                script: Buffer;
                value: number;
            };
            bip32Derivation: {
                masterFingerprint: Buffer;
                pubkey: Buffer;
                path: string;
            }[];
        }[];
        outputs: ({
            bip32Derivation?: undefined;
        } | {
            bip32Derivation: {
                masterFingerprint: Buffer;
                pubkey: Buffer;
                path: string;
            }[];
        })[];
    };
    base64: string;
};
