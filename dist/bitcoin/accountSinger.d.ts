/// <reference types="node" />
import { BIP32Interface } from 'bip32';
import { Signer, HDSigner } from 'bitcoinjs-lib';
export declare class AccountSigner implements Signer, HDSigner {
    publicKey: Buffer;
    fingerprint: Buffer;
    private readonly node;
    private readonly keyPair;
    constructor(accountNode: BIP32Interface, mfp?: Buffer);
    getTapRootSinger(path?: string): import("bip32/types/bip32").Signer;
    derivePath(path: string): AccountSigner;
    sign(hash: Buffer): Buffer;
    signSchnorr(hash: Buffer): Buffer;
}
export declare const validator: (pubkey: Buffer, msghash: Buffer, signature: Buffer) => boolean;
export declare const schnorrValidator: (pubkey: Buffer, msghash: Buffer, signature: Buffer) => boolean;
