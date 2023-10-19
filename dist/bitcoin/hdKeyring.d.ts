/// <reference types="node" />
import { BIP32Interface } from 'bip32';
import { Network } from 'bitcoinjs-lib';
import { ScriptType, Snap } from '../interface';
export declare const pathMap: Record<ScriptType, string[]>;
export declare const CRYPTO_CURVE = "secp256k1";
export declare const toXOnly: (pubKey: Buffer) => Buffer;
export declare function getHDRootNode(snap: Snap, network: Network, scriptType?: ScriptType): Promise<{
    node: BIP32Interface;
    mfp: string;
}>;
