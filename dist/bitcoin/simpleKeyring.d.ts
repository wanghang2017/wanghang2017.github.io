import { Network } from 'bitcoinjs-lib';
import { ScriptType } from 'interface';
export declare function privateKeyToWIF(privateKeyHex: string): string;
export declare function getAddress(network: Network, publicKey: string, scriptType?: ScriptType): string | Record<string, string>;
