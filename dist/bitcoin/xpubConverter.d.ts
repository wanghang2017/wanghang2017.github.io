import { ScriptType } from "../interface";
import { Network } from 'bitcoinjs-lib';
export declare const convertXpub: (xpub: string, to: ScriptType, network: Network) => string;
