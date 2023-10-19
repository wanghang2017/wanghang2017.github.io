import { Psbt } from 'bitcoinjs-lib';
import { BitcoinNetwork } from '../interface';
export declare class PsbtHelper {
    private tx;
    private network;
    constructor(psbt: Psbt, network: BitcoinNetwork);
    get inputAmount(): number;
    get sendAmount(): number;
    get fee(): number;
    get fromAddresses(): string[];
    get toAddresses(): string[];
    get changeAddresses(): string[];
}
