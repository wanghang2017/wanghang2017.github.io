import { Psbt } from 'bitcoinjs-lib';
import { AccountSigner } from './index';
import { BitcoinNetwork } from '../interface';
export declare class PsbtValidator {
    static FEE_THRESHOLD: number;
    private readonly tx;
    private readonly snapNetwork;
    private psbtHelper;
    private error;
    constructor(psbt: Psbt, network: BitcoinNetwork);
    get coinType(): 0 | 1;
    allInputsHaveRawTxHex(): boolean;
    everyInputMatchesNetwork(): boolean;
    everyOutputMatchesNetwork(): boolean;
    allInputsBelongToCurrentAccount(accountSigner: AccountSigner): boolean;
    someInputsBelongToCurrentAccount(accountSigner: AccountSigner): boolean;
    changeAddressBelongsToCurrentAccount(accountSigner: AccountSigner): boolean;
    feeUnderThreshold(): boolean;
    witnessUtxoValueMatchesNoneWitnessOnes(): boolean;
    validate(accountSigner: AccountSigner): boolean;
}
