import { BitcoinNetwork, ScriptType } from '../interface';
import { AccountSigner } from './accountSinger';
export declare class Transaction {
    private tx;
    private network;
    constructor(base64Psbt: string, network: BitcoinNetwork);
    validateTx(accountSigner: AccountSigner): boolean;
    extractPsbtJson(): {
        from: string;
        to: string;
        value: string;
        fee: string;
        network: string;
    } | {
        changeAddress: string;
        from: string;
        to: string;
        value: string;
        fee: string;
        network: string;
    };
    extractPsbtJsonString(): string;
    isDefinedSignType(signType: number): boolean;
    signTx(accountSigner: AccountSigner, signInputIndex: number, signType: number, scriptType: ScriptType): {
        finally: boolean;
        txId: string;
        txHex: string;
        psbt?: undefined;
    } | {
        finally: boolean;
        psbt: string;
        txId?: undefined;
        txHex?: undefined;
    };
}
