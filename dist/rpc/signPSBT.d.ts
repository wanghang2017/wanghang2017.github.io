import { BitcoinNetwork, ScriptType, Snap } from '../interface';
interface ISignResult {
    finally: boolean;
    txId?: string;
    txHex?: string;
    psbt?: string;
}
export declare function signPsbt(domain: string, snap: Snap, psbt: string, network: BitcoinNetwork, scriptType: ScriptType, signInputIndex: number, signType: number): Promise<ISignResult>;
export {};
