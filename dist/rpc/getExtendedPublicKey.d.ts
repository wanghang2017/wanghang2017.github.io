import { Network } from 'bitcoinjs-lib';
import { ScriptType, Snap } from '../interface';
export declare function getExtendedPublicKey(origin: string, snap: Snap, scriptType: ScriptType, network: Network): Promise<{
    xpub: string;
    mfp: string;
    address: string;
}>;
