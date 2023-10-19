import { Network } from 'bitcoinjs-lib';
import { Snap } from '../interface';
export declare function getSimpleAddress(origin: string, snap: Snap, network: Network): Promise<Record<string, string> | string>;
