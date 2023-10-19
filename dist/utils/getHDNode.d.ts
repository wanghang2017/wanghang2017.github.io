import * as bip32 from 'bip32';
import { Snap } from '../interface';
export declare const getHDNode: (snap: Snap, hdPath: string) => Promise<bip32.BIP32Interface>;
