import { BitcoinNetwork, Snap } from '../interface';
export declare function manageNetwork(origin: string, snap: Snap, action: 'get' | 'set', target?: BitcoinNetwork): Promise<string | void>;
