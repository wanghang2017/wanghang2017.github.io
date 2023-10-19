import { Snap } from '../interface';
export declare function getAllXpubs(origin: string, snap: Snap): Promise<{
    xpubs: string[];
    accounts: {};
    mfp: string;
}>;
