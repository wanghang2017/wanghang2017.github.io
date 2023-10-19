import { Snap, KeyOptions } from '../interface';
interface GetLNDataFromSnap {
    key: KeyOptions;
    walletId?: string;
    type?: 'get' | 'refresh';
}
export declare function getLNDataFromSnap(domain: string, snap: Snap, { key, walletId, type, }: GetLNDataFromSnap): Promise<string>;
export {};
