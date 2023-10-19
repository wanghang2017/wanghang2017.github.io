import { PersistedData, Snap } from '../interface';
export declare const getPersistedData: <T>(snap: Snap, key: keyof PersistedData, defaultValue: T) => Promise<T>;
export declare const updatePersistedData: (snap: Snap, key: keyof PersistedData, value: any) => Promise<void>;
