export interface HdPath {
    purpose: string | null;
    coinType: string | null;
    account: string | null;
    change: string | null;
    index: string | null;
}
export interface LightningPath {
    purpose: {
        value: string;
        isHardened: boolean;
    };
    coinType: {
        value: string;
        isHardened: boolean;
    };
    account: {
        value: string;
        isHardened: boolean;
    };
    change: {
        value: string;
        isHardened: boolean;
    };
    index: {
        value: string;
        isHardened: boolean;
    };
}
export declare const fromHdPathToObj: (hdPath: string) => HdPath;
export declare const parseLightningPath: (hdPath: string) => LightningPath;
