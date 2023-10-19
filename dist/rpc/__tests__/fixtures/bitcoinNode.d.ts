import { SLIP10Node } from "interface";
export declare const bip44AccountNode: SLIP10Node;
export declare const bip44: {
    slip10Node: SLIP10Node;
    xpub: string;
};
export declare const LNDataFromSnap: {
    lightning: {
        id00000001: {
            credential: string;
            password: string;
        };
    };
};
export declare const LNDataToSnap: {
    domain: string;
    walletId: string;
    credential: string;
    password: string;
    invoice: string;
};
export declare const LNSignature: {
    signature: string;
};
