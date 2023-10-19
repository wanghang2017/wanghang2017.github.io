/// <reference types="jest" />
import { Snap } from "../../interface";
declare type RpcStubs = "snap_getBip32Entropy" | "snap_manageState" | "snap_dialog";
export declare class SnapMock implements Snap {
    readonly registerRpcMessageHandler: jest.Mock<any, any>;
    readonly requestStub: jest.Mock<any, any>;
    readonly rpcStubs: Record<RpcStubs, jest.Mock>;
    request<T>(options: {
        method: RpcStubs;
        params: unknown[];
    }): Promise<T>;
    reset(): void;
}
export {};
