import { Snap } from '../interface';
import { RpcRequest } from '../index';
export declare const validateRequest: (snap: Snap, origin: string, request: RpcRequest['request']) => Promise<void>;
