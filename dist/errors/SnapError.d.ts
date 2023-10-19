export declare class SnapError extends Error {
    code: number;
    constructor(code: number);
    static of({ code, message }: {
        code: number;
        message: string;
    }): SnapError;
}
