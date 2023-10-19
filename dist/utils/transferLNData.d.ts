export declare const formatTime: (sec: number) => string;
export declare const transferInvoiceContent: (invoice: string) => {
    network: string;
    type: string;
    amount: string;
    expired_in: string;
    description: any;
};
