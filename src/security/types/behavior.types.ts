export interface EmailHistory {
    subject: string;
    bodyText: string | null;
    isSpam: boolean;
    isPhishing: boolean;
    receivedAt: Date
}
export interface BehaviorSignals {
    behaviorScore: number;
    previousEmailCount: number;
    typicalTopic: string;
    anomalyFlag?: boolean;
    anomalyDescription?: string;
    history?: EmailHistory[] | null;
    unusualLanguage?: boolean;
    unusualSendingTime?: boolean;
    suddenSenderChange?: boolean;
}