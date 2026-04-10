export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown' | 'permerror' | 'temperror';

export interface SpfResult {
    status: AuthStatus;
    domain?: string;
    ip?: string;
    reason?: string;
}

export interface DkimResult {
    status: AuthStatus;
    domain?: string;
    selector?: string;
    reason?: string;
}

export interface DmarcResult {
    status: AuthStatus;
    policy?: string; 
    domain?: string;
    reason?: string;
}

export interface ArcResult {
    status: AuthStatus;
    chain?: string;
}

export interface AuthSignals {
    spf: SpfResult;
    dkim: DkimResult;
    dmarc: DmarcResult;
    arc: ArcResult;
    hasAuthFailure: boolean;
    failureSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
    summary: string;
}