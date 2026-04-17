import { BehaviorSignals, ReputationSignals } from "src/security/types";

export const UNKNOWN_REPUTATION: ReputationSignals = {
    ipReputationScore: 0,
    isIpBlacklisted: false,
    ipCountry: 'unknown',
    isIpDatacenter: false,
    isIpTor: false,
    isIpProxy: false,
    domainReputationScore: 0,
    domainBlacklisted: false,
    domainAgeDays: 0,
    newlyRegisteredDomain: false,
    domainRegistrar: 'unknown',
    mxRecordsExist: false,
    whoisHidden: false,
};

export const DEFAULT_BEHAVIOR: BehaviorSignals = {
    behaviorScore: 0,
    history: null,
    previousEmailCount: 0,
    typicalTopic: 'unknown',
    anomalyFlag: false,
    anomalyDescription: '',
    unusualLanguage: false,
    unusualSendingTime: false,
    suddenSenderChange: false,
};
