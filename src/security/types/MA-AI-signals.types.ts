export interface MalwareSignals {
    status?: string;
    message?: string;
    verdict?: string;
    score?: number; 
    severity?: string;
    report?: string; 
  }
  
  export interface AiSignals {
    verdict?: string; 
    confidence?: number;
    summary?: string; 
    explanation?: string; 
    replySuggestions?: string[]; 
    isCampaign?: boolean; 
    campaignDescription?: string;
    behavioralAnomaly?: boolean;
    anomalyDescription?: string;
    recommendation?: string;
  }