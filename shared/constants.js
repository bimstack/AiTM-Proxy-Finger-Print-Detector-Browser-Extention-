const AiTM_Constants = {
    SEVERITY: { CRITICAL: 'CRITICAL', HIGH: 'HIGH', MEDIUM: 'MEDIUM', LOW: 'LOW' },
    CLASSIFICATION: { SAFE: 'SAFE', SUSPICIOUS: 'SUSPICIOUS', DANGEROUS: 'DANGEROUS' },
    MODULE: { HEADERS: 'headers', URL_STRUCTURE: 'urlStructure', DOM_FINGERPRINT: 'domFingerprint', TIMING: 'timing', DOMAIN_REPUTATION: 'domainReputation' },
    MSG_TYPE: { ANOMALY_DETECTED: 'ANOMALY_DETECTED', GET_TAB_REPORT: 'GET_TAB_REPORT' },
    THRESHOLDS: { SAFE_MAX: 25, SUSPICIOUS_MAX: 60 },
    MODULE_WEIGHTS: { headers: 0.25, urlStructure: 0.25, domFingerprint: 0.25, timing: 0.15, domainReputation: 0.10 },
    SUSPICIOUS_TLDS: new Set(['xyz', 'top', 'click', 'live', 'cfd', 'rest', 'buzz', 'surf', 'icu', 'cyou', 'sbs', 'hair', 'mom']),
    PROXY_HEADERS: ['via', 'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip', 'x-proxy-id', 'forwarded'],
    TIMING_THRESHOLDS: { MAX_CONNECT_MS: 25, MIN_TTFB_MS: 400 },
    MAX_EVENT_LOG: 500,
    SEVERITY_SCORES: { CRITICAL: 40, HIGH: 25, MEDIUM: 15, LOW: 8 }
};

if (typeof window !== 'undefined') {
    window.AiTM_Constants = AiTM_Constants;
} else if (typeof self !== 'undefined') {
    self.AiTM_Constants = AiTM_Constants;
}
