/**
 * ThreatScorer manages threat scores per tab based on detected anomalies.
 */
class ThreatScorer {
    constructor() {
        this.tabState = new Map();
    }

    _initializeTab(tabId, url, hostname) {
        if (!this.tabState.has(tabId)) {
            this.tabState.set(tabId, {
                url,
                hostname,
                threatScore: 0,
                classification: self.AiTM_Constants.CLASSIFICATION.SAFE,
                anomalies: [],
                moduleScores: {
                    headers: 0,
                    urlStructure: 0,
                    domFingerprint: 0,
                    timing: 0,
                    domainReputation: 0
                },
                checkedAt: Date.now()
            });
        }
        return this.tabState.get(tabId);
    }

    addAnomaly(tabId, anomaly, url, hostname) {
        const state = this._initializeTab(tabId, url, hostname);
        const { SEVERITY_SCORES, MODULE_WEIGHTS, THRESHOLDS, CLASSIFICATION } = self.AiTM_Constants;
        
        state.anomalies.push(anomaly);

        // Add severity score to module
        const moduleScoreInc = SEVERITY_SCORES[anomaly.severity] || 0;
        state.moduleScores[anomaly.module] = Math.min(100, state.moduleScores[anomaly.module] + moduleScoreInc);

        // Recalculate overall score
        let totalWeightedScore = 0;
        for (const [mod, score] of Object.entries(state.moduleScores)) {
            const weight = MODULE_WEIGHTS[mod] || 0;
            totalWeightedScore += score * weight;
        }

        state.threatScore = Math.min(100, Math.round(totalWeightedScore));

        // Update classification
        if (state.threatScore >= THRESHOLDS.SUSPICIOUS_MAX) {
            state.classification = CLASSIFICATION.DANGEROUS;
        } else if (state.threatScore >= THRESHOLDS.SAFE_MAX) {
            state.classification = CLASSIFICATION.SUSPICIOUS;
        } else {
            state.classification = CLASSIFICATION.SAFE;
        }

        state.checkedAt = Date.now();
        return state;
    }

    getReport(tabId) {
        return this.tabState.get(tabId) || null;
    }

    clearTab(tabId) {
        this.tabState.delete(tabId);
    }

    clearAll() {
        this.tabState.clear();
    }
}

self.ThreatScorer = ThreatScorer;
