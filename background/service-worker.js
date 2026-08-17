importScripts('../shared/constants.js', '../content/idp-signatures.js', 'header-analyzer.js', 'threat-scorer.js');

console.log('[AiTM] Service Worker Initialized');

const scorer = new self.ThreatScorer();
const { MSG_TYPE, CLASSIFICATION } = self.AiTM_Constants;

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({
        tabReports: {},
        eventLog: [],
        settings: { enabled: true }
    });
});

function logEvent(anomaly, tabId, url, hostname) {
    chrome.storage.local.get(['eventLog'], (result) => {
        let eventLog = result.eventLog || [];
        eventLog.unshift({ tabId, url, hostname, anomaly, timestamp: Date.now() });
        if (eventLog.length > self.AiTM_Constants.MAX_EVENT_LOG) {
            eventLog = eventLog.slice(0, self.AiTM_Constants.MAX_EVENT_LOG);
        }
        chrome.storage.local.set({ eventLog });
    });
}

function updateBadge(tabId) {
    const report = scorer.getReport(tabId);
    if (!report) return;

    let text = '';
    let color = '#00FF00';

    if (report.classification === CLASSIFICATION.DANGEROUS) {
        text = '!!';
        color = '#FF0000';
    } else if (report.classification === CLASSIFICATION.SUSPICIOUS) {
        text = '!';
        color = '#FFA500';
    }

    chrome.action.setBadgeText({ text, tabId });
    chrome.action.setBadgeBackgroundColor({ color, tabId });
}

function persistTabReport(tabId) {
    const report = scorer.getReport(tabId);
    if (report) {
        chrome.storage.local.get(['tabReports'], (result) => {
            const tabReports = result.tabReports || {};
            tabReports[tabId] = report;
            chrome.storage.local.set({ tabReports });
        });
    }
}

chrome.webRequest.onHeadersReceived.addListener(
    (details) => {
        if (details.type !== 'main_frame' && details.type !== 'sub_frame') return;
        
        try {
            const urlObj = new URL(details.url);
            const anomalies = self.analyzeHeaders(details.responseHeaders, details.url, urlObj.hostname);
            
            anomalies.forEach(anomaly => {
                scorer.addAnomaly(details.tabId, anomaly, details.url, urlObj.hostname);
                logEvent(anomaly, details.tabId, details.url, urlObj.hostname);
            });

            if (anomalies.length > 0) {
                updateBadge(details.tabId);
                persistTabReport(details.tabId);
            }
        } catch (e) {
            console.error('[AiTM] Error analyzing headers:', e);
        }
    },
    { urls: ['<all_urls>'] },
    ['responseHeaders', 'extraHeaders']
);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === MSG_TYPE.ANOMALY_DETECTED && sender.tab) {
        console.log(`[AiTM] Anomaly received from tab ${sender.tab.id}:`, message.data);
        
        const urlObj = new URL(sender.tab.url);
        scorer.addAnomaly(sender.tab.id, message.data, sender.tab.url, urlObj.hostname);
        logEvent(message.data, sender.tab.id, sender.tab.url, urlObj.hostname);
        
        updateBadge(sender.tab.id);
        persistTabReport(sender.tab.id);
        sendResponse({ success: true });
    } else if (message.type === MSG_TYPE.GET_TAB_REPORT) {
        const report = scorer.getReport(message.tabId);
        sendResponse(report);
    }
    return true;
});

chrome.tabs.onRemoved.addListener((tabId) => {
    scorer.clearTab(tabId);
    chrome.storage.local.get(['tabReports'], (result) => {
        const tabReports = result.tabReports || {};
        delete tabReports[tabId];
        chrome.storage.local.set({ tabReports });
    });
});

chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId === 0) {
        scorer.clearTab(details.tabId);
        chrome.action.setBadgeText({ text: '', tabId: details.tabId });
    }
});
