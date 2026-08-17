(function() {
    console.log('[AiTM] Content script detector injected');
    const { MODULE, SEVERITY, MSG_TYPE, SUSPICIOUS_TLDS } = window.AiTM_Constants;
    const { IDP_SIGNATURES, AITM_TOOLKIT_SIGNATURES } = window.AiTM_Signatures;
    
    let anomaliesAccumulator = [];
    let debounceTimer = null;

    function sendAnomalies() {
        if (anomaliesAccumulator.length === 0) return;
        anomaliesAccumulator.forEach(anomaly => {
            try {
                chrome.runtime.sendMessage({
                    type: MSG_TYPE.ANOMALY_DETECTED,
                    data: anomaly
                }).catch(e => console.debug('[AiTM] Failed to send message (background might be idle)', e));
            } catch (e) {
                console.debug('[AiTM] Extension context invalidated', e);
            }
        });
        anomaliesAccumulator = [];
    }

    function queueAnomaly(module, type, severity, detail, evidence) {
        console.warn(`[AiTM] Anomaly detected [${severity}]: ${type} - ${detail}`);
        anomaliesAccumulator.push({
            module, type, severity, detail, evidence, timestamp: Date.now()
        });
        
        if (!debounceTimer) {
            debounceTimer = setTimeout(() => {
                sendAnomalies();
                debounceTimer = null;
            }, 500);
        }
    }

    const hostname = window.location.hostname;
    const url = window.location.href;
    
    // Check if we are directly on a legitimate IdP domain
    const isLegitIdP = IDP_SIGNATURES.some(sig => sig.domains.some(d => hostname === d || hostname.endsWith('.' + d)));
    
    if (isLegitIdP) {
        console.log('[AiTM] Verified legitimate IdP domain. Exiting checks.');
        return;
    }

    // Phase 1 - Immediate (URL Structure Analysis)
    function analyzeUrlStructure() {
        const tld = hostname.split('.').pop();
        if (SUSPICIOUS_TLDS.has(tld)) {
            queueAnomaly(MODULE.URL_STRUCTURE, 'SUSPICIOUS_TLD', SEVERITY.HIGH, `Suspicious TLD detected: .${tld}`, { tld });
        }

        IDP_SIGNATURES.forEach(sig => {
            sig.domains.forEach(d => {
                if (hostname.includes(d) && !hostname.endsWith(d)) {
                    queueAnomaly(MODULE.URL_STRUCTURE, 'IDP_EMBEDDED_IN_SUBDOMAIN', SEVERITY.CRITICAL, `Legitimate IdP domain embedded in subdomain`, { idpDomain: d, hostname });
                }
            });
        });

        AITM_TOOLKIT_SIGNATURES.forEach(toolkit => {
            if (toolkit.indicators.urlPatterns) {
                toolkit.indicators.urlPatterns.forEach(regex => {
                    if (regex.test(url)) {
                        queueAnomaly(MODULE.URL_STRUCTURE, 'AITM_URL_PATTERN', SEVERITY.CRITICAL, `URL matches known ${toolkit.name} toolkit pattern`, { toolkit: toolkit.name, url });
                    }
                });
            }
        });
    }

    analyzeUrlStructure();

    // Phase 2 - DOMContentLoaded
    function analyzeDOM() {
        const docText = document.body ? document.body.innerText || "" : "";
        const html = document.documentElement ? document.documentElement.innerHTML : "";
        
        let foundMarkers = [];
        let matchedIdp = null;

        IDP_SIGNATURES.forEach(sig => {
            const matches = sig.visualMarkers.filter(m => html.includes(m) || docText.includes(m));
            if (matches.length >= 2) {
                foundMarkers = matches;
                matchedIdp = sig.name;
            }
        });

        if (matchedIdp) {
            queueAnomaly(MODULE.DOM_FINGERPRINT, 'IDP_MARKERS_ON_UNTRUSTED_DOMAIN', SEVERITY.CRITICAL, `Found visual markers for ${matchedIdp} on untrusted domain`, { matchedIdp, foundMarkers });
        }

        const crossOriginResources = Array.from(document.querySelectorAll('script[src], link[href], img[src]'));
        crossOriginResources.forEach(el => {
            const src = el.src || el.href;
            if (!src) return;
            try {
                const srcUrl = new URL(src);
                if (matchedIdp) {
                    const idpInfo = IDP_SIGNATURES.find(s => s.name === matchedIdp);
                    const isIdpResource = idpInfo.domains.some(d => srcUrl.hostname.includes(d));
                    if (isIdpResource) {
                         queueAnomaly(MODULE.DOM_FINGERPRINT, 'AITM_BLEED_THROUGH', SEVERITY.HIGH, `Resource loaded directly from spoofed IdP domain`, { srcUrl: srcUrl.href, idp: matchedIdp });
                    }
                }
            } catch(e) {}
        });

        const scripts = document.querySelectorAll('script[src]');
        const loginLike = hostname.includes('login') || hostname.includes('auth');
        if (loginLike) {
            let hasExternalNoSri = false;
            scripts.forEach(s => {
                if (!s.integrity && s.src && !s.src.includes(window.location.hostname)) {
                    hasExternalNoSri = true;
                }
            });
            if (hasExternalNoSri) {
                queueAnomaly(MODULE.DOM_FINGERPRINT, 'STRIPPED_SRI', SEVERITY.MEDIUM, `External scripts on login-like page missing Subresource Integrity (SRI)`, {});
            }
        }

        AITM_TOOLKIT_SIGNATURES.forEach(toolkit => {
            if (toolkit.indicators.domPatterns) {
                toolkit.indicators.domPatterns.forEach(pattern => {
                    if (html.includes(pattern)) {
                         queueAnomaly(MODULE.DOM_FINGERPRINT, 'AITM_DOM_PATTERN', SEVERITY.HIGH, `Found DOM artifact matching ${toolkit.name}`, { toolkit: toolkit.name, pattern });
                    }
                });
            }
            if (toolkit.indicators.domInjections) {
                toolkit.indicators.domInjections.forEach(pattern => {
                    if (html.includes(pattern)) {
                         queueAnomaly(MODULE.DOM_FINGERPRINT, 'AITM_DOM_INJECTION', SEVERITY.CRITICAL, `Found script injection artifact matching ${toolkit.name}`, { toolkit: toolkit.name, pattern });
                    }
                });
            }
        });
    }

    document.addEventListener('DOMContentLoaded', () => {
        analyzeDOM();
        
        const observer = new MutationObserver((mutations) => {
            if (!debounceTimer) {
                debounceTimer = setTimeout(() => {
                    analyzeDOM();
                    sendAnomalies();
                    debounceTimer = null;
                }, 1000);
            }
        });
        if (document.body) {
            observer.observe(document.body, { childList: true, subtree: true });
        }
    });

    // Phase 3 - Load event
    window.addEventListener('load', () => {
        setTimeout(() => {
            const perfData = window.performance.getEntriesByType('navigation')[0];
            if (perfData) {
                const { TIMING_THRESHOLDS } = window.AiTM_Constants;
                const connectTime = perfData.connectEnd - perfData.connectStart;
                const ttfb = perfData.responseStart - perfData.requestStart;

                if (connectTime < TIMING_THRESHOLDS.MAX_CONNECT_MS && ttfb > TIMING_THRESHOLDS.MIN_TTFB_MS) {
                    queueAnomaly(MODULE.TIMING, 'SUSPICIOUS_TIMING', SEVERITY.MEDIUM, `Fast TCP connect but slow TTFB, indicating potential reverse proxy`, { connectTime, ttfb });
                }

                if (perfData.nextHopProtocol) {
                    const protocol = perfData.nextHopProtocol;
                    if (protocol === 'http/1.1' && (hostname.includes('login') || hostname.includes('microsoft') || hostname.includes('google'))) {
                         queueAnomaly(MODULE.TIMING, 'PROTOCOL_DOWNGRADE', SEVERITY.MEDIUM, `Expected h2/h3 but connection is http/1.1`, { protocol });
                    }
                }
            }
            sendAnomalies();
        }, 1000);
    });

})();
