/**
 * Analyzes HTTP headers for signs of AiTM proxy activity.
 * @param {chrome.webRequest.HttpHeader[]} responseHeaders 
 * @param {string} url 
 * @param {string} hostname 
 * @returns {Array} List of anomalies detected
 */
function analyzeHeaders(responseHeaders, url, hostname) {
    const anomalies = [];
    const headersMap = {};
    const { MODULE, SEVERITY } = self.AiTM_Constants;
    
    // Normalize headers
    responseHeaders.forEach(h => {
        headersMap[h.name.toLowerCase()] = h.value;
    });

    const isLoginLike = hostname.includes('login') || hostname.includes('account') || hostname.includes('auth') || hostname.includes('sso');
    
    // 1. Missing Security Headers on login-like pages
    if (isLoginLike) {
        if (!headersMap['content-security-policy']) {
            anomalies.push({
                module: MODULE.HEADERS,
                type: 'MISSING_CSP',
                severity: SEVERITY.MEDIUM,
                detail: 'Missing Content-Security-Policy on auth page',
                evidence: { url, hostname },
                timestamp: Date.now()
            });
        }
        if (!headersMap['strict-transport-security']) {
            anomalies.push({
                module: MODULE.HEADERS,
                type: 'MISSING_HSTS',
                severity: SEVERITY.HIGH,
                detail: 'Missing Strict-Transport-Security on auth page',
                evidence: { url, hostname },
                timestamp: Date.now()
            });
        }
    }

    // 2. Proxy Leak Headers
    self.AiTM_Constants.PROXY_HEADERS.forEach(proxyHeader => {
        if (headersMap[proxyHeader]) {
            anomalies.push({
                module: MODULE.HEADERS,
                type: 'PROXY_HEADER_LEAK',
                severity: SEVERITY.CRITICAL,
                detail: `Suspicious proxy header detected: ${proxyHeader}`,
                evidence: { header: proxyHeader, value: headersMap[proxyHeader] },
                timestamp: Date.now()
            });
        }
    });

    // 3. Server Header Mismatch & Cookie Domain Rewriting
    const matchedSignature = self.AiTM_Signatures.IDP_SIGNATURES.find(sig => 
        sig.domains.some(d => hostname.includes(d)) || 
        (isLoginLike && (hostname.includes('microsoft') || hostname.includes('google') || hostname.includes('okta')))
    );

    if (matchedSignature) {
        // Server mismatch
        const serverHeader = headersMap['server'];
        if (serverHeader && matchedSignature.expectedServers.length > 0) {
            const isExpected = matchedSignature.expectedServers.some(exp => serverHeader.includes(exp));
            if (!isExpected) {
                const isSuspiciousServer = ['nginx', 'openresty', 'caddy', 'apache', 'envoy'].some(s => serverHeader.toLowerCase().includes(s));
                
                anomalies.push({
                    module: MODULE.HEADERS,
                    type: 'SERVER_MISMATCH',
                    severity: isSuspiciousServer ? SEVERITY.HIGH : SEVERITY.MEDIUM,
                    detail: `Server header '${serverHeader}' does not match expected IdP infrastructure`,
                    evidence: { expected: matchedSignature.expectedServers, actual: serverHeader },
                    timestamp: Date.now()
                });
            }
        }

        // Cookie domain rewriting
        const setCookies = responseHeaders.filter(h => h.name.toLowerCase() === 'set-cookie');
        setCookies.forEach(cookie => {
            const domainMatch = cookie.value.match(/domain=([^;]+)/i);
            if (domainMatch) {
                const cookieDomain = domainMatch[1].trim().toLowerCase();
                const isExpectedCookie = matchedSignature.cookieDomains.some(d => cookieDomain.endsWith(d) || d.endsWith(cookieDomain));
                if (!isExpectedCookie && cookieDomain !== hostname && `.${cookieDomain}` !== hostname) {
                    anomalies.push({
                        module: MODULE.HEADERS,
                        type: 'COOKIE_DOMAIN_REWRITE',
                        severity: SEVERITY.CRITICAL,
                        detail: `Set-Cookie domain does not match expected IdP or current hostname`,
                        evidence: { cookieValue: cookie.value, expected: matchedSignature.cookieDomains },
                        timestamp: Date.now()
                    });
                }
            }
        });
    }

    return anomalies;
}

self.analyzeHeaders = analyzeHeaders;
