const AiTM_Signatures = {
    IDP_SIGNATURES: [
        {
            name: 'Microsoft Entra / Office 365',
            domains: ['login.microsoftonline.com', 'login.microsoft.com', 'login.live.com', 'sts.windows.net', 'aadcdn.msftauth.net', 'aadcdn.msauth.net'],
            expectedServers: ['Microsoft-IIS', 'Microsoft-HTTPAPI'],
            visualMarkers: ['Sign in to your account', 'Microsoft', 'Enter password', 'Stay signed in?', 'msft-account'],
            cookieDomains: ['.login.microsoftonline.com', '.microsoft.com', '.live.com'],
            expectedProtocol: 'h2'
        },
        {
            name: 'Google Workspace',
            domains: ['accounts.google.com', 'myaccount.google.com', 'gds.google.com'],
            expectedServers: ['ESF', 'GSE', 'gws'],
            visualMarkers: ['Sign in', 'Google', 'Use your Google Account', 'Enter your password', 'g-raised'],
            cookieDomains: ['.google.com', '.accounts.google.com'],
            expectedProtocol: 'h2'
        },
        {
            name: 'Okta',
            domains: ['okta.com', 'oktapreview.com', 'okta-emea.com'],
            expectedServers: [],
            visualMarkers: ['Sign In', 'Okta', 'Username', 'Password', 'okta-sign-in'],
            cookieDomains: ['.okta.com'],
            expectedProtocol: 'h2'
        },
        {
            name: 'GitHub',
            domains: ['github.com'],
            expectedServers: ['GitHub.com'],
            visualMarkers: ['Sign in to GitHub', 'Username or email address', 'auth-form'],
            cookieDomains: ['.github.com'],
            expectedProtocol: 'h2'
        }
    ],
    AITM_TOOLKIT_SIGNATURES: [
        { name: 'Evilginx', indicators: { urlPatterns: [/\/auth\/v2\/token/i, /[?&]key=[a-zA-Z0-9]{8,}/i, /[?&]lure=[a-zA-Z0-9]/i], domPatterns: ['o365', 'outlook', 'microsoftonline'], stripsSRI: true } },
        { name: 'Modlishka', indicators: { urlPatterns: [/[?&]ident=[a-zA-Z0-9]/i, /[?&]tracking=[a-zA-Z0-9]/i], headerArtifacts: ['Go-http-client'] } },
        { name: 'Muraena', indicators: { domInjections: ['necrobrowser', 'muraena'], stripsCSP: true, stripsXFO: true } }
    ]
};

if (typeof window !== 'undefined') {
    window.AiTM_Signatures = AiTM_Signatures;
} else if (typeof self !== 'undefined') {
    self.AiTM_Signatures = AiTM_Signatures;
}
