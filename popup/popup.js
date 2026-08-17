// Utility: Convert SNAKE_CASE to Title Case
function snakeCaseToTitleCase(str) {
  return str.split('_').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
  ).join(' ');
}

// Utility: Relative time formatter
function relativeTime(timestamp) {
  if (!timestamp) return 'Just now';
  const diffInSeconds = Math.floor((Date.now() - timestamp) / 1000);
  
  if (diffInSeconds < 5) return 'Just now';
  if (diffInSeconds < 60) return `${diffInSeconds}s ago`;
  
  const diffInMinutes = Math.floor(diffInSeconds / 60);
  if (diffInMinutes < 60) return `${diffInMinutes}m ago`;
  
  const diffInHours = Math.floor(diffInMinutes / 60);
  if (diffInHours < 24) return `${diffInHours}h ago`;
  
  return 'Over a day ago';
}

// Constants
const MODULE_NAMES = {
  headers: 'HTTP Headers',
  urlStructure: 'URL Structure',
  domFingerprint: 'DOM Fingerprint',
  timing: 'Network Timing',
  domainReputation: 'Domain Reputation'
};

const COLORS = {
  SAFE: 'var(--color-safe)',
  SUSPICIOUS: 'var(--color-suspicious)',
  DANGEROUS: 'var(--color-dangerous)',
  CRITICAL: 'var(--color-critical)',
  LOW: 'var(--color-safe)',
  MEDIUM: 'var(--color-suspicious)',
  HIGH: 'var(--color-dangerous)'
};

// UI Update functions
function updateGauge(score, classification) {
  const gauge = document.getElementById('threat-gauge');
  const scoreEl = document.getElementById('threat-score');
  
  scoreEl.textContent = Math.round(score);
  
  // Calculate angle (0-360deg based on 0-100 score)
  const angle = (score / 100) * 360;
  gauge.style.setProperty('--gauge-angle', `${angle}deg`);
  
  let color = COLORS.SAFE;
  if (classification === 'SUSPICIOUS') color = COLORS.SUSPICIOUS;
  if (classification === 'DANGEROUS') color = COLORS.DANGEROUS;
  if (classification === 'CRITICAL') color = COLORS.CRITICAL; // Added CRITICAL just in case
  
  gauge.style.setProperty('--gauge-color', color);
}

function updateBanner(hostname, classification) {
  document.getElementById('hostname-display').textContent = hostname || 'Unknown Host';
  
  const badge = document.getElementById('classification-badge');
  badge.textContent = classification;
  badge.className = `badge ${classification.toLowerCase()}`;
}

function renderModules(moduleScores) {
  const container = document.getElementById('modules-container');
  container.innerHTML = '';
  
  const template = document.getElementById('module-row-template');
  
  for (const [key, score] of Object.entries(moduleScores)) {
    const clone = template.content.cloneNode(true);
    
    clone.querySelector('.module-name').textContent = MODULE_NAMES[key] || key;
    clone.querySelector('.module-score').textContent = `${Math.round(score)}%`;
    
    const fill = clone.querySelector('.module-bar-fill');
    fill.style.width = `${Math.min(100, Math.max(0, score))}%`;
    
    let color = COLORS.SAFE;
    if (score >= 40) color = COLORS.SUSPICIOUS;
    if (score >= 70) color = COLORS.DANGEROUS;
    if (score >= 90) color = COLORS.CRITICAL;
    
    fill.style.backgroundColor = color;
    
    container.appendChild(clone);
  }
}

function renderAnomalies(anomalies) {
  const list = document.getElementById('anomaly-list');
  const emptyState = document.getElementById('empty-state');
  const countBadge = document.getElementById('anomaly-count-badge');
  
  list.innerHTML = '';
  countBadge.textContent = anomalies ? anomalies.length : 0;
  
  if (!anomalies || anomalies.length === 0) {
    list.classList.add('hidden');
    emptyState.classList.remove('hidden');
    countBadge.className = 'badge safe';
    return;
  }
  
  list.classList.remove('hidden');
  emptyState.classList.add('hidden');
  countBadge.className = 'badge dangerous';
  
  const template = document.getElementById('anomaly-card-template');
  
  anomalies.sort((a, b) => b.timestamp - a.timestamp).forEach(anomaly => {
    const clone = template.content.cloneNode(true);
    const card = clone.querySelector('.anomaly-card');
    
    clone.querySelector('.anomaly-type').textContent = snakeCaseToTitleCase(anomaly.type);
    clone.querySelector('.anomaly-module').textContent = MODULE_NAMES[anomaly.module] || anomaly.module;
    clone.querySelector('.anomaly-detail').textContent = anomaly.detail;
    clone.querySelector('.anomaly-evidence').textContent = JSON.stringify(anomaly.evidence, null, 2);
    clone.querySelector('.anomaly-meta').textContent = relativeTime(anomaly.timestamp);
    
    const badge = clone.querySelector('.severity-badge');
    badge.textContent = anomaly.severity;
    badge.className = `badge severity-badge ${anomaly.severity.toLowerCase()}`;
    
    // Toggle expand
    card.addEventListener('click', () => {
      card.classList.toggle('expanded');
    });
    
    list.appendChild(clone);
  });
}

function updateLastChecked(timestamp) {
  document.getElementById('last-checked').textContent = `Last checked: ${relativeTime(timestamp)}`;
}

function render(data) {
  document.getElementById('loading-view').classList.add('hidden');
  document.getElementById('main-view').classList.remove('hidden');
  
  if (!data) {
    updateBanner('No active scan', 'SAFE');
    updateGauge(0, 'SAFE');
    renderModules({ headers: 0, urlStructure: 0, domFingerprint: 0, timing: 0, domainReputation: 0 });
    renderAnomalies([]);
    return;
  }
  
  updateBanner(data.hostname, data.classification);
  updateGauge(data.threatScore, data.classification);
  renderModules(data.moduleScores);
  renderAnomalies(data.anomalies);
  updateLastChecked(data.checkedAt);
}

// Data fetching
function fetchTabData() {
  if (chrome && chrome.tabs && chrome.runtime) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs.length > 0) {
        chrome.runtime.sendMessage({ type: 'GET_TAB_REPORT', tabId: tabs[0].id }, (response) => {
          render(response);
        });
      } else {
        render(null);
      }
    });
  } else {
    // Mock data for development when not in extension environment
    render({
      url: 'https://login.microsoftonline.com.proxy.badactor.com',
      hostname: 'login.microsoftonline.com.proxy.badactor.com',
      threatScore: 85,
      classification: 'DANGEROUS',
      anomalies: [
        {
          module: 'headers',
          type: 'PROXY_HEADER_LEAK',
          severity: 'CRITICAL',
          detail: 'Detected X-Forwarded-For and Via headers indicating a reverse proxy is intercepting the connection.',
          evidence: { 'X-Forwarded-For': '192.168.1.1', 'Via': '1.1 proxy' },
          timestamp: Date.now() - 5000
        },
        {
          module: 'domFingerprint',
          type: 'IDP_VISUAL_SPOOF',
          severity: 'HIGH',
          detail: 'DOM structure matches Microsoft login but domain does not match official list.',
          evidence: { title: 'Sign In to your account', formsCount: 1 },
          timestamp: Date.now() - 15000
        }
      ],
      moduleScores: {
        headers: 95,
        urlStructure: 80,
        domFingerprint: 90,
        timing: 40,
        domainReputation: 60
      },
      checkedAt: Date.now() - 2000
    });
  }
}

// Initialization
document.addEventListener('DOMContentLoaded', () => {
  // Add CSS property definition for the angle animation
  if (CSS.registerProperty) {
    try {
      CSS.registerProperty({
        name: '--gauge-angle',
        syntax: '<angle>',
        inherits: false,
        initialValue: '0deg',
      });
    } catch (e) {
      console.log('CSS.registerProperty not supported or already registered');
    }
  }
  
  fetchTabData();
  
  // Auto-refresh every 3 seconds
  const intervalId = setInterval(fetchTabData, 3000);
  
  // Cleanup
  window.addEventListener('unload', () => {
    clearInterval(intervalId);
  });
});
