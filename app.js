/**
 * CyberGuard - Single-Box URL Threat Scanner Controller
 * Developed for Sakshi Singh • B.Tech CSE (Data Science) 3rd Year
 */

document.addEventListener('DOMContentLoaded', () => {
  const form = document.getElementById('urlScanForm');
  const urlInput = document.getElementById('urlInput');
  const clearBtn = document.getElementById('clearBtn');
  const resultContainer = document.getElementById('resultContainer');
  const sampleChips = document.querySelectorAll('.sample-chip');

  function analyzeAndShow(rawUrl) {
    if (!rawUrl || !rawUrl.trim()) return;
    const cleanUrl = rawUrl.trim();
    urlInput.value = cleanUrl;

    // Run threat engine
    const analysis = URLThreatDetector.analyze(cleanUrl);

    if (!analysis || !analysis.valid) {
      resultContainer.innerHTML = `
        <div class="result-card verdict-card-danger">
          <div class="verdict-banner">
            <span class="verdict-icon">⚠️</span>
            <div>
              <h3 class="verdict-title">Invalid URL Format</h3>
              <p class="verdict-desc">Please enter a valid website link or domain name (e.g., https://example.com or http://login-verify.top).</p>
            </div>
          </div>
        </div>
      `;
      resultContainer.style.display = 'block';
      return;
    }

    const s = analysis.stats;
    const c = analysis.components;

    const isSafe = s.score < 30;
    const isSuspicious = s.score >= 30 && s.score < 60;
    const isDanger = s.score >= 60;

    let cardClass = 'verdict-card-safe';
    let bannerIcon = '✅';
    let bannerTitle = `SAFE TO VISIT (${s.score}/100 Risk)`;
    let bannerDesc = 'This website exhibits verified domain ownership, standard security protocols, and no phishing indicators.';

    if (isDanger) {
      cardClass = 'verdict-card-danger';
      bannerIcon = '🚨';
      bannerTitle = `MALICIOUS PHISHING DETECTED (${s.score}/100 Risk)`;
      bannerDesc = 'High probability of phishing, credential harvesting, or deceptive payload. Do NOT enter credentials or browse this link!';
    } else if (isSuspicious) {
      cardClass = 'verdict-card-warning';
      bannerIcon = '⚠️';
      bannerTitle = `SUSPICIOUS URL DETECTED (${s.score}/100 Risk)`;
      bannerDesc = 'Multiple structural anomalies flagged (such as unusual keywords, unencrypted transmission, or spam extensions). Proceed with caution.';
    }

    // Build flags list
    let flagsHtml = '';
    if (analysis.flags && analysis.flags.length > 0) {
      flagsHtml = `
        <div class="flags-section">
          <h4 class="flags-heading">Detected Threat Indicators (${analysis.flags.length})</h4>
          <div class="flags-list">
            ${analysis.flags.map(f => `
              <div class="flag-item ${f.type === 'danger' ? 'flag-item-danger' : 'flag-item-warning'}">
                <span class="flag-badge">${f.type === 'danger' ? 'CRITICAL' : 'WARNING'}</span>
                <div class="flag-text">
                  <strong>${escapeHtml(f.title)}</strong>
                  <p>${escapeHtml(f.desc)}</p>
                </div>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    } else {
      flagsHtml = `
        <div class="safe-badge-box">
          <span class="safe-check-icon">✓</span>
          <div>
            <strong>Clean Structural Heuristics:</strong> No brand typosquatting, no raw IP addresses, valid HTTPS encryption, and standard domain registry.
          </div>
        </div>
      `;
    }

    resultContainer.innerHTML = `
      <div class="result-card ${cardClass}">
        <!-- Top Verdict Banner -->
        <div class="verdict-banner">
          <span class="verdict-icon">${bannerIcon}</span>
          <div class="verdict-info">
            <h3 class="verdict-title">${bannerTitle}</h3>
            <p class="verdict-desc">${bannerDesc}</p>
            <div class="scanned-link">🔗 <code>${escapeHtml(analysis.rawUrl)}</code></div>
          </div>
        </div>

        <!-- Technical Telemetry Grid -->
        <div class="telemetry-grid">
          <div class="telemetry-box">
            <span class="telemetry-label">Protocol (Scheme)</span>
            <span class="telemetry-value ${c.protocol === 'https' ? 'val-green' : 'val-red'}">${c.protocol.toUpperCase()}</span>
          </div>
          <div class="telemetry-box">
            <span class="telemetry-label">Apex Domain</span>
            <span class="telemetry-value">${escapeHtml(c.apexDomain)}</span>
          </div>
          <div class="telemetry-box">
            <span class="telemetry-label">Subdomains</span>
            <span class="telemetry-value">${escapeHtml(c.subdomain || 'None')}</span>
          </div>
          <div class="telemetry-box">
            <span class="telemetry-label">Domain Extension (TLD)</span>
            <span class="telemetry-value">${escapeHtml(c.tld ? '.' + c.tld : 'None')}</span>
          </div>
          <div class="telemetry-box">
            <span class="telemetry-label">Shannon Entropy</span>
            <span class="telemetry-value">${s.entropy}</span>
          </div>
          <div class="telemetry-box">
            <span class="telemetry-label">Threat Classification</span>
            <span class="telemetry-value ${isSafe ? 'val-green' : 'val-red'}">${isSafe ? 'BENIGN (SAFE)' : 'MALICIOUS'}</span>
          </div>
        </div>

        <!-- Flags or Safe Summary -->
        ${flagsHtml}
      </div>
    `;

    resultContainer.style.display = 'block';
    resultContainer.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Handle Form Submission
  form.addEventListener('submit', (e) => {
    e.preventDefault();
    analyzeAndShow(urlInput.value);
  });

  // Handle Clear Button
  clearBtn.addEventListener('click', () => {
    urlInput.value = '';
    urlInput.focus();
    resultContainer.style.display = 'none';
  });

  // Handle Quick Sample Chips
  sampleChips.forEach(chip => {
    chip.addEventListener('click', () => {
      const u = chip.getAttribute('data-url');
      analyzeAndShow(u);
    });
  });

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
});
