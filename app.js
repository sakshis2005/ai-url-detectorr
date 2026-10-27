/**
 * Sentinel AI - Chatbot Application Controller
 * Handles conversation flows, URL parsing, threat card rendering,
 * sidebar synchronization, Web Audio sound effects, and report exporting.
 */

document.addEventListener('DOMContentLoaded', () => {
  // Elements
  const chatHistory = document.getElementById('chatHistory');
  const chatInput = document.getElementById('chatInput');
  const sendBtn = document.getElementById('sendBtn');
  const clearChatBtn = document.getElementById('clearChatBtn');
  const audioToggleBtn = document.getElementById('audioToggleBtn');
  const audioIcon = document.getElementById('audioIcon');
  const audioStatusText = document.getElementById('audioStatusText');

  // Sidebar Inspector Elements
  const sidebarScanInput = document.getElementById('sidebarScanInput');
  const sidebarScanBtn = document.getElementById('sidebarScanBtn');
  const gaugeProgressCircle = document.getElementById('gaugeProgressCircle');
  const gaugeScore = document.getElementById('gaugeScore');
  const gaugeVerdictLabel = document.getElementById('gaugeVerdictLabel');
  const gaugeVerdictDesc = document.getElementById('gaugeVerdictDesc');
  const activeScanTimestamp = document.getElementById('activeScanTimestamp');

  // Dissector Fields
  const dispProtocol = document.getElementById('dispProtocol');
  const dispApex = document.getElementById('dispApex');
  const dispSubdomain = document.getElementById('dispSubdomain');
  const dispTLD = document.getElementById('dispTLD');
  const dispHostname = document.getElementById('dispHostname');
  const dispPath = document.getElementById('dispPath');
  const dispQuery = document.getElementById('dispQuery');

  // Checklist & Actions
  const heuristicsChecklist = document.getElementById('heuristicsChecklist');
  const copyReportBtn = document.getElementById('copyReportBtn');
  const downloadJsonBtn = document.getElementById('downloadJsonBtn');

  // State
  let lastAnalysis = null;
  let soundEnabled = true;
  let audioCtx = null;

  // Sound Synthesizer via Web Audio API
  function playSound(type = 'blip') {
    if (!soundEnabled) return;
    try {
      if (!audioCtx) {
        audioCtx = new (window.AudioContext || window.webkitAudioContext)();
      }
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }

      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      const now = audioCtx.currentTime;

      if (type === 'blip') {
        osc.type = 'sine';
        osc.frequency.setValueAtTime(800, now);
        osc.frequency.exponentialRampToValueAtTime(400, now + 0.08);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.linearRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      } else if (type === 'alert') {
        osc.type = 'sawtooth';
        osc.frequency.setValueAtTime(260, now);
        osc.frequency.setValueAtTime(320, now + 0.1);
        osc.frequency.setValueAtTime(220, now + 0.2);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.linearRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (type === 'safe') {
        osc.type = 'triangle';
        osc.frequency.setValueAtTime(523.25, now); // C5
        osc.frequency.setValueAtTime(659.25, now + 0.1); // E5
        osc.frequency.setValueAtTime(783.99, now + 0.2); // G5
        gain.gain.setValueAtTime(0.09, now);
        gain.gain.linearRampToValueAtTime(0.001, now + 0.4);
        osc.start(now);
        osc.stop(now + 0.4);
      }
    } catch (e) {
      console.warn('Audio feedback failed:', e);
    }
  }

  // Audio Toggle
  audioToggleBtn.addEventListener('click', () => {
    soundEnabled = !soundEnabled;
    audioStatusText.textContent = soundEnabled ? 'Sound On' : 'Muted';
    audioToggleBtn.style.opacity = soundEnabled ? '1' : '0.6';
    if (soundEnabled) playSound('blip');
  });

  // Welcome Message Initialization
  function initWelcomeMessage() {
    chatHistory.innerHTML = '';
    appendBotMessage(
      `**CyberGuard Threat Detection Engine Initialized & Active.**\n\n` +
      `Ready for lexical URL feature extraction and structural risk scoring. Enter or paste any target URL to run automated security evaluation for **brand spoofing, typosquatting, deceptive subdomains, suspicious TLDs, and credential harvesters**.\n\n` +
      `Select a sample attack vector below or enter a target URL to begin inspection.`,
      null
    );
  }

  // Helper to format timestamp
  function getTimestamp() {
    const d = new Date();
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  }

  // Add Target / Scan Entry Message to Stream
  function appendUserMessage(text) {
    const msgDiv = document.createElement('div');
    msgDiv.className = 'message user';
    msgDiv.innerHTML = `
      <div class="avatar user-avatar" style="font-weight:700; font-size:11px; background:linear-gradient(135deg, #a29bfe, #7e57c2); color:#fff;">SCAN</div>
      <div class="bubble-wrap">
        <div class="sender-meta">
          <span>INPUT TARGET</span>
          <span>•</span>
          <span>${getTimestamp()}</span>
        </div>
        <div class="bubble" style="font-family:monospace; font-size:0.88rem;">${escapeHtml(text)}</div>
      </div>
    `;
    chatHistory.appendChild(msgDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;
  }

  // Add Inspection Progress Indicator
  function showTypingIndicator() {
    const typingDiv = document.createElement('div');
    typingDiv.className = 'message bot';
    typingDiv.id = 'typingIndicator';
    typingDiv.innerHTML = `
      <div class="avatar bot-avatar" style="font-weight:700; font-size:11px; background:linear-gradient(135deg, #7e57c2, #6c5ce7); color:#fff;">SEC</div>
      <div class="bubble-wrap">
        <div class="bubble typing-bubble" style="padding:10px 16px;">
          <span style="font-size:0.75rem; color:#5e548e; font-family:monospace; margin-right:8px;">EXTRACTING FEATURES...</span>
          <span class="typing-dot"></span>
          <span class="typing-dot"></span>
          <span class="typing-dot"></span>
        </div>
      </div>
    `;
    chatHistory.appendChild(typingDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;
    return typingDiv;
  }

  function removeTypingIndicator() {
    const el = document.getElementById('typingIndicator');
    if (el) el.remove();
  }

  // Add Engine Inspection Report to Stream
  function appendBotMessage(markdownText, analysisResult = null) {
    const msgDiv = document.createElement('div');
    msgDiv.className = 'message bot';

    let cardHtml = '';
    if (analysisResult && analysisResult.valid) {
      cardHtml = renderThreatCard(analysisResult);
    }

    const formattedContent = formatSimpleMarkdown(markdownText);

    msgDiv.innerHTML = `
      <div class="avatar bot-avatar" style="font-weight:700; font-size:11px; background:linear-gradient(135deg, #7e57c2, #6c5ce7); color:#fff;">SEC</div>
      <div class="bubble-wrap">
        <div class="sender-meta">
          <span>CYBERGUARD ENGINE</span>
          <span>•</span>
          <span>${getTimestamp()}</span>
        </div>
        <div class="bubble">
          ${formattedContent}
          ${cardHtml}
        </div>
      </div>
    `;

    chatHistory.appendChild(msgDiv);
    chatHistory.scrollTop = chatHistory.scrollHeight;

    // Attach card event listeners if present
    if (analysisResult && analysisResult.valid) {
      const inspectBtn = msgDiv.querySelector('.inspect-btn');
      if (inspectBtn) {
        inspectBtn.addEventListener('click', () => {
          updateSidebarInspector(analysisResult);
          showToast('Updated Intel Inspector Panel with URL data');
          playSound('blip');
        });
      }

      const copyUrlBtn = msgDiv.querySelector('.url-copy-btn');
      if (copyUrlBtn) {
        copyUrlBtn.addEventListener('click', () => {
          navigator.clipboard.writeText(analysisResult.rawUrl);
          showToast('URL copied to clipboard');
          playSound('blip');
        });
      }
    }
  }

  // Render Threat Card HTML
  function renderThreatCard(res) {
    const s = res.stats;
    const borderClass = `border-${s.verdictClass.replace('verdict-', '')}`;
    const pillClass = `pill-${s.verdictClass.replace('verdict-', '')}`;

    const flagsHtml = res.flags.length > 0
      ? res.flags.map(f => `
          <div class="flag-item flag-${f.type}">
            <div class="flag-icon">
              ${f.type === 'danger' 
                ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ff3366" stroke-width="2.5"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>' 
                : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#ffb300" stroke-width="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>'}
            </div>
            <div class="flag-content">
              <strong>${escapeHtml(f.title)}</strong>
              <p>${escapeHtml(f.desc)}</p>
            </div>
          </div>
        `).join('')
      : '<p style="font-size:0.8rem; color:#00f59b;">✓ No suspicious threat signatures detected in heuristic evaluation.</p>';

    const recsHtml = res.recommendations.map(r => `<li>${escapeHtml(r)}</li>`).join('');

    return `
      <div class="threat-card ${borderClass}">
        <div class="threat-card-header">
          <div style="font-size:0.82rem; font-weight:700; letter-spacing:0.5px; color:#cbd5e1;">
            SECURITY THREAT ASSESSMENT
          </div>
          <div class="threat-score-pill ${pillClass}">
            <span>${escapeHtml(s.verdict)}</span>
            <span class="score-num">${s.score}</span>/100
          </div>
        </div>

        <div class="threat-url-row">
          <span class="threat-url-text" title="${escapeHtml(res.rawUrl)}">🔗 ${escapeHtml(res.rawUrl)}</span>
          <button class="url-copy-btn" title="Copy URL">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
          </button>
        </div>

        <div class="threat-card-body">
          <div class="flags-list">
            ${flagsHtml}
          </div>

          <div class="card-recommendations">
            <strong>🛡️ Recommended Protocol:</strong>
            <ul>${recsHtml}</ul>
          </div>
        </div>

        <div class="threat-card-footer">
          <button class="inspect-btn">
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 14 14"></polyline></svg>
            <span>Load in Intel Inspector</span>
          </button>
        </div>
      </div>
    `;
  }

  // Update Sidebar Threat Inspector
  function updateSidebarInspector(res) {
    if (!res || !res.valid) return;
    lastAnalysis = res;

    // Update timestamp
    activeScanTimestamp.textContent = getTimestamp();

    // 1. Update Gauge
    const s = res.stats;
    gaugeScore.textContent = s.score;
    gaugeVerdictLabel.textContent = s.verdict;
    gaugeVerdictLabel.className = `gauge-verdict-label pill-${s.verdictClass.replace('verdict-', '')}`;

    // Circumference = 2 * PI * r = 2 * 3.14159 * 70 ≈ 440
    const circumference = 440;
    const offset = circumference - (s.score / 100) * circumference;
    gaugeProgressCircle.style.strokeDashoffset = offset;
    gaugeProgressCircle.style.stroke = s.color;

    // Gauge Description
    if (s.score >= 70) {
      gaugeVerdictDesc.textContent = 'High probability of phishing or credential harvesting vector. Block or quarantine.';
    } else if (s.score >= 40) {
      gaugeVerdictDesc.textContent = 'Multiple risk indicators flagged. Proceed with extreme scrutiny.';
    } else if (s.score >= 20) {
      gaugeVerdictDesc.textContent = 'Minor anomalies or masked destination detected. Verify before clicking.';
    } else {
      gaugeVerdictDesc.textContent = 'Structure complies with standard safety benchmarks and trusted origin parameters.';
    }

    // 2. Dissector Fields
    const c = res.components;
    dispProtocol.textContent = c.protocol.toUpperCase();
    dispProtocol.className = c.protocol === 'https' ? 'grid-value highlight-safe' : 'grid-value highlight-alert';

    dispApex.textContent = c.apexDomain;
    dispApex.className = s.flags.some(f => f.category.includes('Typosquatting') || f.category.includes('Brand')) 
      ? 'grid-value highlight-alert' 
      : 'grid-value';

    dispSubdomain.textContent = c.subdomains;
    dispTLD.textContent = c.tld;
    dispTLD.className = s.flags.some(f => f.category.includes('TLD')) ? 'grid-value highlight-alert' : 'grid-value';

    dispHostname.textContent = c.hostname;
    dispPath.textContent = c.pathname;
    dispQuery.textContent = c.search;

    // 3. Update Heuristics Checklist
    const hasCategory = (cat) => res.flags.some(f => f.category.toLowerCase().includes(cat.toLowerCase()));

    setChecklistStatus('ip', hasCategory('IP Host'));
    setChecklistStatus('brand', hasCategory('Brand Impersonation'));
    setChecklistStatus('typosquat', hasCategory('Typosquatting'));
    setChecklistStatus('tld', hasCategory('Suspicious TLD'));
    setChecklistStatus('punycode', hasCategory('Homograph'));
    setChecklistStatus('auth', hasCategory('Authority Confusion'));
    setChecklistStatus('keywords', hasCategory('Urgency'));
    setChecklistStatus('shortener', hasCategory('Masking'));
    setChecklistStatus('entropy', hasCategory('Cryptographic Entropy'));
    setChecklistStatus('ssl', c.protocol !== 'https');
  }

  function setChecklistStatus(checkId, isFlagged) {
    const row = heuristicsChecklist.querySelector(`[data-check="${checkId}"]`);
    if (!row) return;
    const badge = row.querySelector('.h-status-badge');
    if (isFlagged) {
      badge.textContent = 'ALERT';
      badge.className = 'h-status-badge badge-flagged';
    } else {
      badge.textContent = checkId === 'entropy' ? 'NORMAL' : (checkId === 'ssl' ? 'HTTPS' : 'CLEAR');
      badge.className = 'h-status-badge badge-pass';
    }
  }

  // Process User Input (Chat or Scan)
  function handleSendMessage(text) {
    const trimmed = (text || chatInput.value).trim();
    if (!trimmed) return;

    appendUserMessage(trimmed);
    chatInput.value = '';

    playSound('blip');
    showTypingIndicator();

    setTimeout(() => {
      removeTypingIndicator();

      // Check for URLs
      const urls = URLThreatDetector.extractURLs(trimmed);

      if (urls.length > 0) {
        // Run deep heuristic analysis on primary URL
        const targetUrl = urls[0];
        const analysis = URLThreatDetector.analyze(targetUrl);

        // Synchronize sidebar
        updateSidebarInspector(analysis);

        // Sound alert based on verdict
        if (analysis.stats.score >= 70) {
          playSound('alert');
        } else {
          playSound('safe');
        }

        // Generate professional security telemetry explanation
        let explanation = '';
        if (analysis.stats.score >= 70) {
          explanation = `🚨 **CRITICAL RISK DETECTED (${analysis.stats.score}/100):** Multiple malicious threat indicators identified in target URL structure. ` +
            `Target host **"${analysis.components.hostname}"** exhibits phishing heuristics and credential harvesting characteristics. ` +
            `Refer to the technical breakdown below:`;
        } else if (analysis.stats.score >= 40) {
          explanation = `⚠️ **SUSPICIOUS URL DETECTED (${analysis.stats.score}/100):** Structural anomalies identified (such as deceptive keywords, non-standard path depth, or high-risk domain extension). ` +
            `Exercise extreme caution before navigating to this destination.`;
        } else if (analysis.stats.score >= 20) {
          explanation = `ℹ️ **LOW-RISK CAUTION (${analysis.stats.score}/100):** Target destination is obfuscated or shortened (e.g. redirection shortener). Destination should be verified.`;
        } else {
          explanation = `✅ **SECURITY VERIFICATION PASSED (0/100):** Target hostname **"${analysis.components.hostname}"** complies with verified apex domain standards and encryption protocols.`;
        }

        appendBotMessage(explanation, analysis);

      } else {
        // Technical Reference Glossary & Fallback
        const lower = trimmed.toLowerCase();
        let reply = '';

        if (lower.includes('typosquat') || lower.includes('lookalike')) {
          reply = `**Technical Reference: Typosquatting (URL Hijacking)**\n\n` +
            `Typosquatting is a social engineering attack where malicious actors register domains with deliberate typographic variations of trusted brands (e.g., \`paypa1.com\` vs \`paypal.com\`).\n\n` +
            `**Detection Vectors:**\n` +
            `1. **Levenshtein Distance:** Measures character substitution edits against known apex domains.\n` +
            `2. **Homoglyph & Glyph Substitution:** Identifies visually similar character mapping (\`1\` for \`l\`, \`0\` for \`o\`, \`rn\` for \`m\`).\n` +
            `3. **Deceptive Subdomain Stacking:** Prepending brand names to spoofed base domains (\`paypal.com.account-verify.xyz\`).`;
        } else if (lower.includes('phishing') || lower.includes('spot')) {
          reply = `**Technical Reference: Phishing URL Indicators**\n\n` +
            `• **Subdomain Deception:** Spoofed brand names prepended to unverified third-party hosts.\n` +
            `• **High-Risk TLD Abuse:** Cheap or high-entropy top-level domains frequently associated with automated spam campaigns (\`.xyz\`, \`.top\`, \`.click\`).\n` +
            `• **Credential Theft Tokens:** URI paths containing authentication keywords (\`login\`, \`verify\`, \`account-update\`, \`auth\`).\n` +
            `• **Bare IP Addressing:** URLs using raw IPv4/IPv6 notation instead of registered DNS records.`;
        } else if (lower.includes('shorten') || lower.includes('bitly') || lower.includes('bit.ly')) {
          reply = `**Technical Reference: URL Shortener Obfuscation**\n\n` +
            `Shortening services (\`bit.ly\`, \`tinyurl.com\`) conceal the final target destination from automated security scanners and users.\n` +
            `CyberGuard flags shortened URLs for mandatory destination resolution before trust is assigned.`;
        } else {
          reply = `**Input Notice:** No valid URL detected in input string.\n\n` +
            `Please enter a complete website link or IP address (e.g., \`http://secure-paypal-login.xyz/verify\` or \`https://github.com\`) to perform automated threat inspection.`;
        }

        playSound('blip');
        appendBotMessage(reply, null);
      }
    }, 120);
  }

  // Event Listeners
  sendBtn.addEventListener('click', () => handleSendMessage());
  chatInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      handleSendMessage();
    }
  });

  // Suggestion Chips Click
  document.querySelectorAll('.chip-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.getAttribute('data-prompt');
      handleSendMessage(prompt);
    });
  });

  // Sidebar Quick Scanner
  sidebarScanBtn.addEventListener('click', () => {
    const url = sidebarScanInput.value.trim();
    if (!url) return;
    sidebarScanInput.value = '';
    handleSendMessage(url);
  });

  sidebarScanInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      sidebarScanBtn.click();
    }
  });

  // Presets Test Bank Buttons
  document.querySelectorAll('.preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const url = btn.getAttribute('data-url');
      handleSendMessage(url);
    });
  });

  // Clear Inspection Log
  clearChatBtn.addEventListener('click', () => {
    initWelcomeMessage();
    playSound('blip');
    showToast('Inspection log cleared');
  });

  // Copy Markdown Report
  copyReportBtn.addEventListener('click', () => {
    if (!lastAnalysis) {
      showToast('Please analyze a URL first to generate a report');
      return;
    }

    const a = lastAnalysis;
    const md = [
      `# CyberGuard Threat Inspection Report: ${a.rawUrl}`,
      `**Timestamp:** ${new Date().toISOString()}`,
      `**Risk Score:** ${a.stats.score}/100 (${a.stats.verdict})`,
      `**Protocol:** ${a.components.protocol.toUpperCase()}`,
      `**Apex Domain:** ${a.components.apexDomain}`,
      `**Hostname:** ${a.components.hostname}`,
      `**Entropy:** ${a.stats.entropy} bits/char`,
      ``,
      `## Detected Threat Signals (${a.flags.length})`,
      a.flags.length > 0
        ? a.flags.map(f => `- **[${f.type.toUpperCase()}] ${f.title}**: ${f.desc}`).join('\n')
        : `- No suspicious threat flags triggered.`,
      ``,
      `## Recommended Actions`,
      a.recommendations.map(r => `- ${r}`).join('\n')
    ].join('\n');

    navigator.clipboard.writeText(md);
    playSound('blip');
    showToast('Report copied to clipboard as Markdown');
  });

  // Download JSON Report
  downloadJsonBtn.addEventListener('click', () => {
    if (!lastAnalysis) {
      showToast('Please analyze a URL first to export JSON');
      return;
    }

    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(lastAnalysis, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `sentinel-threat-report-${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();

    playSound('blip');
    showToast('Exported threat report as JSON file');
  });

  // Toast Notification Helper
  function showToast(msg) {
    const existing = document.querySelector('.toast-notice');
    if (existing) existing.remove();

    const toast = document.createElement('div');
    toast.className = 'toast-notice';
    toast.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--accent-cyan)" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>
      <span>${escapeHtml(msg)}</span>
    `;
    document.body.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(10px)';
      toast.style.transition = 'all 0.3s ease';
      setTimeout(() => toast.remove(), 300);
    }, 2800);
  }

  // Utilities: Markdown Formatter & Escape HTML
  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function formatSimpleMarkdown(text) {
    if (!text) return '';
    return text
      .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
      .replace(/\*(.*?)\*/g, '<em>$1</em>')
      .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.08);padding:2px 6px;border-radius:4px;font-family:var(--font-mono);font-size:0.85em;">$1</code>')
      .replace(/\n\n/g, '<br><br>')
      .replace(/\n• /g, '<br>• ')
      .replace(/\n/g, '<br>');
  }

  // Run initial setup
  initWelcomeMessage();
});
