
 const firebaseConfig = {
    apiKey: "AIzaSyAS01ZPt6bFTYD3T2kgXrQPZCxP4q4UeFk",
    authDomain: "phishing-detector-4d35d.firebaseapp.com",
    projectId: "phishing-detector-4d35d",
    storageBucket: "phishing-detector-4d35d.firebasestorage.app",
    messagingSenderId: "1559268109",
    appId: "1:1559268109:web:0f53cf9a6c5bf38de37e44",
    measurementId: "G-YCLZFLZ3Y9"
};

firebase.initializeApp(firebaseConfig);
const db = firebase.firestore();

// ══════════════════════════════════════════
// DETECTION ENGINE
// ══════════════════════════════════════════
function extractFeatures(url) {
  let parsed;
  try {
    parsed = new URL(url.includes('://') ? url : 'http://' + url);
  } catch(e) {
    return null;
  }

  const domain   = parsed.hostname;
  const path     = parsed.pathname;
  const urlLower = url.toLowerCase();

  const suspiciousWords = [
    'login','verify','secure','update','bank','account',
    'confirm','password','signin','paypal','ebay','amazon',
    'apple','microsoft','netflix','alert','suspend','urgent',
    'click','free','winner','prize','billing','authorize'
  ];
  const shorteners = [
    'bit.ly','tinyurl.com','t.co','goo.gl',
    'ow.ly','short.link','rb.gy','cutt.ly'
  ];

  return {
    url_length:          url.length,
    has_ip:              /(\d{1,3}\.){3}\d{1,3}/.test(domain) ? 1 : 0,
    has_at_symbol:       url.includes('@') ? 1 : 0,
    has_https:           url.startsWith('https') ? 1 : 0,
    subdomain_count:     Math.max(domain.split('.').length - 2, 0),
    suspicious_keywords: suspiciousWords.filter(w => urlLower.includes(w)).length,
    is_shortened:        shorteners.some(s => urlLower.includes(s)) ? 1 : 0,
    has_double_slash:    url.slice(8).includes('//') ? 1 : 0,
    has_hyphen:          domain.includes('-') ? 1 : 0,
    digit_count:         (domain.match(/\d/g) || []).length,
    path_length:         path.length
  };
}

function calculateRisk(features) {
  let score   = 0;
  const reasons = [];

  if (features.url_length > 100) { score += 3; reasons.push(`Very long URL (${features.url_length} characters)`); }
  else if (features.url_length > 75) { score += 2; reasons.push(`Long URL (${features.url_length} characters)`); }

  if (features.has_ip)        { score += 4; reasons.push('IP address used instead of domain name'); }
  if (features.has_at_symbol) { score += 4; reasons.push('@ symbol found — browser redirects after @'); }
  if (!features.has_https)    { score += 2; reasons.push('No HTTPS — connection is not encrypted'); }

  if (features.subdomain_count > 3)      { score += 3; reasons.push(`Too many subdomains (${features.subdomain_count})`); }
  else if (features.subdomain_count > 2) { score += 1; reasons.push(`Multiple subdomains detected`); }

  if (features.suspicious_keywords >= 3) { score += 3; reasons.push(`Multiple suspicious keywords (${features.suspicious_keywords})`); }
  else if (features.suspicious_keywords >= 1) { score += 2; reasons.push('Suspicious keywords found in URL'); }

  if (features.is_shortened)    { score += 3; reasons.push('URL shortener hides real destination'); }
  if (features.has_double_slash){ score += 2; reasons.push('Double slash redirect detected'); }
  if (features.has_hyphen)      { score += 1; reasons.push('Hyphen in domain (common phishing pattern)'); }
  if (features.digit_count > 5) { score += 2; reasons.push(`Many digits in domain (${features.digit_count})`); }

  return { score, reasons };
}

function getVerdict(score) {
  if (score >= 8) return { verdict:'PHISHING',   emoji:'🚨', risk:'HIGH RISK',   cssClass:'phishing'  };
  if (score >= 4) return { verdict:'SUSPICIOUS',  emoji:'⚠️', risk:'MEDIUM RISK', cssClass:'suspicious' };
  return               { verdict:'LEGITIMATE',  emoji:'✅', risk:'LOW RISK',   cssClass:'legitimate' };
}

// ══════════════════════════════════════════
// FIREBASE OPERATIONS
// ══════════════════════════════════════════
async function saveScan(url, verdict, score, reasons) {
  try {
    await db.collection('scans').add({
      url, verdict, score, reasons,
      timestamp: firebase.firestore.FieldValue.serverTimestamp()
    });
  } catch(e) { console.warn('Save failed:', e); }
}

async function loadStats() {
  try {
    const snap = await db.collection('scans').get();
    let total=0, phishing=0, suspicious=0, safe=0;
    snap.forEach(doc => {
      total++;
      const v = doc.data().verdict;
      if      (v === 'PHISHING')   phishing++;
      else if (v === 'SUSPICIOUS') suspicious++;
      else                         safe++;
    });
    document.getElementById('totalScans').textContent      = total;
    document.getElementById('phishingCount').textContent   = phishing;
    document.getElementById('suspiciousCount').textContent = suspicious;
    document.getElementById('safeCount').textContent       = safe;
  } catch(e) { console.warn('Stats failed:', e); }
}

// ══════════════════════════════════════════
// UI FUNCTIONS
// ══════════════════════════════════════════
function showLoader(show) {
  document.getElementById('loader').style.display    = show ? 'block' : 'none';
  document.getElementById('resultBox').style.display = 'none';
}

function displayResult(url, score, reasons, v) {
  const maxScore = 29;
  const pct = Math.min((score / maxScore) * 100, 100);

  document.getElementById('resultIcon').textContent    = v.emoji;
  document.getElementById('resultVerdict').textContent = `${v.verdict} — ${v.risk}`;
  document.getElementById('resultUrl').textContent     = url;
  document.getElementById('scoreText').textContent     = `${score} / ${maxScore} (${pct.toFixed(0)}%)`;

  document.getElementById('resultHeader').className =
    `result-header ${v.cssClass}`;

  const fill = document.getElementById('scoreFill');
  fill.className   = `score-fill ${score >= 8 ? 'high' : score >= 4 ? 'medium' : 'low'}`;
  fill.style.width = '0%';
  setTimeout(() => { fill.style.width = pct + '%'; }, 100);

  const list = document.getElementById('reasonsList');
  list.innerHTML = reasons.length
    ? reasons.map(r =>
        `<div class="reason-item">
           <i class="fas fa-exclamation-circle"></i>
           <span>${r}</span>
         </div>`).join('')
    : `<div class="reason-item">
         <i class="fas fa-check-circle" style="color:#22c55e"></i>
         <span>No suspicious indicators detected</span>
       </div>`;

  document.getElementById('resultBox').style.display = 'block';
}

function addToHistory(url, v, score) {
  const list  = document.getElementById('historyList');
  const empty = list.querySelector('.empty-state');
  if (empty) empty.remove();

  const time = new Date().toLocaleTimeString();
  const item = document.createElement('div');
  item.className = 'history-item';
  item.innerHTML = `
    <span class="history-icon">${v.emoji}</span>
    <div class="history-info">
      <div class="history-url">${url}</div>
      <div class="history-verdict ${v.verdict}">
        ${v.verdict} — Score: ${score}
      </div>
    </div>
    <span class="history-time">${time}</span>`;
  list.insertBefore(item, list.firstChild);

  const badge = document.getElementById('historyCount');
  badge.textContent = parseInt(badge.textContent || '0') + 1;
}

// ══════════════════════════════════════════
// MAIN FUNCTION
// ══════════════════════════════════════════
async function analyzeURL() {
  const input = document.getElementById('urlInput');
  const url   = input.value.trim();
  if (!url) { alert('Please enter a URL to scan!'); return; }

  showLoader(true);
  await new Promise(r => setTimeout(r, 1200));

  const features = extractFeatures(url);
  if (!features) {
    showLoader(false);
    alert('Invalid URL! Please include http:// or https://');
    return;
  }

  const { score, reasons } = calculateRisk(features);
  const v = getVerdict(score);

  showLoader(false);
  displayResult(url, score, reasons, v);
  addToHistory(url, v, score);

  await saveScan(url, v.verdict, score, reasons);
  await loadStats();
}

function quickTest(url) {
  document.getElementById('urlInput').value = url;
  analyzeURL();
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('urlInput')
    .addEventListener('keypress', e => {
      if (e.key === 'Enter') analyzeURL();
    });
  loadStats();
});