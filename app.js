/* Password Sentinel — app.js
   Features:
   - Real-time entropy & heuristic scoring
   - Suggestions & color-coded strength meter
   - Password generator (length, classes)
   - SHA-256 preview via Web Crypto
   - Local history (localStorage) + export
   - Copy to clipboard, paste, quick breach check against embedded list
*/

(() => {
  // --- DOM refs
  const passwordInput = document.getElementById('passwordInput');
  const toggleVisible = document.getElementById('toggleVisible');
  const strengthLabel = document.getElementById('strengthLabel');
  const meterFill = document.getElementById('meterFill');
  const entropyEl = document.getElementById('entropy');
  const suggestionsEl = document.getElementById('suggestions');
  const copyBtn = document.getElementById('copyBtn');
  const saveBtn = document.getElementById('saveBtn');
  const pasteBtn = document.getElementById('pasteBtn');
  const clearBtn = document.getElementById('clearBtn');
  const hashBtn = document.getElementById('hashBtn');
  const hashOutput = document.getElementById('hashOutput');
  const checkBreachedBtn = document.getElementById('checkBreached');

  const genLength = document.getElementById('genLength');
  const genLengthValue = document.getElementById('genLengthValue');
  const inclLower = document.getElementById('inclLower');
  const inclUpper = document.getElementById('inclUpper');
  const inclNumbers = document.getElementById('inclNumbers');
  const inclSymbols = document.getElementById('inclSymbols');
  const generateBtn = document.getElementById('generateBtn');
  const generated = document.getElementById('generated');
  const copyGenBtn = document.getElementById('copyGenBtn');

  const historyList = document.getElementById('historyList');
  const historyTpl = document.getElementById('historyItem');

  const exportBtn = document.getElementById('exportBtn');
  const clearHistoryBtn = document.getElementById('clearHistory');

  const themeToggle = document.getElementById('themeToggle');

  // --- storage keys
  const KEY_HISTORY = 'ps_history_v1';

  // --- small breached password list for demo (do not rely on this for production)
  const breachedDemo = new Set([
    '123456', 'password', 'qwerty', '111111', '12345678', 'iloveyou',
    'admin', 'letmein', 'welcome', 'monkey', 'login', 'abc123'
  ]);

  // --- helpers
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));
  const nowISO = () => new Date().toISOString();

  // entropy calc: estimate bits of entropy based on character pool size and length
  function estimateEntropy(pw) {
    if (!pw) return 0;
    let pool = 0;
    if (/[a-z]/.test(pw)) pool += 26;
    if (/[A-Z]/.test(pw)) pool += 26;
    if (/[0-9]/.test(pw)) pool += 10;
    if (/[^a-zA-Z0-9]/.test(pw)) pool += 32; // rough symbol count
    // if none matched, assume full ASCII
    if (pool === 0) pool = 94;
    const entropy = Math.log2(Math.pow(pool, pw.length));
    return Math.round(entropy * 10) / 10;
  }

  // heuristic scoring to produce actionable categories
  function scorePassword(pw) {
    if (!pw) return { score: 0, label: 'Empty' };
    const entropy = estimateEntropy(pw);
    let score = 0;
    // baseline by entropy
    if (entropy < 28) score = 10;        // very weak
    else if (entropy < 35) score = 30;   // weak
    else if (entropy < 60) score = 55;   // fair
    else if (entropy < 80) score = 75;   // strong
    else score = 95;                     // excellent

    // heuristics to penalize common patterns
    const lower = pw.toLowerCase();
    if (breachedDemo.has(lower)) score = Math.min(score, 5);
    if (/^(.)\1+$/.test(pw)) score = Math.min(score, 5); // repeated single char
    if (/^[0-9]+$/.test(pw)) score = Math.min(score, 8); // only digits
    if (pw.length < 8) score = Math.min(score, 12);
    // small bonus for mixed classes
    const classes = [
      /[a-z]/.test(pw),
      /[A-Z]/.test(pw),
      /[0-9]/.test(pw),
      /[^a-zA-Z0-9]/.test(pw)
    ].filter(Boolean).length;
    if (classes >= 3 && pw.length >= 12) score += 7;
    return { score: clamp(score, 0, 100), label: labelFromScore(score), entropy };
  }

  function labelFromScore(s) {
    if (s < 15) return 'Very weak';
    if (s < 35) return 'Weak';
    if (s < 60) return 'Fair';
    if (s < 80) return 'Strong';
    return 'Excellent';
  }

  function meterColor(score) {
    // return CSS gradient stops by score
    if (score < 15) return 'linear-gradient(90deg,#ff5a5a,#ff8a5a)';
    if (score < 35) return 'linear-gradient(90deg,#ff8a5a,#ffc857)';
    if (score < 60) return 'linear-gradient(90deg,#ffd166,#9be15d)';
    if (score < 80) return 'linear-gradient(90deg,#7bd389,#00f5d4)';
    return 'linear-gradient(90deg,#7c4dff,#00f5d4)';
  }

  // suggestion engine
  function buildSuggestions(pw) {
    const items = [];
    if (!pw) {
      items.push({ text: 'Enter a password to see suggestions.', good: false });
      return items;
    }
    if (pw.length < 8) items.push({ text: 'Increase length to at least 12 characters.', good: false });
    if (!/[a-z]/.test(pw)) items.push({ text: 'Add lowercase letters (a–z).', good: false });
    if (!/[A-Z]/.test(pw)) items.push({ text: 'Add uppercase letters (A–Z).', good: false });
    if (!/[0-9]/.test(pw)) items.push({ text: 'Include numbers (0–9).', good: false });
    if (!/[^a-zA-Z0-9]/.test(pw)) items.push({ text: 'Include symbols (!@#$% etc.)', good: false });
    if (/(password|1234|abcd|qwerty|admin)/i.test(pw)) items.push({ text: 'Avoid common words or sequences.', good: false });
    if (pw.length >= 12 && /[A-Z]/.test(pw) && /[0-9]/.test(pw) && /[^a-zA-Z0-9]/.test(pw)) 
      items.push({ text: 'Strong composition — good job!', good: true });
    return items;
  }

  // compute SHA-256 hex using Web Crypto
  async function sha256Hex(str) {
    const enc = new TextEncoder();
    const buf = enc.encode(str);
    const hash = await crypto.subtle.digest('SHA-256', buf);
    const hex = Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('');
    return hex;
  }

  // --- history storage
  function loadHistory() {
    try {
      const raw = localStorage.getItem(KEY_HISTORY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }
  function saveHistory(list) { localStorage.setItem(KEY_HISTORY, JSON.stringify(list)); }

  function addToHistory(pw, entropy, score) {
    const list = loadHistory();
    list.unshift({ id: Date.now()+Math.random(), time: nowISO(), pw, entropy, score });
    if (list.length > 200) list.pop();
    saveHistory(list);
    renderHistory();
  }

  function deleteFromHistory(id) {
    let list = loadHistory();
    list = list.filter(i => i.id !== id);
    saveHistory(list);
    renderHistory();
  }

  function exportHistoryCSV() {
    const list = loadHistory();
    if (!list.length) return alert('No history to export');
    const rows = [['time','password','entropy','score']].concat(list.map(r => [r.time, r.pw, r.entropy, r.score]));
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'password-sentinel-history.csv'; a.click();
    URL.revokeObjectURL(url);
  }

  function renderHistory() {
    const list = loadHistory();
    historyList.innerHTML = '';
    list.forEach(item => {
      const tmpl = historyTpl.content.cloneNode(true);
      const li = tmpl.querySelector('li');
      li.dataset.id = item.id;
      tmpl.querySelector('.h-pass').textContent = item.pw.length > 16 ? item.pw.slice(0,12) + '…' : item.pw;
      tmpl.querySelector('.h-time').textContent = new Date(item.time).toLocaleString();
      tmpl.querySelector('.h-entropy').textContent = `${item.entropy} bits • ${labelFromScore(item.score)}`;
      const copyBtn = tmpl.querySelector('.h-copy');
      const delBtn = tmpl.querySelector('.h-delete');
      copyBtn.addEventListener('click', () => {
        navigator.clipboard.writeText(item.pw).then(()=> flash('Copied to clipboard'));
      });
      delBtn.addEventListener('click', () => deleteFromHistory(item.id));
      historyList.appendChild(tmpl);
    });
  }

  // flash small transient message (simple)
  function flash(msg) {
    const el = document.createElement('div');
    el.textContent = msg;
    el.style.position = 'fixed';
    el.style.right = '16px';
    el.style.bottom = '20px';
    el.style.padding = '10px 14px';
    el.style.borderRadius = '10px';
    el.style.background = 'linear-gradient(180deg,#0f1720,#0b0b0d)';
    el.style.color = '#dbeafe';
    el.style.boxShadow = '0 10px 30px rgba(2,6,23,0.6)';
    document.body.appendChild(el);
    setTimeout(()=> el.style.opacity = '0', 1800);
    setTimeout(()=> el.remove(), 2300);
  }

  // breach check (demo offline using set)
  function quickBreachCheck(pw) {
    if (!pw) return { breached: false, msg: 'No password' };
    const lower = pw.toLowerCase();
    if (breachedDemo.has(lower)) return { breached: true, msg: 'This password appears in common breached lists (demo).' };
    if (pw.length < 8) return { breached: true, msg: 'Too short — likely insecure.' };
    return { breached: false, msg: 'No immediate matches found (demo). For production use a secure breach API.' };
  }

  // update UI from password
  async function updateFromInput(pw) {
    const { score, label, entropy } = scorePassword(pw);
    const percent = score;
    strengthLabel.textContent = `Strength: ${label}`;
    meterFill.style.width = `${percent}%`;
    meterFill.style.background = meterColor(score);
    entropyEl.textContent = `Entropy: ${entropy} bits`;
    // suggestions
    const suggestions = buildSuggestions(pw);
    suggestionsEl.innerHTML = '';
    suggestions.forEach(s => {
      const li = document.createElement('li');
      li.textContent = s.text;
      li.className = s.good ? 'good' : 'bad';
      suggestionsEl.appendChild(li);
    });
    // clear hash output if password cleared
    if (!pw) hashOutput.textContent = '';
  }

  // event wiring
  passwordInput.addEventListener('input', e => updateFromInput(e.target.value));
  passwordInput.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); saveCurrentToHistory(); }});

  toggleVisible.addEventListener('click', () => {
    const isPwd = passwordInput.type === 'password';
    passwordInput.type = isPwd ? 'text' : 'password';
    toggleVisible.setAttribute('aria-pressed', String(isPwd));
    toggleVisible.textContent = isPwd ? '🙈' : '👁️';
  });

  pasteBtn.addEventListener('click', async () => {
    try {
      const text = await navigator.clipboard.readText();
      passwordInput.value = text;
      updateFromInput(text);
      flash('Pasted from clipboard');
    } catch (e) { flash('Unable to read clipboard'); }
  });

  clearBtn.addEventListener('click', () => {
    passwordInput.value = '';
    updateFromInput('');
  });

  copyBtn.addEventListener('click', async () => {
    const pw = passwordInput.value;
    if (!pw) return flash('No password to copy');
    try {
      await navigator.clipboard.writeText(pw);
      flash('Password copied to clipboard');
    } catch (e) {
      flash('Copy failed');
    }
  });

  saveBtn.addEventListener('click', () => saveCurrentToHistory());

  async function saveCurrentToHistory() {
    const pw = passwordInput.value;
    if (!pw) return flash('Nothing to save');
    const { entropy, score } = scorePassword(pw);
    addToHistory(pw, entropy, score);
    flash('Saved to history (local)');
  }

  hashBtn.addEventListener('click', async () => {
    const pw = passwordInput.value;
    if (!pw) return flash('Enter password to hash');
    hashOutput.textContent = 'Computing…';
    try {
      const h = await sha256Hex(pw);
      hashOutput.textContent = h;
    } catch (e) {
      hashOutput.textContent = 'Error computing hash';
    }
  });

  checkBreachedBtn.addEventListener('click', () => {
    const pw = passwordInput.value;
    const { breached, msg } = quickBreachCheck(pw);
    if (breached) flash(msg);
    else flash('Quick check passed (demo)');
  });

  // generator
  genLength.addEventListener('input', () => genLengthValue.textContent = genLength.value);
  generateBtn.addEventListener('click', () => {
    const len = parseInt(genLength.value, 10);
    const pools = [];
    if (inclLower.checked) pools.push('abcdefghijklmnopqrstuvwxyz');
    if (inclUpper.checked) pools.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (inclNumbers.checked) pools.push('0123456789');
    if (inclSymbols.checked) pools.push('!@#$%^&*()-_=+[]{};:,.<>?/`~|');
    if (!pools.length) { flash('Choose at least one character class'); return; }
    // build password ensuring at least one from each selected pool
    let pw = '';
    for (let i = 0; i < pools.length; i++) pw += pools[i][Math.floor(Math.random()*pools[i].length)];
    const all = pools.join('');
    for (let i = pw.length; i < len; i++) pw += all[Math.floor(Math.random()*all.length)];
    // shuffle
    pw = pw.split('').sort(() => Math.random() - 0.5).join('');
    generated.value = pw;
    flash('Password generated');
  });

  copyGenBtn.addEventListener('click', async () => {
    const p = generated.value;
    if (!p) return flash('No generated password');
    try { await navigator.clipboard.writeText(p); flash('Generated password copied'); } catch(e){ flash('Copy failed'); }
  });

  exportBtn.addEventListener('click', exportHistoryCSV);
  clearHistoryBtn.addEventListener('click', () => {
    if (!confirm('Clear saved history?')) return;
    saveHistory([]); renderHistory(); flash('History cleared');
  });

  // simple theme toggle (persisted)
  const THEME_KEY = 'ps_theme';
  function applyTheme(theme) {
    if (theme === 'light') document.documentElement.style.filter = 'invert(.98) hue-rotate(180deg)';
    else document.documentElement.style.filter = '';
    localStorage.setItem(THEME_KEY, theme);
    themeToggle.textContent = theme === 'light' ? '☀️' : '🌙';
  }
  themeToggle.addEventListener('click', () => {
    const cur = localStorage.getItem(THEME_KEY) || 'dark';
    applyTheme(cur === 'dark' ? 'light' : 'dark');
  });
  applyTheme(localStorage.getItem(THEME_KEY) || 'dark');

  // initial render
  (async function init() {
    renderHistory();
    await updateFromInput(passwordInput.value);
  })();

  // expose for debugging in demo
  window.PasswordSentinel = {
    estimateEntropy, scorePassword, buildSuggestions
  };

})();