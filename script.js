const secretEl = document.getElementById('secretKey');
const codeDisplay = document.getElementById('codeDisplay');
const remainingEl = document.getElementById('remaining');
const pasteBtn = document.getElementById('pasteBtn');
const cleanBtn = document.getElementById('cleanBtn');
const getCodeBtn = document.getElementById('getCodeBtn');
const verifyBtn = document.getElementById('verifyBtn');
const verifyInput = document.getElementById('verifyInput');
const verifyResult = document.getElementById('verifyResult');
const errorEl = document.getElementById('error');
const copyCodeBtn = document.getElementById('copyCodeBtn');
const copyMsg = document.getElementById('copyMsg');

let interval = null;

// Base32 থেকে bytes এ কনভার্ট করে
function base32ToBytes(base32) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = (base32 || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (let i = 0; i < cleaned.length; i++) {
    const val = alphabet.indexOf(cleaned[i]);
    if (val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.substr(i, 8), 2));
  }
  return new Uint8Array(bytes);
}

// counter কে 8-বাইট বাফারে রূপান্তর করে
function counterToBuffer(counter) {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  const hi = Math.floor(counter / 0x100000000);
  const lo = counter >>> 0;
  view.setUint32(0, hi, false);
  view.setUint32(4, lo, false);
  return buf;
}

// HMAC-SHA1 সাইনিং (Web Crypto API)
async function hmacSha1(keyBytes, dataBuffer) {
  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, dataBuffer);
  return new Uint8Array(sig);
}

// HOTP জেনারেটর (RFC 4226)
async function hotp(secretBytes, counter, digits = 6) {
  const counterBuf = counterToBuffer(counter);
  const h = await hmacSha1(secretBytes, counterBuf);
  const offset = h[h.length - 1] & 0x0f;
  const code = ((h[offset] & 0x7f) << 24) |
               ((h[offset + 1] & 0xff) << 16) |
               ((h[offset + 2] & 0xff) << 8) |
               (h[offset + 3] & 0xff);
  return (code % (10 ** digits)).toString().padStart(digits, '0');
}

// TOTP জেনারেট (30 সেকেন্ড স্টেপ)
async function generateTOTP(secretBase32, step = 30, digits = 6) {
  const secretBytes = base32ToBytes(secretBase32);
  if (!secretBytes.length) throw new Error('Invalid Base32 secret');
  const now = Date.now();
  const counter = Math.floor((now / 1000) / step);
  const code = await hotp(secretBytes, counter, digits);
  const periodEnd = (counter + 1) * step * 1000;
  const remaining = Math.max(0, Math.ceil((periodEnd - now) / 1000));
  return { code, remaining };
}

// একবার কোড আপডেট করে UI-তে দেখানো
async function updateOnce() {
  setError('');
  const s = secretEl.value.trim();
  if (!s) {
    codeDisplay.textContent = '— — — — — —';
    remainingEl.textContent = '30s';
    return;
  }
  try {
    const { code, remaining } = await generateTOTP(s);
    codeDisplay.textContent = code;
    remainingEl.textContent = `${remaining}s`;
  } catch (e) {
    setError('Invalid secret or generation error');
    codeDisplay.textContent = '— — — — — —';
    remainingEl.textContent = '';
  }
}

// প্রতি সেকেন্ডে আপডেট চালানো
async function startContinuous() {
  await updateOnce();
  if (interval) clearInterval(interval);
  interval = setInterval(updateOnce, 1000);
}

function setError(msg) {
  errorEl.textContent = msg || '';
}

// Paste বাটন ক্লিক হ্যান্ডলার
pasteBtn.addEventListener('click', async () => {
  try {
    const txt = await navigator.clipboard.readText();
    secretEl.value = txt;
    setError('');
  } catch (e) {
    setError('Clipboard access denied');
  }
});

// Clean বাটন ক্লিক হ্যান্ডলার
cleanBtn.addEventListener('click', () => {
  secretEl.value = '';
  verifyInput.value = '';
  codeDisplay.textContent = '— — — — — —';
  remainingEl.textContent = '30s';
  verifyResult.textContent = '';
  setError('');
  if (interval) { clearInterval(interval); interval = null; }
});

// Get Code বাটন ক্লিক হ্যান্ডলার
getCodeBtn.addEventListener('click', () => {
  startContinuous();
});

// Verify বাটন ক্লিক হ্যান্ডলার
verifyBtn.addEventListener('click', async () => {
  setError('');
  verifyResult.textContent = '';
  const s = secretEl.value.trim();
  const v = verifyInput.value.trim();
  if (!s) { setError('Enter secret to verify against'); return; }
  if (!v) { setError('Enter code to verify'); return; }
  try {
    const step = 30;
    const now = Date.now();
    const base = Math.floor((now / 1000) / step);
    const counters = [base - 1, base, base + 1]; // +/- 1 window allowed
    const secretBytes = base32ToBytes(s);
    let ok = false;
    for (const c of counters) {
      const expected = await hotp(secretBytes, c);
      if (expected === v) { ok = true; break; }
    }
    verifyResult.textContent = ok ? 'Code is valid' : 'Code is NOT valid';
    verifyResult.style.color = ok ? '#7af0d9' : '#ff6b6b';
  } catch (e) {
    setError('Verification failed or invalid secret');
  }
});

// Copy Code বাটন ক্লিক হ্যান্ডলার
copyCodeBtn.addEventListener('click', () => {
  const code = codeDisplay.textContent.trim();
  if (!code || code.includes('—')) {
    copyMsg.textContent = 'No code to copy';
    setTimeout(() => { copyMsg.textContent = ''; }, 1500);
    return;
  }
  navigator.clipboard.writeText(code).then(() => {
    copyMsg.textContent = 'Copied!';
    setTimeout(() => { copyMsg.textContent = ''; }, 1500);
  }).catch(() => {
    copyMsg.textContent = 'Copy failed';
    setTimeout(() => { copyMsg.textContent = ''; }, 1500);
  });
});

// Enter চাপলে বাটন trigger করবে
secretEl.addEventListener('keydown', (e) => { if (e.key === 'Enter') getCodeBtn.click(); });
verifyInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') verifyBtn.click(); });