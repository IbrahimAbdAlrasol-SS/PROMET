/* ── PROMET Web UI — Frontend ─────────────────────────────────────────────── */
'use strict';

// ── Phase definitions ─────────────────────────────────────────────────────────
const PHASES = [
  { n: 0,  label: "Env. Validation" },
  { n: 1,  label: "Boot Emulator"   },
  { n: 2,  label: "Target Intake"   },
  { n: 3,  label: "Static Triage"   },
  { n: 4,  label: "Install & Launch"},
  { n: 5,  label: "Net. Intercept"  },
  { n: 6,  label: "Exercise App"    },
  { n: 7,  label: "Prepare Frida"   },
  { n: 8,  label: "Anti-Analysis"   },
  { n: 9,  label: "PoC Scripts"     },
  { n: 10, label: "Review"          },
  { n: 11, label: "Backup Extract"  },
  { n: 12, label: "Magisk Bypass"   },
  { n: 13, label: "Packed DEX"      },
];

// ── State ─────────────────────────────────────────────────────────────────────
let ws           = null;
let sessionId    = crypto.randomUUID();
let currentPhase = -1;
let isGenerating = false;
let pendingApk   = null;   // { filename, path }

// ── DOM refs ──────────────────────────────────────────────────────────────────
const $messages    = document.getElementById('messages');
const $input       = document.getElementById('user-input');
const $sendBtn     = document.getElementById('btn-send');
const $statusDot   = document.getElementById('status-dot');
const $phaseFill   = document.getElementById('phase-fill');
const $phaseName   = document.getElementById('phase-name');
const $phaseList   = document.getElementById('phase-list');
const $apkBadge    = document.getElementById('apk-badge');
const $apkName     = document.getElementById('apk-badge-name');
const $apkRemove   = document.getElementById('apk-remove');
const $fileInput   = document.getElementById('file-input');
const $dropOverlay = document.getElementById('drop-overlay');
const $inputRow    = document.getElementById('input-row');

// Markdown: use marked.js if available, else plain text
let renderMd;
(function loadMarked() {
  const s = document.createElement('script');
  s.src = 'https://cdn.jsdelivr.net/npm/marked@9/marked.min.js';
  s.onload = () => {
    window.marked.setOptions({ breaks: true, gfm: true });
    renderMd = (text) => window.marked.parse(text);
  };
  s.onerror = () => { renderMd = (text) => `<pre>${escHtml(text)}</pre>`; };
  document.head.appendChild(s);
})();

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function safeRender(text) {
  return renderMd ? renderMd(text) : `<pre>${escHtml(text)}</pre>`;
}

// ── Phase sidebar ─────────────────────────────────────────────────────────────
function buildSidebar() {
  $phaseList.innerHTML = '';
  PHASES.forEach(p => {
    const li = document.createElement('li');
    li.id = `ph-${p.n}`;
    li.innerHTML = `<span class="ph-num">${p.n}</span>${p.label}`;
    $phaseList.appendChild(li);
  });
}

function setPhase(n) {
  if (n === currentPhase) return;
  currentPhase = n;
  const total = PHASES.length - 1;
  const pct   = Math.round((n / total) * 100);
  $phaseFill.style.width = pct + '%';
  $phaseName.textContent = PHASES[n]?.label ?? `Phase ${n}`;

  PHASES.forEach(p => {
    const li = document.getElementById(`ph-${p.n}`);
    if (!li) return;
    li.classList.remove('active','done');
    if (p.n === n)  li.classList.add('active');
    if (p.n < n)    li.classList.add('done');
  });
}

// ── WebSocket ─────────────────────────────────────────────────────────────────
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  const url   = `${proto}://${location.host}/ws/${sessionId}`;
  ws = new WebSocket(url);

  ws.addEventListener('open', () => {
    setStatus('online');
    console.log('[WS] connected');
  });

  ws.addEventListener('close', () => {
    setStatus('offline');
    setTimeout(connectWS, 3000);
  });

  ws.addEventListener('error', () => setStatus('offline'));

  ws.addEventListener('message', e => {
    const msg = JSON.parse(e.data);
    handleServerMsg(msg);
  });
}

// ── Server message handler ────────────────────────────────────────────────────
let activeAssistantDiv = null;   // current streaming assistant bubble
let mdBuffer           = '';     // accumulated text for markdown
let activeToolBlock    = null;   // current tool block element

function handleServerMsg(msg) {
  switch (msg.type) {

    case 'text': {
      if (!activeAssistantDiv) startAssistantBubble();
      mdBuffer += msg.content;
      const mdDiv = activeAssistantDiv.querySelector('.md-content');
      mdDiv.innerHTML = safeRender(mdBuffer);
      scrollBottom();
      break;
    }

    case 'phase':
      setPhase(msg.number);
      break;

    case 'tool_start': {
      if (!activeAssistantDiv) startAssistantBubble();
      flushMdBuffer();
      activeToolBlock = createToolBlock(msg.id, msg.name, '…');
      activeAssistantDiv.querySelector('.msg-bubble').appendChild(activeToolBlock);
      scrollBottom();
      break;
    }

    case 'tool_exec': {
      if (activeToolBlock && activeToolBlock.dataset.id === msg.id) {
        const cmdEl = activeToolBlock.querySelector('.tool-cmd');
        if (msg.input?.command) cmdEl.textContent = msg.input.command;
        else if (msg.input?.path) cmdEl.textContent = msg.input.path;
        activeToolBlock.querySelector('.tool-status').textContent = 'running';
        activeToolBlock.querySelector('.tool-status').className = 'tool-status running';
      }
      break;
    }

    case 'tool_output': {
      if (activeToolBlock) {
        const out = activeToolBlock.querySelector('.tool-output');
        const line = document.createElement('span');
        const raw  = msg.content;
        if (/error|fail|exception/i.test(raw)) line.className = 'line-err';
        else if (/success|done|ok|complete/i.test(raw)) line.className = 'line-ok';
        else if (/warn|skip/i.test(raw)) line.className = 'line-warn';
        line.textContent = raw;
        out.appendChild(line);
        out.scrollTop = out.scrollHeight;
        scrollBottom();
      }
      break;
    }

    case 'tool_result': {
      if (activeToolBlock && activeToolBlock.dataset.id === msg.id) {
        const st = activeToolBlock.querySelector('.tool-status');
        st.textContent = 'done';
        st.className = 'tool-status done';
        activeToolBlock = null;
      }
      break;
    }

    case 'done':
      finishGeneration();
      break;

    case 'cleared':
      $messages.innerHTML = '';
      showWelcome();
      currentPhase = -1;
      setPhase(0);
      break;

    case 'pong':
      break;

    case 'error':
      finishGeneration();
      appendError(msg.message);
      break;

    default:
      console.warn('[WS] unknown msg', msg);
  }
}

// ── Message helpers ───────────────────────────────────────────────────────────
function startAssistantBubble() {
  mdBuffer = '';
  const div = document.createElement('div');
  div.className = 'msg assistant';
  div.innerHTML = `
    <div class="msg-avatar">⬡</div>
    <div class="msg-body">
      <div class="msg-bubble">
        <div class="thinking"><span></span><span></span><span></span></div>
        <div class="md-content"></div>
      </div>
      <div class="msg-time">${timeNow()}</div>
    </div>`;
  $messages.appendChild(div);
  activeAssistantDiv = div;
  scrollBottom();
}

function flushMdBuffer() {
  if (!activeAssistantDiv) return;
  const thinking = activeAssistantDiv.querySelector('.thinking');
  if (thinking) thinking.remove();
  mdBuffer = '';
}

function finishGeneration() {
  if (activeAssistantDiv) {
    const thinking = activeAssistantDiv.querySelector('.thinking');
    if (thinking) thinking.remove();
    const mdDiv = activeAssistantDiv.querySelector('.md-content');
    if (mdDiv && mdBuffer) mdDiv.innerHTML = safeRender(mdBuffer);
    activeAssistantDiv = null;
  }
  mdBuffer = '';
  activeToolBlock = null;
  isGenerating = false;
  setStatus('online');
  $sendBtn.disabled = false;
  scrollBottom();
}

function appendUserMsg(text) {
  const div = document.createElement('div');
  div.className = 'msg user';
  div.innerHTML = `
    <div class="msg-avatar">👤</div>
    <div class="msg-body">
      <div class="msg-bubble">${escHtml(text)}</div>
      <div class="msg-time">${timeNow()}</div>
    </div>`;
  $messages.appendChild(div);
  scrollBottom();
}

function appendError(text) {
  const div = document.createElement('div');
  div.className = 'error-msg';
  div.innerHTML = `<strong>Error:</strong> ${escHtml(text)}`;
  $messages.appendChild(div);
  scrollBottom();
}

function createToolBlock(id, name, cmd) {
  const icons = { bash:'$', read_file:'📄', write_file:'✏️' };
  const icon  = icons[name] ?? '🔧';
  const div   = document.createElement('div');
  div.className = 'tool-block';
  div.dataset.id = id;
  div.innerHTML = `
    <div class="tool-header">
      <span class="tool-icon">${icon}</span>
      <span class="tool-name">${escHtml(name)}</span>
      <span class="tool-cmd">${escHtml(cmd)}</span>
      <span class="tool-status running">running</span>
      <span class="tool-chevron">▾</span>
    </div>
    <div class="tool-output"></div>`;
  div.querySelector('.tool-header').addEventListener('click', () => {
    div.classList.toggle('collapsed');
  });
  return div;
}

function showWelcome() {
  $messages.innerHTML = `
    <div class="welcome">
      <div class="welcome-icon">⬡</div>
      <h2>PROMET Android Security Analysis</h2>
      <p>Upload an APK or type a command below. PROMET will walk through the full 13-phase RE workflow — static triage, dynamic instrumentation, Frida hooks, and PoC development.</p>
      <div class="welcome-hints">
        <div class="hint-chip" onclick="sendHint(this)">📋 Read all .md files and confirm environment is ready</div>
        <div class="hint-chip" onclick="sendHint(this)">🔧 Run baseline health check: doctor + status</div>
        <div class="hint-chip" onclick="sendHint(this)">📦 Drop an APK below or click 📎 to begin full assessment</div>
      </div>
    </div>`;
}

window.sendHint = function(el) {
  $input.value = el.textContent.replace(/^[^\s]+\s/, '').trim();
  $input.dispatchEvent(new Event('input'));
  sendMessage();
};

// ── Send ──────────────────────────────────────────────────────────────────────
function sendMessage() {
  if (isGenerating) return;
  const text = $input.value.trim();
  if (!text && !pendingApk) return;

  const welcome = $messages.querySelector('.welcome');
  if (welcome) welcome.remove();

  appendUserMsg(pendingApk ? `${text}\n\n📦 ${pendingApk.filename}` : text);
  $input.value = '';
  resizeInput();

  isGenerating = true;
  setStatus('busy');
  $sendBtn.disabled = true;

  ws.send(JSON.stringify({
    type: 'chat',
    message: text,
    apk_path: pendingApk?.path ?? null,
  }));

  clearApk();
}

// ── APK upload ────────────────────────────────────────────────────────────────
async function uploadApk(file) {
  if (!file.name.endsWith('.apk')) {
    appendError('Only .apk files are supported');
    return;
  }
  const fd = new FormData();
  fd.append('file', file);
  try {
    const res = await fetch('/api/upload', { method: 'POST', body: fd });
    if (!res.ok) throw new Error(await res.text());
    const data = await res.json();
    pendingApk = { filename: data.filename, path: data.path };
    $apkName.textContent = `📦 ${data.filename} (${(data.size/1024).toFixed(1)} KB)`;
    $apkBadge.classList.remove('hidden');
    $input.placeholder = 'Message to send with APK…';
  } catch (e) {
    appendError(`APK upload failed: ${e.message}`);
  }
}

function clearApk() {
  pendingApk = null;
  $apkBadge.classList.add('hidden');
  $apkName.textContent = '';
  $input.placeholder = 'Message PROMET… or drop an APK to begin';
}

// ── Input auto-resize ─────────────────────────────────────────────────────────
function resizeInput() {
  $input.style.height = 'auto';
  $input.style.height = Math.min($input.scrollHeight, 180) + 'px';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function setStatus(s) {
  $statusDot.className = 'status-dot ' + s;
  $statusDot.title = { online:'Connected', offline:'Disconnected', busy:'Generating…' }[s] ?? s;
}
function scrollBottom() {
  const cp = document.getElementById('chat-panel');
  cp.scrollTop = cp.scrollHeight;
}
function timeNow() {
  return new Date().toLocaleTimeString([], { hour:'2-digit', minute:'2-digit' });
}

// ── Settings modal ────────────────────────────────────────────────────────────
async function loadConfig() {
  try {
    const res = await fetch('/api/config');
    const cfg = await res.json();

    // Show active shell in settings
    const shellInput = document.getElementById('shell-input');
    if (cfg.shell) shellInput.value = cfg.shell;
    const modelInput = document.getElementById('model-input');
    if (cfg.model) modelInput.value = cfg.model;

    // Mode badge in header
    const logoSub = document.querySelector('.logo-sub');
    if (logoSub) {
      if (cfg.mode === 'api') {
        logoSub.textContent = 'Android RE · API';
        logoSub.style.color = 'var(--accent)';
      } else if (cfg.mode === 'cli') {
        logoSub.textContent = 'Android RE · CLI ✓';
        logoSub.style.color = '#60a5fa';
      } else {
        logoSub.textContent = 'Android RE · Setup needed';
        logoSub.style.color = 'var(--warn)';
      }
    }

    // Mode info inside settings modal
    const modeInfo = document.getElementById('mode-info');
    if (modeInfo) {
      if (cfg.mode === 'api') {
        modeInfo.textContent = '✓ Using Anthropic API (API key found)';
        modeInfo.className = 'field-hint ok';
      } else if (cfg.mode === 'cli') {
        modeInfo.textContent = `✓ Using Claude Code CLI — no API key needed (${cfg.claude_bin})`;
        modeInfo.className = 'field-hint ok';
      } else {
        modeInfo.textContent = '✗ No API key and Claude Code CLI not found';
        modeInfo.className = 'field-hint err';
      }
    }

    // Only force open settings if nothing works
    if (cfg.mode === 'none') {
      document.getElementById('settings-overlay').classList.remove('hidden');
    }
  } catch { /* ignore */ }
}

async function saveApiKey() {
  const key = document.getElementById('api-key-input').value.trim();
  if (!key) return;
  const hint = document.getElementById('api-key-status');
  try {
    const res = await fetch('/api/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ api_key: key }),
    });
    if (!res.ok) throw new Error(await res.text());
    hint.textContent = '✓ API key saved';
    hint.className = 'field-hint ok';
    setTimeout(() => document.getElementById('settings-overlay').classList.add('hidden'), 800);
  } catch (e) {
    hint.textContent = `✗ ${e.message}`;
    hint.className = 'field-hint err';
  }
}

// ── Event listeners ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  buildSidebar();
  showWelcome();
  connectWS();
  loadConfig();
  setPhase(0);

  // Send on Enter (Shift+Enter = newline)
  $input.addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  });
  $input.addEventListener('input', resizeInput);
  $sendBtn.addEventListener('click', sendMessage);

  // APK remove badge
  $apkRemove.addEventListener('click', clearApk);

  // File picker
  $fileInput.addEventListener('change', () => {
    if ($fileInput.files[0]) uploadApk($fileInput.files[0]);
    $fileInput.value = '';
  });

  // Drag and drop
  document.addEventListener('dragover', e => { e.preventDefault(); $dropOverlay.classList.add('active'); });
  document.addEventListener('dragleave', e => { if (!e.relatedTarget) $dropOverlay.classList.remove('active'); });
  document.addEventListener('drop', e => {
    e.preventDefault();
    $dropOverlay.classList.remove('active');
    const file = e.dataTransfer.files[0];
    if (file) uploadApk(file);
  });

  // Clear button
  document.getElementById('btn-clear').addEventListener('click', () => {
    if (isGenerating) return;
    ws.send(JSON.stringify({ type: 'clear' }));
  });

  // Settings
  document.getElementById('btn-settings').addEventListener('click', () => {
    document.getElementById('settings-overlay').classList.remove('hidden');
  });
  document.getElementById('settings-close').addEventListener('click', () => {
    document.getElementById('settings-overlay').classList.add('hidden');
  });
  document.getElementById('api-key-save').addEventListener('click', saveApiKey);
  document.getElementById('api-key-input').addEventListener('keydown', e => {
    if (e.key === 'Enter') saveApiKey();
  });

  // Close modal on backdrop click
  document.getElementById('settings-overlay').addEventListener('click', e => {
    if (e.target === document.getElementById('settings-overlay'))
      document.getElementById('settings-overlay').classList.add('hidden');
  });
});
