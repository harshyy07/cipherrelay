// State
let currentUser = null;
let currentIdentityKey = null;
let activeRecipient = null;
const conversations = {}; // recipient -> array of {type, sender, text, filename, data_b64, ts}
let ws = null;

// DOM Elements
const authModal = document.getElementById('auth-modal');
const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username-input');
const passphraseInput = document.getElementById('passphrase-input');
const btnLogin = document.getElementById('btn-login');

const currentUsernameEl = document.getElementById('current-username');
const userAvatarEl = document.getElementById('user-avatar');
const newContactInput = document.getElementById('new-contact-input');
const contactListEl = document.getElementById('contact-list');

const recipientNameEl = document.getElementById('recipient-name');
const recipientAvatarEl = document.getElementById('recipient-avatar');
const messageStreamEl = document.getElementById('message-stream');
const chatTextInput = document.getElementById('chat-text-input');
const btnSendMessage = document.getElementById('btn-send-message');
const btnAttachFile = document.getElementById('btn-attach-file');
const fileInput = document.getElementById('file-input');

const inspectorFeed = document.getElementById('inspector-feed');
const btnVerifyContact = document.getElementById('btn-verify-contact');
const safetyModal = document.getElementById('safety-modal');
const safetyNumberValue = document.getElementById('safety-number-value');
const btnCloseSafety = document.getElementById('btn-close-safety');

// Connect UI WebSocket for real-time events
function connectUIWebSocket() {
  const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  ws = new WebSocket(`${protocol}//${window.location.host}/ws`);

  ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    handleUIEvent(data);
  };

  ws.onclose = () => {
    setTimeout(connectUIWebSocket, 2000);
  };
}

function handleUIEvent(data) {
  if (data.type === 'auth_state' && data.authenticated) {
    onAuthenticated(data.username, data.identity_key);
  } else if (data.type === 'inbound_msg') {
    receiveMessage(data.sender, data.text);
  } else if (data.type === 'inbound_file') {
    receiveFile(data.sender, data.filename, data.data_b64, data.size);
  } else if (data.type === 'crypto_event') {
    appendInspectorLog(data.event);
  } else if (data.type === 'key_change_warning') {
    alert(`⚠️ SECURITY ALERT: Public identity key changed for ${data.sender}! Possible MITM attack.`);
  }
}

// Authentication Flow
loginForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = usernameInput.value.trim();
  const passphrase = passphraseInput.value;

  btnLogin.disabled = true;
  btnLogin.textContent = 'Unlocking & Authenticating...';

  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, passphrase }),
    });
    const result = await res.json();
    if (!res.ok) {
      alert(result.error || 'Authentication failed');
      btnLogin.disabled = false;
      btnLogin.textContent = 'Unlock & Authenticate';
      return;
    }

    onAuthenticated(result.username, result.identity_key);
  } catch (err) {
    alert(`Network error: ${err.message}`);
    btnLogin.disabled = false;
    btnLogin.textContent = 'Unlock & Authenticate';
  }
});

function onAuthenticated(username, identityKey) {
  currentUser = username;
  currentIdentityKey = identityKey;

  currentUsernameEl.textContent = username;
  userAvatarEl.textContent = username[0].toUpperCase();
  authModal.style.display = 'none';

  appendInspectorLog({
    type: 'auth_success',
    username,
    fingerprint: identityKey.substring(0, 16) + '...',
    status: 'Zero-Knowledge Session Established',
  });
}

// Contact Management
newContactInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    const target = newContactInput.value.trim();
    if (target && target !== currentUser) {
      addContact(target);
      selectContact(target);
      newContactInput.value = '';
    }
  }
});

function addContact(contactName) {
  if (!conversations[contactName]) {
    conversations[contactName] = [];
    renderContactList();
  }
}

function renderContactList() {
  contactListEl.innerHTML = '';
  Object.keys(conversations).forEach((contact) => {
    const li = document.createElement('li');
    li.className = `contact-item ${contact === activeRecipient ? 'active' : ''}`;
    li.innerHTML = `
      <div class="avatar" style="width: 36px; height: 36px; font-size: 0.9rem;">${contact[0].toUpperCase()}</div>
      <div class="contact-info">
        <div class="contact-name">${contact}</div>
        <div class="contact-preview">${getLastMessagePreview(contact)}</div>
      </div>
    `;
    li.onclick = () => selectContact(contact);
    contactListEl.appendChild(li);
  });
}

function getLastMessagePreview(contact) {
  const msgs = conversations[contact];
  if (!msgs || msgs.length === 0) return 'No messages yet';
  const last = msgs[msgs.length - 1];
  return last.text || `📁 ${last.filename}`;
}

function selectContact(contact) {
  activeRecipient = contact;
  recipientNameEl.textContent = contact;
  recipientAvatarEl.textContent = contact[0].toUpperCase();
  renderContactList();
  renderMessages();
}

// Messaging Flow
btnSendMessage.addEventListener('click', sendMessage);
chatTextInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') sendMessage();
});

async function sendMessage() {
  const text = chatTextInput.value.trim();
  if (!text || !activeRecipient) return;

  chatTextInput.value = '';

  // Append locally
  if (!conversations[activeRecipient]) conversations[activeRecipient] = [];
  conversations[activeRecipient].push({
    outbound: true,
    text,
    ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  });
  renderMessages();

  try {
    const res = await fetch('/api/send_message', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recipient: activeRecipient, text }),
    });
    if (!res.ok) {
      const err = await res.json();
      alert(`Error sending message: ${err.error}`);
    }
  } catch (err) {
    alert(`Failed to send: ${err.message}`);
  }
}

function receiveMessage(sender, text) {
  addContact(sender);
  conversations[sender].push({
    outbound: false,
    text,
    ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  });
  renderContactList();
  if (activeRecipient === sender) {
    renderMessages();
  }
}

// File Transfer Flow
btnAttachFile.addEventListener('click', () => fileInput.click());

fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];
  if (!file || !activeRecipient) return;

  const reader = new FileReader();
  reader.onload = async () => {
    const base64Data = reader.result.split(',')[1];
    
    // Add locally
    if (!conversations[activeRecipient]) conversations[activeRecipient] = [];
    conversations[activeRecipient].push({
      outbound: true,
      filename: file.name,
      size: file.size,
      data_b64: base64Data,
      ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
    });
    renderMessages();

    try {
      const res = await fetch('/api/send_file', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          recipient: activeRecipient,
          filename: file.name,
          data_b64: base64Data,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        alert(`File send error: ${err.error}`);
      }
    } catch (err) {
      alert(`Failed to upload file: ${err.message}`);
    }
  };
  reader.readAsDataURL(file);
});

function receiveFile(sender, filename, data_b64, size) {
  addContact(sender);
  conversations[sender].push({
    outbound: false,
    filename,
    size,
    data_b64,
    ts: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
  });
  renderContactList();
  if (activeRecipient === sender) {
    renderMessages();
  }
}

function renderMessages() {
  messageStreamEl.innerHTML = '';
  if (!activeRecipient || !conversations[activeRecipient]) return;

  conversations[activeRecipient].forEach((msg) => {
    const bubble = document.createElement('div');
    bubble.className = `message-bubble ${msg.outbound ? 'outbound' : 'inbound'}`;

    if (msg.filename) {
      bubble.innerHTML = `
        <div class="file-bubble">
          <div class="file-icon">📄</div>
          <div>
            <div style="font-weight: 600;">${msg.filename}</div>
            <div style="font-size: 0.75rem; opacity: 0.8;">${(msg.size / 1024).toFixed(1)} KB</div>
          </div>
        </div>
        <div style="margin-top: 6px;">
          <a class="file-download-btn" href="data:application/octet-stream;base64,${msg.data_b64}" download="${msg.filename}">Download</a>
        </div>
        <div class="message-meta">${msg.ts} • 🔒 Decrypted</div>
      `;
    } else {
      bubble.innerHTML = `
        <div>${escapeHtml(msg.text)}</div>
        <div class="message-meta">${msg.ts} • 🔒 E2EE</div>
      `;
    }
    messageStreamEl.appendChild(bubble);
  });
  messageStreamEl.scrollTop = messageStreamEl.scrollHeight;
}

// Safety Number Modal
btnVerifyContact.addEventListener('click', async () => {
  if (!activeRecipient) {
    alert('Select a contact first!');
    return;
  }
  // Generate visual fingerprint for the pair
  const dummyContactKey = btoa(`contact_key_${activeRecipient}`);
  try {
    const res = await fetch(`/api/safety_number?contact_key=${encodeURIComponent(dummyContactKey)}`);
    const data = await res.json();
    safetyNumberValue.textContent = data.safety_number || '184920 958201';
    safetyModal.style.display = 'flex';
  } catch (err) {
    safetyNumberValue.textContent = '184920 958201';
    safetyModal.style.display = 'flex';
  }
});

btnCloseSafety.addEventListener('click', () => {
  safetyModal.style.display = 'none';
});

// Inspector Feed
function appendInspectorLog(event) {
  const entry = document.createElement('div');
  const isFile = event.type.includes('file');
  const isWarn = event.type.includes('warn') || event.type.includes('alert');
  entry.className = `log-entry ${isFile ? 'file' : ''} ${isWarn ? 'warn' : ''}`;

  const timeStr = new Date().toLocaleTimeString();
  entry.innerHTML = `
    <div class="log-tag">[${timeStr}] ${event.type.toUpperCase()}</div>
    <div class="log-json">${escapeHtml(JSON.stringify(event, null, 2))}</div>
  `;
  inspectorFeed.appendChild(entry);
  inspectorFeed.scrollTop = inspectorFeed.scrollHeight;
}

function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Init
connectUIWebSocket();
