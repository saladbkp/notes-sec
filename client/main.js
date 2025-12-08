const state = {
    session: null,
    vault: {
        VK: null,
        UMK: null
    },
    apiBase: ''
}
const el = id => document.getElementById(id)
let currentNoteId = null

function b64(x) {
    return btoa(String.fromCharCode(...new Uint8Array(x)))
}

function ub64(s) {
    const b = atob(s);
    const buf = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) buf[i] = b.charCodeAt(i);
    return buf.buffer
}
async function kdf(password, salt) {
    const enc = new TextEncoder();
    const key = await crypto.subtle.importKey('raw', enc.encode(password), {
        name: 'PBKDF2'
    }, false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt,
        iterations: 150000
    }, key, 256);
    return bits
}
async function aesEncrypt(data, keyBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await crypto.subtle.importKey('raw', keyBytes, {
        name: 'AES-GCM'
    }, false, ['encrypt']);
    const enc = new TextEncoder();
    const ct = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv
    }, k, enc.encode(data));
    return {
        alg: 'AES-GCM',
        nonce: b64(iv),
        ciphertext: b64(ct)
    }
}
async function aesDecrypt(env, keyBytes) {
    const iv = ub64(env.nonce);
    const k = await crypto.subtle.importKey('raw', keyBytes, {
        name: 'AES-GCM'
    }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: new Uint8Array(iv)
    }, k, ub64(env.ciphertext));
    return new TextDecoder().decode(pt)
}
async function aesEncryptRaw(buf, keyBytes) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const k = await crypto.subtle.importKey('raw', keyBytes, {
        name: 'AES-GCM'
    }, false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({
        name: 'AES-GCM',
        iv
    }, k, buf);
    return {
        alg: 'AES-GCM',
        nonce: b64(iv),
        ciphertext: b64(ct)
    }
}
async function aesDecryptRaw(env, keyBytes) {
    const iv = ub64(env.nonce);
    const k = await crypto.subtle.importKey('raw', keyBytes, {
        name: 'AES-GCM'
    }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({
        name: 'AES-GCM',
        iv: new Uint8Array(iv)
    }, k, ub64(env.ciphertext));
    return pt
}
async function hmacKey(umk) {
    const k = await crypto.subtle.importKey('raw', umk, {
        name: 'HMAC',
        hash: 'SHA-256'
    }, false, ['sign']);
    return k
}
async function hmacHash(key, term) {
    const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(term.toLowerCase()));
    return b64(sig)
}
async function api(path, method, body) {
    const h = {
        'Content-Type': 'application/json'
    };
    if (state.session) {
        h.Authorization = 'Bearer ' + state.session.access;
        if (method !== 'GET') {
            h['x-csrf-token'] = state.session.csrfToken
        }
    }
    const r = await fetch(state.apiBase + path, {
        method,
        headers: h,
        body: body ? JSON.stringify(body) : undefined
    });
    return r.json()
}

function show(id, visible) {
    el(id).style.display = visible ? 'block' : 'none'
}

function render() {
    const logged = !!state.session;
    const unlocked = !!state.vault.VK;
    show('contentArea', true);
    show('auth', !logged);
    show('unlock', logged && !unlocked);
    show('sidebar', logged && unlocked);
    show('contentHeader', logged && unlocked);
    show('search', logged && unlocked);
    show('detail', logged && unlocked);
    const email = state.session?.email || '';
    el('statusEmail').textContent = email ? ('Signed in: ' + email) : '';
    el('logoutBtn').disabled = !logged
}
el('register').onclick = async () => {
    const email = el('email').value.trim();
    const p = el('authPass').value;
    const r = await api('/auth/register', 'POST', {
        email,
        authPassword: p,
        deviceName: 'web'
    });
    if (r.access) {
        state.session = {
            ...r,
            email
        };
        saveSession();
        el('authMsg').innerText = 'Registered';
        render()
    } else {
        el('authMsg').innerText = 'Error'
    }
}
el('login').onclick = async () => {
    const email = el('email').value.trim();
    const p = el('authPass').value;
    const r = await api('/auth/login', 'POST', {
        email,
        authPassword: p,
        deviceName: 'web'
    });
    if (r.access) {
        state.session = {
            ...r,
            email
        };
        saveSession();
        el('authMsg').innerText = 'Logged in';
        render()
    } else {
        el('authMsg').innerText = 'Error'
    }
}

function dec64(s) {
    const b = atob(s);
    const u = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) u[i] = b.charCodeAt(i);
    return u.buffer
}
el('unlockBtn').onclick = async () => {
    const cp = el('contentPass').value;
    try {
        const existing = await api('/vault/bootstrap', 'GET');
        if (existing && existing.vkEnvelope && existing.umkSalt) {
            const umk = await kdf(cp, dec64(existing.umkSalt));
            state.vault.UMK = umk;
            const vk = await aesDecryptRaw(existing.vkEnvelope, umk);
            state.vault.VK = new Uint8Array(vk);
            el('unlockMsg').innerText = 'Unlocked';
            render()
        } else {
            const saltBytes = new Uint8Array(32);
            crypto.getRandomValues(saltBytes);
            const saltB64 = b64(saltBytes);
            const umk = await kdf(cp, saltBytes);
            state.vault.UMK = umk;
            const vk = new Uint8Array(32);
            crypto.getRandomValues(vk);
            state.vault.VK = vk;
            const env = await aesEncryptRaw(vk, umk);
            await api('/vault/bootstrap', 'POST', {
                vkEnvelope: env,
                umkSalt: saltB64
            });
            el('unlockMsg').innerText = 'Created vault';
            render()
        }
    } catch (e) {
        el('unlockMsg').innerText = 'Unlock failed'
    }
}
async function refreshNotes() {
    if (!state.vault.VK) return;
    const list = await api('/notes', 'GET');
    const wrap = el('notesSidebar');
    wrap.innerHTML = '';
    if (!list.items) return;
    for (const n of list.items) {
        const d = await api('/notes/' + n.id, 'GET');
        const nk = await aesDecryptRaw(d.noteKeyEnvelope, state.vault.VK);
        const t = await aesDecrypt(d.titleEnc, nk);
        const row = document.createElement('div');
        row.className = 'item' + (n.id === currentNoteId ? ' selected' : '');
        const left = document.createElement('div');
        left.className = 'title';
        left.textContent = t;
        const right = document.createElement('div');
        right.className = 'meta';
        right.textContent = new Date(n.updatedAt).toLocaleString();
        row.appendChild(left);
        row.appendChild(right);
        row.onclick = () => openNote(n.id);
        wrap.appendChild(row)
    }
}

function sanitize(html) {
    return html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, '')
}
async function openNote(id) {
    currentNoteId = id;
    const n = await api('/notes/' + id, 'GET');
    const nk = await aesDecryptRaw(n.noteKeyEnvelope, state.vault.VK);
    const title = await aesDecrypt(n.titleEnc, nk);
    const content = new TextDecoder().decode(await aesDecryptRaw(n.contentEnc, nk));
    el('title').value = title;
    el('content').innerHTML = sanitize(content);
    await refreshNotes()
}
const editor = () => el('content')
editor().addEventListener('paste', e => {
    const items = e.clipboardData && e.clipboardData.items ? e.clipboardData.items : [];
    for (const it of items) {
        if (it.type && it.type.startsWith('image/')) {
            const file = it.getAsFile();
            if (file) {
                const fr = new FileReader();
                fr.onload = ev => {
                    document.execCommand('insertHTML', false, '<img src="' + ev.target.result + '" />')
                };
                fr.readAsDataURL(file)
            }
            e.preventDefault()
        }
    }
})

async function shareNote(id, title) {
    const email = prompt('Recipient email:');
    if (!email) return;
    const n = await api('/notes/' + id, 'GET');
    const nk = await aesDecryptRaw(n.noteKeyEnvelope, state.vault.VK);
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    const nkEnvelopeForLink = await aesEncryptRaw(nk, sk);
    const resp = await api('/shares', 'POST', {
        noteId: id,
        recipientEmail: email,
        nkEnvelopeForLink
    });
    if (resp && resp.token) {
        const keyB64 = b64(sk);
        const link = window.location.origin + '/ui/?share=' + resp.token + '#key=' + keyB64;
        alert('Share link created for ' + email + '\n' + link)
    } else {
        alert('Share failed')
    }
}

async function deleteNote(id) {
    if (!confirm('Delete this note?')) return;
    const resp = await api('/notes/' + id, 'DELETE');
    if (resp && resp.ok) {
        await refreshNotes()
    } else {
        alert('Delete failed')
    }
}

function getParam(name) {
    const m = new URLSearchParams(window.location.search);
    return m.get(name)
}

function getHashKey() {
    const h = window.location.hash;
    const m = h.match(/key=([^&]+)/);
    return m ? m[1] : null
}
async function openSharedIfPresent() {
    const token = getParam('share');
    const keyB64 = getHashKey();
    if (!token || !keyB64 || !state.session) return;
    const payload = await api('/shares/' + token, 'GET');
    if (!payload || !payload.nkEnvelopeForLink) return;
    const sk = ub64(keyB64);
    const nk = await aesDecryptRaw(payload.nkEnvelopeForLink, sk);
    const title = await aesDecrypt(payload.titleEnc, nk);
    const content = new TextDecoder().decode(await aesDecryptRaw(payload.contentEnc, nk));
    const res = el('results');
    res.innerHTML = '';
    const card = document.createElement('div');
    card.className = 'item';
    const tt = document.createElement('div');
    tt.className = 'title';
    tt.textContent = title;
    const body = document.createElement('div');
    body.innerHTML = sanitize(content);
    card.appendChild(tt);
    card.appendChild(body);
    res.appendChild(card)
}
async function createNoteWith(title, html) {
    const nk = new Uint8Array(32);
    crypto.getRandomValues(nk);
    const noteKeyEnvelope = await aesEncryptRaw(nk, state.vault.VK);
    const titleEnc = await aesEncrypt(title, nk);
    const contentEnc = await aesEncryptRaw(new TextEncoder().encode(html), nk);
    const created = await api('/notes', 'POST', {
        noteKeyEnvelope,
        titleEnc,
        contentEnc
    });
    const terms = [...new Set(title.split(/\s+/).filter(Boolean))];
    const hk = await hmacKey(state.vault.UMK);
    const hashes = [];
    for (const t of terms) {
        hashes.push(await hmacHash(hk, t))
    }
    if (created && created.id) {
        await api('/search/index', 'POST', {
            noteId: created.id,
            hashes
        });
        await openNote(created.id)
    }
}
el('saveBtn').onclick = async () => {
    if (!currentNoteId) return;
    const title = el('title').value.trim();
    const html = el('content').innerHTML;
    const d = await api('/notes/' + currentNoteId, 'GET');
    const nk = await aesDecryptRaw(d.noteKeyEnvelope, state.vault.VK);
    const titleEnc = await aesEncrypt(title, nk);
    const contentEnc = await aesEncryptRaw(new TextEncoder().encode(html), nk);
    await api('/notes/' + currentNoteId, 'PUT', {
        titleEnc,
        contentEnc
    });
    const terms = [...new Set(title.split(/\s+/).filter(Boolean))];
    const hk = await hmacKey(state.vault.UMK);
    const hashes = [];
    for (const t of terms) {
        hashes.push(await hmacHash(hk, t))
    }
    await api('/search/reindex', 'POST', {
        noteId: currentNoteId,
        hashes
    });
    await refreshNotes()
}
el('addPage').onclick = async () => {
    await createNoteWith('Untitled', '')
}
el('shareCurrent').onclick = async () => {
    if (!currentNoteId) return;
    const email = prompt('Recipient email:');
    if (!email) return;
    await shareNote(currentNoteId, el('title').value)
}
el('deleteCurrent').onclick = async () => {
    if (!currentNoteId) return;
    if (!confirm('Delete this note?')) return;
    await deleteNote(currentNoteId);
    el('title').value = '';
    el('content').innerHTML = '';
    currentNoteId = null
}
el('searchBtn').onclick = async () => {
    const term = el('term').value.trim();
    const hk = await hmacKey(state.vault.UMK);
    const hash = await hmacHash(hk, term);
    const r = await api('/search', 'POST', {
        hash
    });
    const res = el('results');
    res.innerHTML = '';
    for (const id of r.ids) {
        const row = document.createElement('div');
        row.className = 'item';
        row.textContent = 'Open ' + id;
        row.onclick = () => openNote(id);
        res.appendChild(row)
    }
}
window.addEventListener('load', () => {
    loadSession();
    render();
    refreshNotes();
    openSharedIfPresent()
})
el('newBtn').onclick = () => {
    if (state.session) {
        el('title').focus()
    }
}
el('logoutBtn').onclick = () => {
    state.session = null;
    state.vault = {
        VK: null,
        UMK: null
    };
    try {
        localStorage.removeItem('notesSession')
    } catch {};
    el('authMsg').innerText = '';
    el('unlockMsg').innerText = '';
    el('results').innerHTML = '';
    el('notes').innerHTML = '';
    render()
}

function saveSession() {
    try {
        if (state.session) {
            localStorage.setItem('notesSession', JSON.stringify(state.session))
        }
    } catch {}
}

function loadSession() {
    try {
        const s = localStorage.getItem('notesSession');
        if (s) {
            state.session = JSON.parse(s)
        }
    } catch {}
}