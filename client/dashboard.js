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
let searchTerm = ''

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
    if (!env || env.alg === 'PLAIN') {
        return new TextEncoder().encode(env?.data || '')
    }
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
async function api(path, method, body) {
    const h = { 'Content-Type': 'application/json' };
    if (state.session) { h.Authorization = 'Bearer ' + state.session.access; if (method !== 'GET') { h['x-csrf-token'] = state.session.csrfToken } }
    const r = await fetch(path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    const ct = (r.headers.get('content-type') || '').toLowerCase();
    if (ct.includes('application/json')) {
        try { return JSON.parse(text || '{}') } catch { return { ok: false, error: 'parse_error', status: r.status, body: text } }
    }
    return r.ok ? { ok: true, raw: text } : { ok: false, status: r.status, body: text }
}

function show(id, visible) {
    const n = el(id);
    if (n) n.style.display = visible ? 'block' : 'none'
}

function render() {
    const logged = !!state.session;
    show('contentArea', logged);
    show('sidebar', logged);
    const email = state.session?.email || '';
    el('statusEmail').textContent = email ? ('Signed in: ' + email) : '';
    el('logoutBtn').disabled = !logged
}

function sanitize(html) {
    return html.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '').replace(/<iframe[^>]*>[\s\S]*?<\/iframe>/gi, '')
}
async function refreshNotes() {
    const list = await api('/notes', 'GET');
    const wrap = el('notesSidebar');
    wrap.innerHTML = '';
    if (!list.items) return;
    let items = list.items;
    try {
        if (searchTerm) {
            const rx = new RegExp(searchTerm, 'i');
            items = items.filter(x => (x.titlePlain || '').match(rx))
        }
    } catch {}
    for (const n of items) {
        const title = n.titlePlain || '(encrypted)';
        const row = document.createElement('div');
        row.className = 'item' + (n.id === currentNoteId ? ' selected' : '');
        const left = document.createElement('div');
        left.className = 'title';
        left.textContent = title;
        const right = document.createElement('div');
        right.className = 'meta';
        right.textContent = n.protected ? '🔒' : '';
        const actions = document.createElement('div');
        actions.className = 'actions-mini';
        const shareBtn = document.createElement('button');
        shareBtn.title = 'Share';
        shareBtn.textContent = '📤';
        shareBtn.onclick = (e) => {
            e.stopPropagation();
            shareNote(n.id, title)
        };
        const delBtn = document.createElement('button');
        delBtn.title = 'Delete';
        delBtn.textContent = '🗑️';
        delBtn.onclick = (e) => {
            e.stopPropagation();
            deleteNote(n.id)
        };
        actions.appendChild(shareBtn);
        actions.appendChild(delBtn);
        row.appendChild(left);
        row.appendChild(right);
        row.appendChild(actions);
        row.onclick = () => openNote(n.id);
        wrap.appendChild(row)
    }
}
async function openNote(id) {
    currentNoteId = id;
    const n = await api('/notes/' + id, 'GET');
    const title = n.titlePlain || '';
    let html = '';
    if (n.protected) {
        html = '<div style="text-align:center;padding:24px">🔒 Locked — unlock with password</div>'
    } else {
        html = n.contentEnc && n.contentEnc.alg === 'PLAIN' ? n.contentEnc.data : ''
    }
    el('title').value = title;
    el('content').innerHTML = sanitize(html);
    await refreshNotes()
}
async function createNoteWith(title, html) {
    const created = await api('/notes/plain', 'POST', {
        title,
        contentHtml: html
    });
    if (created && created.id) {
        await openNote(created.id);
        const pass = prompt('Set note password now (leave blank to skip)');
        if (pass) {
            const saltBytes = new Uint8Array(32);
            crypto.getRandomValues(saltBytes);
            const saltB64 = b64(saltBytes);
            const key = await kdf(pass, saltBytes);
            const content = el('content').innerHTML || '';
            const contentEnc = await aesEncryptRaw(new TextEncoder().encode(content), key);
            await api('/notes/' + created.id, 'protect', {
                title,
                noteSalt: saltB64,
                contentEnc
            });
            sessionStorage.setItem('notePass:' + created.id, pass);
            await openNote(created.id)
        }
    }
}
el('saveBtn').onclick = async () => {
    openSaveDialog()
}
async function shareNote(id, title) {
    const email = prompt('Recipient email:');
    if (!email) return;
    const n = await api('/notes/' + id, 'GET');
    const sk = new Uint8Array(32);
    crypto.getRandomValues(sk);
    const payload = JSON.stringify(n.contentEnc || {
        alg: 'PLAIN',
        data: ''
    });
    const nkEnvelopeForLink = await aesEncryptRaw(new TextEncoder().encode(payload), sk);
    const resp = await api('/shares', 'POST', {
        noteId: id,
        recipientEmail: email,
        nkEnvelopeForLink
    });
    if (resp && resp.token) {
        const keyB64 = b64(sk);
        const link = window.location.origin + '/dashboard?share=' + resp.token + '#key=' + keyB64;
        alert('Share link created for ' + email + '\n' + link)
    }
}
async function deleteNote(id) {
    if (!confirm('Delete this note?')) return;
    const resp = await api('/notes/' + id, 'DELETE');
    if (resp && resp.ok) {
        if (id === currentNoteId) {
            currentNoteId = null;
            el('title').value = '';
            el('content').innerHTML = ''
        }
        await refreshNotes()
    }
}
function showStatus(ok, msg) {
    const box = document.getElementById('statusBox');
    const card = document.getElementById('statusCard');
    card.textContent = (ok ? '✅ ' : '❌ ') + msg;
    box.style.display = 'flex';
    setTimeout(() => { box.style.display = 'none' }, 1200)
}

function openCreateDialog() {
    const modal = document.getElementById('modal');
    const titleEl = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    const okBtn = document.getElementById('modalOk');
    const cancelBtn = document.getElementById('modalCancel');
    titleEl.textContent = 'Create Note';
    body.innerHTML = '';
    const t = document.createElement('input');
    t.id = 'modalTitleInput';
    t.placeholder = 'Title';
    t.style.width = '100%';
    t.style.margin = '8px 0';
    t.value = 'Untitled';
    const p = document.createElement('input');
    p.id = 'modalPassInput';
    p.type = 'password';
    p.placeholder = 'Set password (optional)';
    p.style.width = '100%';
    p.style.margin = '8px 0';
    body.appendChild(t);
    body.appendChild(p);
    modal.style.display = 'flex';
    function close() {
        modal.style.display = 'none';
        okBtn.onclick = null;
        cancelBtn.onclick = null
    }
    cancelBtn.onclick = () => { close() }
    okBtn.onclick = async () => {
        const title = t.value.trim() || 'Untitled';
        const pass = p.value;
        try {
            const created = await api('/notes/plain', 'POST', { title, contentHtml: '' });
            if (!(created && created.id)) throw new Error('create_fail');
            if (pass) {
                const saltBytes = new Uint8Array(32);
                crypto.getRandomValues(saltBytes);
                const saltB64 = b64(saltBytes);
                const key = await kdf(pass, saltBytes);
                const contentEnc = await aesEncryptRaw(new TextEncoder().encode(''), key);
                await api('/notes/' + created.id + '/protect', 'PUT', { title, noteSalt: saltB64, contentEnc });
                sessionStorage.setItem('notePass:' + created.id, pass)
            }
            showStatus(true, 'Saved');
            close();
            await refreshNotes();
            await openNote(created.id)
        } catch (e) {
            showStatus(false, 'Save failed ' + e.message);
            close()
        }
    }
}

el('addPage').onclick = () => { openCreateDialog() }

function openSaveDialog() {
    if (!currentNoteId) { showStatus(false, 'No note selected'); return }
    const modal = document.getElementById('modal');
    const titleEl = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    const okBtn = document.getElementById('modalOk');
    const cancelBtn = document.getElementById('modalCancel');
    titleEl.textContent = 'Save Note';
    body.innerHTML = '';
    const p = document.createElement('input');
    p.id = 'modalPassInputSave';
    p.type = 'password';
    p.placeholder = 'Set/enter password (optional)';
    p.style.width = '100%';
    p.style.margin = '8px 0';
    body.appendChild(p);
    modal.style.display = 'flex';
    function close() { modal.style.display = 'none'; okBtn.onclick = null; cancelBtn.onclick = null }
    cancelBtn.onclick = () => { close() }
    okBtn.onclick = async () => {
        const title = el('title').value.trim();
        const html = el('content').innerHTML;
        const pass = p.value;
        try {
            if (pass) {
                const saltBytes = new Uint8Array(32);
                crypto.getRandomValues(saltBytes);
                const saltB64 = b64(saltBytes);
                const key = await kdf(pass, saltBytes);
                const contentEnc = await aesEncryptRaw(new TextEncoder().encode(html), key);
                const resp = await api('/notes/' + currentNoteId + '/protect', 'PUT', { title, noteSalt: saltB64, contentEnc });
                console.log("resp"+ resp);
                if (!resp || resp.ok !== true) throw new Error('protect_failed');
                sessionStorage.setItem('notePass:' + currentNoteId, pass)
            } else {
                const resp = await api('/notes/' + currentNoteId + '/plain', 'PUT', { title, contentHtml: html });
                if (!resp || resp.ok !== true) throw new Error('save_failed')
            }
            showStatus(true, 'Saved');
            close();
            await refreshNotes();
            await openNote(currentNoteId)
        } catch (e) {
            showStatus(false, 'Save failed ' + e.message);
            close()
        }
    }
}
el('headerSearchBtn').onclick = () => {
    searchTerm = el('headerSearch').value.trim();
    refreshNotes()
}
el('headerSearch').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        searchTerm = el('headerSearch').value.trim();
        refreshNotes()
    }
})

function loadSession() {
    try {
        const s = localStorage.getItem('notesSession');
        if (s) {
            state.session = JSON.parse(s)
        }
    } catch {}
}
window.addEventListener('load', () => {
    loadSession();
    if (!state.session) {
        location.href = '/login';
        return
    }
    render();
    refreshNotes()
})
el('logoutBtn').onclick = () => {
    try {
        localStorage.removeItem('notesSession')
    } catch {};
    location.href = '/login'
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
