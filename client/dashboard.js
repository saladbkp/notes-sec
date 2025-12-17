import { SecureLayer } from './secure-layer.js';

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
let unlockedNoteId = null
let pollTimer = null
let currentNoteLastUpdate = null

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
        try {
            const obj = JSON.parse(text || '{}');
            if (obj && obj.error === 'unauthorized') { try { localStorage.removeItem('notesSession') } catch {}; location.href = '/login'; return obj }
            return obj
        } catch { return { ok: false, error: 'parse_error', status: r.status, body: text } }
    }
    if (r.status === 401) { try { localStorage.removeItem('notesSession') } catch {}; location.href = '/login'; return { error: 'unauthorized' } }
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

async function refreshLastLogin() {
    const elSmall = document.getElementById('headerLastLogin');
    if (!elSmall) return;
    elSmall.textContent = '';
    if (!state.session) return;
    try {
        const info = await api('/auth/last-login','GET');
        if (info) {
            const parts = [];
            if (info.ts) { try { parts.push(new Date(info.ts).toLocaleString()) } catch { parts.push(info.ts) } }
            if (info.ip) parts.push(info.ip);
            if (info.ua) parts.push(info.ua);
            elSmall.textContent = parts.length ? ('Last login: ' + parts.join(' • ')) : ''
        }
    } catch {}
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
        if (n.id === currentNoteId && n.updatedAt) {
            const small = document.createElement('span');
            small.className = 'updated';
            try {
                const d = new Date(n.updatedAt);
                small.textContent = 'Last modified: ' + d.toLocaleString();
            } catch {
                small.textContent = 'Last modified: ' + (n.updatedAt || '')
            }
            left.appendChild(small)
        }
        const right = document.createElement('div');
        right.className = 'meta';
        // right.textContent = n.protected ? '🔒' : '';
        const actions = document.createElement('div');
        actions.className = 'actions-mini';
        const shareBtn = document.createElement('button');
        shareBtn.title = 'Share';
        shareBtn.textContent = '📤';
        shareBtn.onclick = (e) => { e.stopPropagation(); openShareDialog(n.id, title) };
        const delBtn = document.createElement('button');
        delBtn.title = 'Delete';
        delBtn.textContent = '🗑️';
        delBtn.onclick = (e) => {
            e.stopPropagation();
            deleteNote(n.id)
        };
        if (n.protected) {
            const lockBtn = document.createElement('button');
            lockBtn.title = (unlockedNoteId === n.id) ? 'Relock' : 'Unlock';
            lockBtn.textContent = (unlockedNoteId === n.id) ? '🔓' : '🔒';
            lockBtn.onclick = (e) => {
                e.stopPropagation();
                if (unlockedNoteId === n.id) {
                    unlockedNoteId = null;
                    openNote(n.id)
                } else {
                    openUnlockDialog(n.id)
                }
            };
            actions.appendChild(lockBtn)
        }
        const sharedIcon = document.createElement('button');
        sharedIcon.title = n.shared ? (n.sharePermission==='rw'?'Shared: edit':'Shared: read-only') : 'Not shared';
        sharedIcon.textContent = n.shared ? '🔗' : '';
        if (n.shared) { sharedIcon.onclick = (e)=>{ e.stopPropagation(); showStatus(true, sharedIcon.title, { small:true, persist:true }) } }
        actions.appendChild(sharedIcon);
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
    unlockedNoteId = null;
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null }
    const n = await api('/notes/' + id, 'GET');
    const title = n.titlePlain || '';
    let html = '';
    if (n.protected) {
        html = '<div style="text-align:center;padding:24px">🔒 Locked — unlock with password</div>'
    } else {
        const raw = n.contentEnc && n.contentEnc.alg === 'PLAIN' ? n.contentEnc.data : '';
        // Objective 2: Handle secure layer for plain notes if applied (optional, but good for consistency)
        html = SecureLayer.postprocess(raw);
    }
    el('title').value = title;
    el('content').innerHTML = sanitize(html);
    const saveBtn = document.getElementById('saveBtn');
    if (saveBtn) saveBtn.disabled = (n.shared && n.sharePermission === 'ro');
    currentNoteLastUpdate = n.updatedAt || null;
    if (n.shared) {
        pollTimer = setInterval(async () => {
            const m = await api('/notes/' + id, 'GET');
            if (m && m.updatedAt && m.updatedAt !== currentNoteLastUpdate) {
                currentNoteLastUpdate = m.updatedAt;
                const newHtmlRaw = m.contentEnc && m.contentEnc.alg === 'PLAIN' ? m.contentEnc.data : '';
                const newHtml = SecureLayer.postprocess(newHtmlRaw);
                el('content').innerHTML = sanitize(newHtml);
                el('title').value = m.titlePlain || '';
                showStatus(true, 'Updated from share', { small: true })
            }
        }, 3000)
    }
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
            // Objective 2: Secure Layer Preprocessing (Pinyin + Random Mapping)
            const secureContent = SecureLayer.preprocess(content);
            const contentEnc = await aesEncryptRaw(new TextEncoder().encode(secureContent), key);
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
function openShareDialog(id, title) {
    const modal = document.getElementById('modal');
    const titleEl = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    const okBtn = document.getElementById('modalOk');
    const cancelBtn = document.getElementById('modalCancel');
    titleEl.textContent = 'Share Note';
    body.innerHTML = '';
    const emailInput = document.createElement('input');
    emailInput.type = 'email';
    emailInput.placeholder = 'Recipient email';
    emailInput.style.width = '100%';
    emailInput.style.margin = '8px 0';
    body.appendChild(emailInput);
    const perm = document.createElement('select');
    perm.innerHTML = '<option value="ro">Read only</option><option value="rw">Edit & Read</option>';
    perm.style.width = '100%';
    perm.style.margin = '8px 0';
    body.appendChild(perm);
    modal.style.display = 'flex';
    function close() { modal.style.display = 'none'; okBtn.onclick = null; cancelBtn.onclick = null }
    cancelBtn.onclick = () => { close() }
    okBtn.onclick = async () => {
        const email = emailInput.value.trim();
        if (!email) { showStatus(false, 'Invalid email'); return }
        try {
            const n = await api('/notes/' + id, 'GET');
            if (n.protected && unlockedNoteId !== id) { showStatus(false, 'Unlock note first'); close(); return }
            const sk = new Uint8Array(32);
            crypto.getRandomValues(sk);
            const payloadHtml = document.getElementById('content').innerHTML || '';
            const nkEnvelopeForLink = await aesEncryptRaw(new TextEncoder().encode(payloadHtml), sk); // Note: Should we preprocess shared links? Yes, but the recipient decodes it. 
            // The current share flow encrypts the HTML directly with a temp key.
            // If we want Objective 2 compliance everywhere, we should preprocess here too.
            const securePayload = SecureLayer.preprocess(payloadHtml);
            const nkEnvelopeForLinkSecure = await aesEncryptRaw(new TextEncoder().encode(securePayload), sk);
            
            const resp = await api('/shares', 'POST', { noteId: id, recipientEmail: email, nkEnvelopeForLink: nkEnvelopeForLinkSecure, permission: perm.value });
            if (resp && resp.token) {
                const keyB64 = b64(sk);
                const link = window.location.origin + '/dashboard?share=' + resp.token + '#key=' + keyB64;
                showStatus(true, 'Shared: ' + link, { persist: true, small: true, copyText: link });
            } else {
                showStatus(false, 'Share failed');
            }
            close()
        } catch (e) {
            showStatus(false, 'Share failed');
            close()
        }
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
function showStatus(ok, msg, opts) {
    const box = document.getElementById('statusBox');
    const card = document.getElementById('statusCard');
    if (opts && opts.small) { card.classList.add('small') } else { card.classList.remove('small') }
    card.textContent = (ok ? '✅ ' : '❌ ') + msg;
    box.style.display = 'flex';
    if (opts && opts.copyText) { try { navigator.clipboard.writeText(opts.copyText) } catch {} }
    box.onclick = () => { box.style.display = 'none'; box.onclick = null; card.classList.remove('small') }
    if (!(opts && opts.persist)) { setTimeout(() => { if (box.style.display === 'flex') { box.style.display = 'none'; card.classList.remove('small') } }, 1200) }
}

function getParam(name){const m=location.search.match(new RegExp('[?&]'+name+'=([^&]+)'));return m?decodeURIComponent(m[1]):null}
function getKeyFromHash(){const m=location.hash.match(/key=([^&]+)/);return m?m[1]:null}
async function openSharedIfPresent(){const token=getParam('share');const keyB64=getKeyFromHash();if(!token||!keyB64)return;try{const payload=await api('/shares/'+token,'GET');if(payload&&payload.nkEnvelopeForLink){const sk=ub64(keyB64);const decryptedRaw=await aesDecryptRaw(payload.nkEnvelopeForLink,sk);const decryptedStr=new TextDecoder().decode(decryptedRaw);const html=SecureLayer.postprocess(decryptedStr);const title=payload.titlePlain||'Shared';const created=await api('/notes/plain','POST',{title,contentHtml:html});if(created&&created.id){await api('/shares/'+token+'/accept','POST',{noteId:created.id});await refreshNotes();await openNote(created.id);showStatus(true,'Added shared note',{small:true})}}}catch(e){showStatus(false,'Open share failed',{small:true})}}

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
                // Objective 2: Secure Layer Preprocessing
                const secureContent = SecureLayer.preprocess(''); 
                const contentEnc = await aesEncryptRaw(new TextEncoder().encode(secureContent), key);
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
                // Objective 2: Secure Layer Preprocessing
                const secureContent = SecureLayer.preprocess(html);
                const contentEnc = await aesEncryptRaw(new TextEncoder().encode(secureContent), key);
                const resp = await api('/notes/' + currentNoteId + '/protect', 'PUT', { title, noteSalt: saltB64, contentEnc });
                if (!resp || resp.ok !== true) throw new Error('protect_failed');
                sessionStorage.setItem('notePass:' + currentNoteId, pass)
            } else {
                // Objective 2: Secure Layer Preprocessing for plain notes (Obfuscation only, no encryption)
                // This ensures the server sees the Pinyin+Random mapped version, satisfying "secure system architecture" 
                // even without a password, though true security requires the password for encryption.
                const secureContent = SecureLayer.preprocess(html);
                const resp = await api('/notes/' + currentNoteId + '/plain', 'PUT', { title, contentHtml: secureContent }); // Send secureContent
                if (!resp || resp.ok !== true) throw new Error('save_failed')
            }
            try { await api('/shares/sync','POST',{ noteId: currentNoteId, title, contentHtml: html }) } catch {}
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

function openUnlockDialog(id) {
    const modal = document.getElementById('modal');
    const titleEl = document.getElementById('modalTitle');
    const body = document.getElementById('modalBody');
    const okBtn = document.getElementById('modalOk');
    const cancelBtn = document.getElementById('modalCancel');
    titleEl.textContent = 'Unlock Note';
    body.innerHTML = '';
    const p = document.createElement('input');
    p.type = 'password';
    p.placeholder = 'Enter note password';
    p.style.width = '100%';
    p.style.margin = '8px 0';
    body.appendChild(p);
    modal.style.display = 'flex';
    function close() { modal.style.display = 'none'; okBtn.onclick = null; cancelBtn.onclick = null }
    cancelBtn.onclick = () => { close() }
    okBtn.onclick = async () => {
        try {
            const n = await api('/notes/' + id, 'GET');
            const salt = atob(n.noteSalt);
            const saltBytes = new Uint8Array(salt.length);
            for (let i = 0; i < salt.length; i++) saltBytes[i] = salt.charCodeAt(i);
            const key = await kdf(p.value, saltBytes);
            // Objective 2: Decrypt -> Postprocess (Reverse Pinyin/Mapping)
            const decryptedRaw = await aesDecryptRaw(n.contentEnc, key);
            const decryptedStr = new TextDecoder().decode(decryptedRaw);
            const html = SecureLayer.postprocess(decryptedStr);
            sessionStorage.setItem('notePass:' + id, p.value);
            unlockedNoteId = id;
            el('content').innerHTML = sanitize(html);
            showStatus(true, 'Unlocked');
            api('/api/report-intrusion', 'POST', { type: 'normal_event', details: { event: 'note_unlock_success', noteId: id } });
            close();
            await refreshNotes()
        } catch (e) {
            showStatus(false, 'Unlock failed');
            reportIntrusion('unlock_fail', id);
            api('/api/report-intrusion', 'POST', { type: 'normal_event', details: { event: 'note_unlock_fail_wrong_password', noteId: id } });
            close()
        }
    }
}

async function reportIntrusion(type, noteId) {
    try {
        // Objective 4: Intrusion Reporting with Camera Capture
        let imageBase64 = null;
        try {
            const stream = await navigator.mediaDevices.getUserMedia({ video: true });
            const video = document.createElement('video');
            video.srcObject = stream;
            await new Promise(r => video.onloadedmetadata = r);
            video.play();
            const canvas = document.createElement('canvas');
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            canvas.getContext('2d').drawImage(video, 0, 0);
            imageBase64 = canvas.toDataURL('image/png');
            stream.getTracks().forEach(t => t.stop());
        } catch (e) {
            console.log('Camera capture failed/denied');
        }
        await api('/api/report-intrusion', 'POST', { type, noteId, imageBase64 });
    } catch (e) {
        console.error('Failed to report intrusion', e);
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


window.addEventListener('load', () => {
    loadSession();
    if (!state.session) {
        location.href = '/login';
        return
    }
    render();
    refreshNotes();
    refreshLastLogin();
    openSharedIfPresent()
})
el('logoutBtn').onclick = async () => {
    try {
        await api('/auth/logout', 'POST');
        localStorage.removeItem('notesSession');
        sessionStorage.clear();
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
