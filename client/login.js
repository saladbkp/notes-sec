const el = id => document.getElementById(id)

function saveSession(s) {
    try {
        localStorage.setItem('notesSession', JSON.stringify(s))
    } catch {}
}

function loadSession() {
    try {
        const s = localStorage.getItem('notesSession');
        return s ? JSON.parse(s) : null
    } catch {
        return null
    }
}
async function api(path, method, body) {
    const h = { 'Content-Type': 'application/json' };
    const s = loadSession();
    if (s) { h.Authorization = 'Bearer ' + s.access; if (method !== 'GET') { h['x-csrf-token'] = s.csrfToken } }
    const r = await fetch(path, { method, headers: h, body: body ? JSON.stringify(body) : undefined });
    const text = await r.text();
    try {
        const obj = text ? JSON.parse(text) : {};
        if (obj && obj.error === 'unauthorized') { try { localStorage.removeItem('notesSession') } catch {}; location.href = '/login'; return obj }
        return obj
    } catch {
        return { ok: false, error: 'parse_error', status: r.status, body: text }
    }
}
window.addEventListener('load', () => {
    const s = loadSession();
    if (s && s.access) {
        location.href = '/dashboard'
    }
})
el('register').onclick = async () => {
    const email = el('email').value.trim();
    const p = el('authPass').value;
    const r = await api('/auth/register', 'POST', {
        email,
        authPassword: p,
        deviceName: 'web'
    });
    if (r.access) {
        try {
            sessionStorage.setItem('contentPass', p)
        } catch {};
        saveSession({
            ...r,
            email
        });
        location.href = '/dashboard'
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
        try {
            sessionStorage.setItem('contentPass', p)
        } catch {};
        saveSession({
            ...r,
            email
        });
        location.href = '/dashboard'
    } else {
        el('authMsg').innerText = 'Error'
    }
}
