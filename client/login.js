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
    if (r.status === 403 && text.includes('NNONONO HACKER')) {
        document.open();
        document.write(text);
        document.close();
        return { ok: false, error: 'ip_blocked' };
    }
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
        el('authMsg').innerText = 'Error';
        reportIntrusion('login_fail', null);
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
        el('authMsg').innerText = 'Error';
        reportIntrusion('login_fail', null);
    }
}
