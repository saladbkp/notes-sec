const http = require('http');
const fs = require('fs');
const path = require('path');

const logPath = path.join(process.cwd(), 'logs', 'ip_blocking.txt');

// Helper to make a request
function makeRequest(i) {
    return new Promise((resolve) => {
        const req = http.request({
            hostname: 'localhost',
            port: 3333,
            path: '/auth/login',
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                console.log(`Req ${i}: Status ${res.statusCode}`);
                resolve(res.statusCode);
            });
        });
        
        req.on('error', (e) => {
            console.error(`Req ${i} Error:`, e.message);
            resolve(500);
        });
        
        // Send bad credentials to trigger recordFailure
        req.write(JSON.stringify({ email: 'admin@example.com', authPassword: 'wrongpassword' }));
        req.end();
    });
}

async function run() {
    console.log('Triggering IP block...');
    // Block threshold is 3. We send 5 requests to be sure.
    for (let i = 1; i <= 5; i++) {
        await makeRequest(i);
        await new Promise(r => setTimeout(r, 200)); // Small delay
    }

    console.log('Checking for log file...');
    if (fs.existsSync(logPath)) {
        console.log('SUCCESS: ip_blocking.txt exists!');
        const content = fs.readFileSync(logPath, 'utf8');
        console.log('Log Content:\n', content);
    } else {
        console.log('FAILURE: ip_blocking.txt NOT found.');
    }
}

run();
