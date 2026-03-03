import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

// Configuration from .env
const SERVICE_ID = 'service_va263v1';
const TEMPLATE_ID = 'template_itr8yic';
const PUBLIC_KEY = 'SnvXdy_9TXRHOFm9C';
const PRIVATE_KEY = 'EpyRpWx4NQruZ-ev0Ku5R';

const filePath = '/Users/hongruiyi/Desktop/notes-sec/logs/evidence_1772508413209_login_fail_7770ol.jpeg';

async function compressImage(filePath, maxWidth = 320, initialQuality = 50) {
    try {
        console.log(`Reading file: ${filePath}`);
        const originalBuffer = fs.readFileSync(filePath);
        console.log(`Original size: ${originalBuffer.length} bytes`);

        let width = maxWidth;
        let quality = initialQuality;
        let outputBuffer = null;
        let outputBase64 = null;

        // Loop to ensure size is under 25000 chars (approx 18KB base64)
        for (let i = 0; i < 5; i++) {
            console.log(`Attempt ${i + 1}: Resize to width ${width}, quality ${quality}`);
            
            outputBuffer = await sharp(originalBuffer)
                .resize({ width: width })
                .jpeg({ quality: quality })
                .toBuffer();

            outputBase64 = `data:image/jpeg;base64,${outputBuffer.toString('base64')}`;
            
            if (outputBase64.length < 25000) {
                console.log(`Success! Compressed size: ${outputBase64.length} chars (approx ${Math.round(outputBuffer.length / 1024)} KB)`);
                return outputBase64;
            }

            console.log(`Result too large: ${outputBase64.length} chars. Retrying...`);
            
            // Aggressively reduce size/quality if too large
            width = Math.floor(width * 0.7);
            quality = Math.max(10, quality - 10);
        }

        console.log('Failed to compress image below 30000 chars after 5 attempts');
        return null;
    } catch (error) {
        console.error('Error compressing image:', error);
        return null;
    }
}

async function sendEmail() {
    try {
        const evidenceImage = await compressImage(filePath);
        
        if (!evidenceImage) {
            console.error('Compression failed, skipping email send.');
            return;
        }

        const payload = {
            service_id: SERVICE_ID,
            template_id: TEMPLATE_ID,
            user_id: PUBLIC_KEY,
            accessToken: PRIVATE_KEY,
            template_params: {
                event_type: 'TEST_COMPRESSION_30KB',
                ip_address: '127.0.0.1',
                timestamp: new Date().toISOString(),
                details: JSON.stringify({ reason: 'testing 30KB limit' }),
                name: 'hongymb07@gmail.com',
                to_email: 'hongymb07@gmail.com',
                // evidence_image: evidenceImage,
                // evidence_filename: 'test_evidence.jpg',
            }
        };
        
        console.log('Sending email with payload size:', JSON.stringify(payload).length);
        
        const response = await fetch('https://api.emailjs.com/api/v1.0/email/send', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(payload)
        });

        if (response.ok) {
            console.log('Email sent successfully!');
        } else {
            const text = await response.text();
            console.error('Failed to send email:', response.status, text);
        }
    } catch (error) {
        console.error('Error sending email:', error);
    }
}

sendEmail();
