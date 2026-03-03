import fs from 'fs';
import path from 'path';
import sharp from 'sharp';

const filePath = '/Users/hongruiyi/Desktop/notes-sec/logs/evidence_1772465608243_login_fail_ngy5q.png';

async function compressImage(filePath, maxWidth = 320, initialQuality = 60) {
    try {
        console.log(`Reading file: ${filePath}`);
        const originalBuffer = fs.readFileSync(filePath);
        console.log(`Original size: ${originalBuffer.length} bytes`);

        let width = maxWidth;
        let quality = initialQuality;
        let outputBuffer = null;
        let outputBase64 = null;

        for (let i = 0; i < 5; i++) {
            console.log(`Attempt ${i + 1}: Resize to width ${width}, quality ${quality}`);
            
            outputBuffer = await sharp(originalBuffer)
                .resize({ width: width })
                .jpeg({ quality: quality })
                .toBuffer();

            outputBase64 = `data:image/jpeg;base64,${outputBuffer.toString('base64')}`;
            
            if (outputBase64.length < 40000) {
                console.log(`Success! Compressed size: ${outputBase64.length} chars (approx ${Math.round(outputBuffer.length / 1024)} KB)`);
                console.log(`Final dimensions: width=${width}, quality=${quality}`);
                
                // Save the result for verification
                const outputPath = path.join(path.dirname(filePath), 'compressed_test.jpg');
                fs.writeFileSync(outputPath, outputBuffer);
                console.log(`Saved compressed file to: ${outputPath}`);
                return;
            }

            console.log(`Result too large: ${outputBase64.length} chars. Retrying...`);
            
            // Aggressively reduce size/quality if too large
            width = Math.floor(width * 0.7);
            quality = Math.max(10, quality - 10);
        }

        console.log('Failed to compress image below 40000 chars after 5 attempts');
    } catch (error) {
        console.error('Error compressing image:', error);
    }
}

compressImage(filePath);
