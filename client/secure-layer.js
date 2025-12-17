import { getPinyin, getRandomChar } from './pinyin-map.js';

/**
 * SecureLayer implements Objective 2:
 * "client-side text preprocessing (Pinyin conversion), random mapping, and AES-GCM encryption"
 */
export class SecureLayer {
    /**
     * Preprocesses plaintext into an obfuscated format before encryption.
     * Format: Pinyin Conversion + Random Mapping + Reversible Encoding
     * Output format: `SECURE_V1:<obfuscated_string>`
     */
    static preprocess(plaintext) {
        let result = '';
        for (let i = 0; i < plaintext.length; i++) {
            const char = plaintext[i];
            // Check if Chinese character (Range 4E00-9FFF)
            if (char >= '\u4e00' && char <= '\u9fff') {
                const pinyin = getPinyin(char);
                if (pinyin) {
                    // Pinyin Conversion + Random Mapping
                    // We map the Pinyin to a "spoofed" form but keep the original char encoded for reversibility
                    // Format: {pinyin}|{noise}|{hex}
                    const noise = this.generateNoise(2);
                    const hex = char.charCodeAt(0).toString(16);
                    const logMsg = `Mapping: ${char} -> Pinyin: ${pinyin} -> Noise: ${noise} -> Hex: ${hex} => [${pinyin}~${noise}~${hex}]`;
                    console.log(`[SecureLayer] ${logMsg}`);
                    // Send to server terminal
                    fetch('/debug/log', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ msg: logMsg })
                    }).catch(()=>{});
                    
                    result += `[${pinyin}~${noise}~${hex}]`;
                } else {
                    // Fallback for unknown Chinese chars: treat as normal but wrap
                    result += char;
                }
            } else {
                result += char;
            }
        }
        return 'SECURE_V1:' + result;
    }

    /**
     * Reverses the obfuscation to restore plaintext.
     */
    static postprocess(obfuscatedText) {
        if (!obfuscatedText.startsWith('SECURE_V1:')) {
            return obfuscatedText; // Not processed by this layer
        }
        
        const content = obfuscatedText.substring(10); // Remove prefix
        
        // Regex to find patterns like [wo3~xy~6211]
        // Group 1: Pinyin (ignored during restore), Group 2: Noise, Group 3: Hex
        return content.replace(/\[([^~]+)~([^~]+)~([0-9a-fA-F]+)\]/g, (match, p1, p2, p3) => {
            try {
                return String.fromCharCode(parseInt(p3, 16));
            } catch (e) {
                return match;
            }
        });
    }

    static generateNoise(len) {
        let s = '';
        for (let i = 0; i < len; i++) s += getRandomChar();
        return s;
    }
}
