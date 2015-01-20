// JWT Decoder & Validator
class JWTDecoder {
    constructor() {
        this.jwtInput = document.getElementById('jwt-input');
        this.headerContent = document.getElementById('header-content');
        this.payloadContent = document.getElementById('payload-content');
        this.timestampInfo = document.getElementById('timestamp-info');
        this.algorithmSelect = document.getElementById('algorithm-select');
        this.secretInput = document.getElementById('secret-input');
        this.verificationStatus = document.getElementById('verification-status');
        this.errorMessage = document.getElementById('error-message');
        
        this.currentJWT = null;
        this.currentHeader = null;
        this.currentPayload = null;
        
        this.initializeEventListeners();
    }
    
    initializeEventListeners() {
        // Real-time JWT input processing
        this.jwtInput.addEventListener('input', () => {
            this.processJWT();
            this.applyColorCoding();
        });
        
        // Verification controls
        this.algorithmSelect.addEventListener('change', () => {
            this.verifySignature();
        });
        
        this.secretInput.addEventListener('input', () => {
            this.verifySignature();
        });
        
        // Initial color coding setup
        this.jwtInput.addEventListener('keyup', () => this.applyColorCoding());
        this.jwtInput.addEventListener('paste', () => {
            setTimeout(() => this.applyColorCoding(), 10);
        });
    }
    
    processJWT() {
        const jwtString = this.jwtInput.value.trim();
        
        if (!jwtString) {
            this.clearAll();
            return;
        }
        
        try {
            // Basic JWT format validation
            const parts = jwtString.split('.');
            if (parts.length !== 3) {
                throw new Error('Invalid JWT format: must have 3 parts separated by dots');
            }
            
            // Decode header and payload
            const header = this.decodeBase64Url(parts[0]);
            const payload = this.decodeBase64Url(parts[1]);
            
            this.currentJWT = jwtString;
            this.currentHeader = JSON.parse(header);
            this.currentPayload = JSON.parse(payload);
            
            // Update displays
            this.displayHeader(this.currentHeader);
            this.displayPayload(this.currentPayload);
            this.updateAlgorithmSelect();
            this.verifySignature();
            this.hideError();
            
        } catch (error) {
            this.showError(`Invalid JWT: ${error.message}`);
            this.clearDecodedSections();
        }
    }
    
    decodeBase64Url(str) {
        // Add padding if needed
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        
        try {
            return atob(base64);
        } catch (error) {
            throw new Error('Invalid base64 encoding');
        }
    }
    
    displayHeader(header) {
        this.headerContent.textContent = JSON.stringify(header, null, 2);
    }
    
    displayPayload(payload) {
        this.payloadContent.textContent = JSON.stringify(payload, null, 2);
        this.displayTimestamps(payload);
    }
    
    displayTimestamps(payload) {
        const timestampFields = ['iat', 'exp', 'nbf'];
        const timestampInfo = [];
        
        timestampFields.forEach(field => {
            if (payload[field]) {
                const timestamp = payload[field];
                const date = new Date(timestamp * 1000);
                const now = new Date();
                const diff = date.getTime() - now.getTime();
                
                let relativeTime;
                if (Math.abs(diff) < 60000) {
                    relativeTime = 'just now';
                } else if (diff > 0) {
                    relativeTime = this.formatRelativeTime(diff, 'in');
                } else {
                    relativeTime = this.formatRelativeTime(Math.abs(diff), 'ago');
                }
                
                const fieldName = {
                    'iat': 'Issued At',
                    'exp': 'Expires',
                    'nbf': 'Not Before'
                }[field];
                
                timestampInfo.push(`
                    <div class="timestamp-item">
                        <strong>${fieldName}:</strong> ${date.toLocaleString()} (${relativeTime})
                    </div>
                `);
            }
        });
        
        this.timestampInfo.innerHTML = timestampInfo.join('');
    }
    
    formatRelativeTime(milliseconds, prefix) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);
        
        if (days > 0) {
            return `${prefix} ${days} day${days > 1 ? 's' : ''}`;
        } else if (hours > 0) {
            return `${prefix} ${hours} hour${hours > 1 ? 's' : ''}`;
        } else if (minutes > 0) {
            return `${prefix} ${minutes} minute${minutes > 1 ? 's' : ''}`;
        } else {
            return `${prefix} ${seconds} second${seconds > 1 ? 's' : ''}`;
        }
    }
    
    updateAlgorithmSelect() {
        if (this.currentHeader && this.currentHeader.alg) {
            this.algorithmSelect.value = this.currentHeader.alg;
        }
    }
    
    async verifySignature() {
        if (!this.currentJWT || !this.secretInput.value.trim()) {
            this.updateVerificationStatus('not-verified', 'Signature Not Verified');
            return;
        }
        
        try {
            const algorithm = this.algorithmSelect.value;
            const secret = this.secretInput.value.trim();
            const isValid = await this.validateJWTSignature(this.currentJWT, secret, algorithm);
            
            if (isValid) {
                this.updateVerificationStatus('verified', '✔️ Signature Verified');
            } else {
                this.updateVerificationStatus('invalid', '❌ Invalid Signature');
            }
        } catch (error) {
            this.updateVerificationStatus('invalid', `❌ Verification Error: ${error.message}`);
        }
    }
    
    async validateJWTSignature(jwt, secret, algorithm) {
        try {
            // For HMAC algorithms (HS256, HS384, HS512)
            if (algorithm.startsWith('HS')) {
                const encoder = new TextEncoder();
                const secretKey = await crypto.subtle.importKey(
                    'raw',
                    encoder.encode(secret),
                    { name: 'HMAC', hash: this.getHashAlgorithm(algorithm) },
                    false,
                    ['verify']
                );
                
                const parts = jwt.split('.');
                const data = encoder.encode(parts[0] + '.' + parts[1]);
                const signature = this.base64UrlDecode(parts[2]);
                
                return await crypto.subtle.verify('HMAC', secretKey, signature, data);
            }
            
            // For RSA algorithms (RS256, RS384, RS512)
            if (algorithm.startsWith('RS')) {
                const publicKey = await this.importRSAPublicKey(secret, algorithm);
                const parts = jwt.split('.');
                const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
                const signature = this.base64UrlDecode(parts[2]);
                
                return await crypto.subtle.verify(
                    { name: 'RSASSA-PKCS1-v1_5' },
                    publicKey,
                    signature,
                    data
                );
            }
            
            // For ECDSA algorithms (ES256, ES384, ES512)
            if (algorithm.startsWith('ES')) {
                const publicKey = await this.importECDSAPublicKey(secret, algorithm);
                const parts = jwt.split('.');
                const data = new TextEncoder().encode(parts[0] + '.' + parts[1]);
                const signature = this.base64UrlDecode(parts[2]);
                
                return await crypto.subtle.verify(
                    { name: 'ECDSA', hash: this.getHashAlgorithm(algorithm) },
                    publicKey,
                    signature,
                    data
                );
            }
            
            throw new Error(`Unsupported algorithm: ${algorithm}`);
        } catch (error) {
            throw new Error(`Signature verification failed: ${error.message}`);
        }
    }
    
    getHashAlgorithm(algorithm) {
        const hashMap = {
            'HS256': 'SHA-256',
            'HS384': 'SHA-384',
            'HS512': 'SHA-512',
            'RS256': 'SHA-256',
            'RS384': 'SHA-384',
            'RS512': 'SHA-512',
            'ES256': 'SHA-256',
            'ES384': 'SHA-384',
            'ES512': 'SHA-512'
        };
        return hashMap[algorithm] || 'SHA-256';
    }
    
    async importRSAPublicKey(pemKey, algorithm) {
        const binaryDer = this.pemToBinary(pemKey);
        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            {
                name: 'RSASSA-PKCS1-v1_5',
                hash: this.getHashAlgorithm(algorithm)
            },
            false,
            ['verify']
        );
    }
    
    async importECDSAPublicKey(pemKey, algorithm) {
        const binaryDer = this.pemToBinary(pemKey);
        const namedCurve = algorithm === 'ES256' ? 'P-256' : 
                          algorithm === 'ES384' ? 'P-384' : 'P-521';
        
        return await crypto.subtle.importKey(
            'spki',
            binaryDer,
            {
                name: 'ECDSA',
                namedCurve: namedCurve
            },
            false,
            ['verify']
        );
    }
    
    pemToBinary(pem) {
        const base64 = pem
            .replace(/-----BEGIN.*-----/g, '')
            .replace(/-----END.*-----/g, '')
            .replace(/\s/g, '');
        
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    base64UrlDecode(str) {
        let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        while (base64.length % 4) {
            base64 += '=';
        }
        
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }
    
    updateVerificationStatus(status, message) {
        this.verificationStatus.textContent = message;
        this.verificationStatus.className = `verification-status ${status}`;
    }
    
    applyColorCoding() {
        const text = this.jwtInput.value;
        const parts = text.split('.');
        
        if (parts.length === 3) {
            // Create a temporary div to apply color coding
            const coloredText = `<span class="jwt-header">${parts[0]}</span>.<span class="jwt-payload">${parts[1]}</span>.<span class="jwt-signature">${parts[2]}</span>`;
            
            // Note: Direct HTML manipulation in textarea is not possible
            // This is a limitation - we'll use CSS classes on the sections instead
            // The color coding will be visual feedback through the section borders
        }
    }
    
    clearAll() {
        this.clearDecodedSections();
        this.updateVerificationStatus('not-verified', 'Signature Not Verified');
        this.hideError();
    }
    
    clearDecodedSections() {
        this.headerContent.textContent = '';
        this.payloadContent.textContent = '';
        this.timestampInfo.innerHTML = '';
        this.currentJWT = null;
        this.currentHeader = null;
        this.currentPayload = null;
    }
    
    showError(message) {
        this.errorMessage.textContent = message;
        this.errorMessage.classList.remove('hidden');
        
        // Auto-hide error after 5 seconds
        setTimeout(() => {
            this.hideError();
        }, 5000);
    }
    
    hideError() {
        this.errorMessage.classList.add('hidden');
    }
}

// Initialize the JWT Decoder when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new JWTDecoder();
});

// Sample JWT for testing (optional - can be removed)
const sampleJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';