# 🔐 One-Click JWT Decoder & Validator

A secure, client-side JWT (JSON Web Token) decoder and validator that runs entirely in your browser. No data ever leaves your machine - perfect for handling sensitive tokens with complete privacy.

![JWT Decoder Screenshot](https://img.shields.io/badge/Status-Ready-brightgreen) ![No Dependencies](https://img.shields.io/badge/Dependencies-None-blue) ![Client Side](https://img.shields.io/badge/Processing-Client%20Side-orange)


Running version : https://sourojit.online/jwt/

## ✨ Features

### 🔒 **Privacy First**
- **100% Client-Side Processing** - All decoding and validation happens in your browser
- **No Server Communication** - Your tokens never leave your machine
- **No External Dependencies** - Uses only native browser APIs

### ⚡ **Real-Time Processing**
- **Instant Decoding** - See results as you type, no button clicks needed
- **Live Validation** - Signature verification updates automatically
- **Color-Coded Sections** - Visual distinction between header, payload, and signature

### 🛠️ **Comprehensive Support**
- **Multiple Algorithms**: HS256, HS384, HS512, RS256, RS384, RS512, ES256, ES384, ES512
- **Smart Algorithm Detection** - Automatically selects the correct algorithm from JWT header
- **Flexible Key Support** - Works with both secret keys (HMAC) and public keys (RSA/ECDSA)

### 📱 **Modern UI/UX**
- **Dark Theme** - Easy on the eyes, similar to jwt.io
- **Responsive Design** - Works perfectly on desktop, tablet, and mobile
- **Intuitive Layout** - Three-panel design for optimal workflow
- **Human-Readable Timestamps** - Shows relative time (e.g., "expires in 2 hours")

## 🚀 Quick Start

1. **Clone or Download**
   ```bash
   git clone https://github.com/yourusername/jwt-decoder.git
   cd jwt-decoder
   ```

2. **Open in Browser**
   ```bash
   # Simply open index.html in any modern browser
   open index.html
   # or
   python -m http.server 8000  # For local development server
   ```

3. **Start Decoding**
   - Paste your JWT token in the left panel
   - Watch it decode automatically
   - Add your secret/public key for signature verification

## 📖 How to Use

### Basic Decoding
1. Paste any JWT token into the "Encoded JWT" textarea
2. The header and payload will decode automatically
3. Timestamps (iat, exp, nbf) are shown in human-readable format

### Signature Verification
1. The algorithm is auto-detected from your JWT header
2. For **HMAC algorithms** (HS256/384/512):
   - Enter your secret key in the "Secret / Public Key" field
3. For **RSA/ECDSA algorithms** (RS256/384/512, ES256/384/512):
   - Paste your public key in PEM format
4. Verification status updates automatically

### Example Keys

**HMAC Secret (for HS256):**
```
your-256-bit-secret
```

**RSA Public Key (for RS256):**
```
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4f5wg5l2hKsTeNem/V41
fGnJm6gOdrj8ym3rFkEjWT2btf7FMEQjbXxr3RT6KSaF3psvQy9GJn9nzylz5sMi
...
-----END PUBLIC KEY-----
```

## 🔧 Technical Details

### Architecture
- **Frontend**: Vanilla HTML5, CSS3, JavaScript (ES6+)
- **Crypto**: Native Web Crypto API for all cryptographic operations
- **No Build Process**: Ready to run directly in the browser

### Supported Algorithms
| Algorithm | Type | Hash Function | Key Type |
|-----------|------|---------------|----------|
| HS256     | HMAC | SHA-256       | Secret   |
| HS384     | HMAC | SHA-384       | Secret   |
| HS512     | HMAC | SHA-512       | Secret   |
| RS256     | RSA  | SHA-256       | Public   |
| RS384     | RSA  | SHA-384       | Public   |
| RS512     | RSA  | SHA-512       | Public   |
| ES256     | ECDSA| SHA-256       | Public   |
| ES384     | ECDSA| SHA-384       | Public   |
| ES512     | ECDSA| SHA-512       | Public   |

### Browser Compatibility
- Chrome 60+
- Firefox 57+
- Safari 11+
- Edge 79+

## 🎨 Customization

### Themes
The application uses CSS custom properties for easy theming:

```css
:root {
  --bg-primary: #1a1a1a;
  --bg-secondary: #2a2a2a;
  --text-primary: #e0e0e0;
  --accent-header: #ff6b6b;
  --accent-payload: #a855f7;
  --accent-signature: #3b82f6;
}
```

### Adding New Algorithms
To add support for additional algorithms, extend the `validateJWTSignature` method in `script.js`.

## 🔍 Security Considerations

- **Client-Side Only**: No network requests are made
- **Memory Safety**: Sensitive data is not persisted
- **Crypto Standards**: Uses Web Crypto API following current standards
- **Input Validation**: Comprehensive validation of JWT format and keys

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by [jwt.io](https://jwt.io) but with enhanced privacy and security
- Built with modern web standards and best practices
- Uses native browser APIs for maximum compatibility and security

## 📞 Support

If you encounter any issues or have questions:
- Open an issue on GitHub
- Check the browser console for error messages
- Ensure you're using a modern browser with Web Crypto API support

---

**Made with ❤️ for developers who value privacy and security**
