# SecureFile - Simple Web Encryption

A simple, client-side file encryption tool using Web Crypto API. No server needed!

## Quick Start

```bash
# Install dependencies
npm install

# Start development server
npm run dev
```

That's it! Open http://localhost:3000 in your browser.

## Features

- 🔐 **Encrypt files** with RSA-wrapped AES keys
- 🔓 **Decrypt files** with your private key
- 🔑 **Generate RSA keypairs** (2048 or 3072 bits)
- 📦 **Pure client-side** - everything runs in your browser
- 🎨 **Simple, clean UI** - no frameworks, just vanilla JS

## How It Works

1. **Encrypt**: 
   - Upload a file
   - Provide RSA public key (or generate one)
   - Download: encrypted file, wrapped key, IV, and tag (for GCM)

2. **Decrypt**:
   - Upload encrypted file
   - Upload wrapped key
   - Provide RSA private key
   - Upload IV and tag files (if using GCM)
   - Download decrypted file

## File Structure

```
web/
├── index.html          # Main HTML
├── src/
│   ├── main.js         # Entry point
│   ├── app.js          # UI logic
│   ├── crypto.js       # Encryption/decryption functions
│   └── styles.css      # Styling
├── package.json
└── vite.config.js
```

## Notes

- All encryption happens in your browser - no data is sent to any server
- Uses Web Crypto API (supported in all modern browsers)
- RSA-OAEP for key wrapping
- AES-256-GCM or AES-256-CBC for file encryption
- SHA-256 for integrity verification