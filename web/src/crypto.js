// Hybrid RSA-AES Encryption using Web Crypto API

// Generate RSA keypair
export async function generateKeyPair(bits = 2048) {
    const keyPair = await crypto.subtle.generateKey(
        {
            name: 'RSA-OAEP',
            modulusLength: bits,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: 'SHA-256',
        },
        true,
        ['encrypt', 'decrypt']
    );
    
    // Export keys to PEM format
    const publicKeyPem = await exportKey(keyPair.publicKey, 'spki');
    const privateKeyPem = await exportKey(keyPair.privateKey, 'pkcs8');
    
    return { publicKey: publicKeyPem, privateKey: privateKeyPem, keyPair };
}

// Encrypt file with hybrid RSA-AES
export async function encryptFile(file, publicKeyPem, mode = 'AES-GCM') {
    const startTime = performance.now();
    
    // Read file
    const fileData = await file.arrayBuffer();
    const fileBytes = new Uint8Array(fileData);
    
    // Compute SHA-256 of original
    const sha256Original = await computeSHA256(fileBytes);
    
    // Import public key
    const publicKey = await importPublicKey(publicKeyPem);
    
    // Generate random AES key
    const aesKey = await crypto.subtle.generateKey(
        { name: mode === 'AES-GCM' ? 'AES-GCM' : 'AES-CBC', length: 256 },
        true,
        ['encrypt']
    );
    
    // Encrypt AES key with RSA
    const exportedAesKey = await crypto.subtle.exportKey('raw', aesKey);
    const wrappedKey = await crypto.subtle.encrypt(
        { name: 'RSA-OAEP' },
        publicKey,
        exportedAesKey
    );
    
    // Encrypt file with AES
    const iv = crypto.getRandomValues(new Uint8Array(mode === 'AES-GCM' ? 12 : 16));
    const algorithm = mode === 'AES-GCM' 
        ? { name: 'AES-GCM', iv }
        : { name: 'AES-CBC', iv };
    
    const encrypted = await crypto.subtle.encrypt(algorithm, aesKey, fileBytes);
    let encryptedData = new Uint8Array(encrypted);
    
    // For GCM, the tag is automatically appended by Web Crypto API
    // We'll store it separately for decryption
    let tag = null;
    if (mode === 'AES-GCM') {
        // GCM tag is the last 16 bytes of encrypted data
        tag = new Uint8Array(encryptedData.slice(-16));
        // Remove tag from encrypted data for storage
        encryptedData = new Uint8Array(encryptedData.slice(0, -16));
    }
    
    // Compute SHA-256 of encrypted
    const sha256Encrypted = await computeSHA256(encryptedData);
    
    const elapsedMs = performance.now() - startTime;
    
    return {
        encrypted: encryptedData,
        wrappedKey: new Uint8Array(wrappedKey),
        iv,
        tag,
        sha256Original,
        sha256Encrypted,
        bytesIn: fileBytes.length,
        bytesOut: encryptedData.length,
        elapsedMs
    };
}

// Decrypt file with hybrid RSA-AES
export async function decryptFile(encryptedFile, wrappedKeyFile, privateKeyPem, passphrase = '', iv = null, tag = null, mode = 'AES-GCM') {
    const startTime = performance.now();
    
    // Read files
    let encryptedData = new Uint8Array(await encryptedFile.arrayBuffer());
    const wrappedKeyData = new Uint8Array(await wrappedKeyFile.arrayBuffer());
    
    // Import private key
    const privateKey = await importPrivateKey(privateKeyPem, passphrase);
    
    // Decrypt AES key with RSA
    const exportedAesKey = await crypto.subtle.decrypt(
        { name: 'RSA-OAEP' },
        privateKey,
        wrappedKeyData
    );
    
    // Determine mode and IV
    // If IV and tag are provided, use them; otherwise try to detect
    let useMode = mode;
    let useIv = iv;
    let useTag = tag;
    
    // Validate IV is provided and has correct size for the mode
    if (!useIv) {
        throw new Error(`${useMode} mode requires an IV. Please provide the IV file.`);
    }
    
    // Validate IV size matches the mode
    const expectedIvSize = useMode === 'AES-GCM' ? 12 : 16;
    if (useIv.length !== expectedIvSize) {
        throw new Error(`Invalid IV size for ${useMode} mode. Expected ${expectedIvSize} bytes, got ${useIv.length} bytes.`);
    }
    
    // For GCM, if tag is not provided, assume it's appended to encrypted data
    if (useMode === 'AES-GCM' && !useTag) {
        // Check if encrypted data ends with a 16-byte tag
        if (encryptedData.length >= 16) {
            useTag = new Uint8Array(encryptedData.slice(-16));
            encryptedData = new Uint8Array(encryptedData.slice(0, -16));
        } else {
            throw new Error('GCM mode requires a tag. Please provide IV and tag files.');
        }
    }
    
    // For CBC mode, ignore tag if provided (CBC doesn't use tags)
    if (useMode === 'AES-CBC') {
        useTag = null;
    }
    
    // Import AES key for the detected mode
    const aesKey = await crypto.subtle.importKey(
        'raw',
        exportedAesKey,
        { name: useMode === 'AES-GCM' ? 'AES-GCM' : 'AES-CBC', length: 256 },
        false,
        ['decrypt']
    );
    
    // Decrypt
    let algorithm;
    if (useMode === 'AES-GCM') {
        // For GCM, we need to append the tag back for decryption
        const encryptedWithTag = new Uint8Array(encryptedData.length + 16);
        encryptedWithTag.set(encryptedData);
        encryptedWithTag.set(useTag, encryptedData.length);
        algorithm = { name: 'AES-GCM', iv: useIv };
        encryptedData = encryptedWithTag;
    } else {
        algorithm = { name: 'AES-CBC', iv: useIv };
    }
    
    const decrypted = await crypto.subtle.decrypt(algorithm, aesKey, encryptedData);
    const decryptedBytes = new Uint8Array(decrypted);
    const sha256Decrypted = await computeSHA256(decryptedBytes);
    
    const elapsedMs = performance.now() - startTime;
    
    return {
        decrypted: decryptedBytes,
        sha256Decrypted,
        bytesOut: decryptedBytes.length,
        elapsedMs
    };
}

// Helper: Compute SHA-256
async function computeSHA256(data) {
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper: Import public key from PEM
async function importPublicKey(pem) {
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const pemContents = pem
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '');
    const binaryDer = base64ToArrayBuffer(pemContents);
    
    return await crypto.subtle.importKey(
        'spki',
        binaryDer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['encrypt']
    );
}

// Helper: Import private key from PEM
async function importPrivateKey(pem, passphrase = '') {
    const pemHeader = '-----BEGIN PRIVATE KEY-----';
    const pemFooter = '-----END PRIVATE KEY-----';
    const pemContents = pem
        .replace(pemHeader, '')
        .replace(pemFooter, '')
        .replace(/\s/g, '');
    const binaryDer = base64ToArrayBuffer(pemContents);
    
    // Note: Web Crypto API doesn't support password-protected keys directly
    // For this demo, we assume unencrypted keys
    return await crypto.subtle.importKey(
        'pkcs8',
        binaryDer,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
    );
}

// Helper: Export key to PEM format
async function exportKey(key, format) {
    const exported = await crypto.subtle.exportKey(format, key);
    const exportedAsBase64 = arrayBufferToBase64(exported);
    const pemHeader = format === 'spki' 
        ? '-----BEGIN PUBLIC KEY-----\n'
        : '-----BEGIN PRIVATE KEY-----\n';
    const pemFooter = format === 'spki'
        ? '\n-----END PUBLIC KEY-----'
        : '\n-----END PRIVATE KEY-----';
    
    // Format with line breaks every 64 characters
    const formatted = exportedAsBase64.match(/.{1,64}/g).join('\n');
    return pemHeader + formatted + pemFooter;
}

// Helper: Base64 to ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

// Helper: ArrayBuffer to Base64
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

