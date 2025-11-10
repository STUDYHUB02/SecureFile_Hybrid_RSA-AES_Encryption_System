import { encryptFile, decryptFile, generateKeyPair } from './crypto.js';
import './app.js';

// Make functions available globally for debugging
window.encryptFile = encryptFile;
window.decryptFile = decryptFile;
window.generateKeyPair = generateKeyPair;

