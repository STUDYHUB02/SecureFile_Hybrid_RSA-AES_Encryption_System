// Tab switching
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const tab = btn.dataset.tab;

    // Update buttons
    document
      .querySelectorAll(".tab-btn")
      .forEach((b) => b.classList.remove("active"));
    btn.classList.add("active");

    // Update content
    document
      .querySelectorAll(".tab-content")
      .forEach((c) => c.classList.remove("active"));
    document.getElementById(`${tab}-tab`).classList.add("active");
  });
});

// File upload handlers
function setupFileUpload(uploadArea, fileInput, fileInfo) {
  uploadArea.addEventListener("click", () => fileInput.click());
  uploadArea.addEventListener("dragover", (e) => {
    e.preventDefault();
    uploadArea.classList.add("dragover");
  });
  uploadArea.addEventListener("dragleave", () => {
    uploadArea.classList.remove("dragover");
  });
  uploadArea.addEventListener("drop", (e) => {
    e.preventDefault();
    uploadArea.classList.remove("dragover");
    if (e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      updateFileInfo(fileInput, fileInfo);
    }
  });
  fileInput.addEventListener("change", () =>
    updateFileInfo(fileInput, fileInfo)
  );
}

function updateFileInfo(input, info) {
  if (input.files.length > 0) {
    const file = input.files[0];
    info.textContent = `${file.name} (${(file.size / 1024).toFixed(2)} KB)`;
  } else {
    info.textContent = "";
  }
}

// Setup upload areas
setupFileUpload(
  document.getElementById("encrypt-upload"),
  document.getElementById("encrypt-file-input"),
  document.getElementById("encrypt-file-info")
);

setupFileUpload(
  document.getElementById("decrypt-upload"),
  document.getElementById("decrypt-file-input"),
  document.getElementById("decrypt-file-info")
);

// Encrypt button
document.getElementById("encrypt-btn").addEventListener("click", async () => {
  const fileInput = document.getElementById("encrypt-file-input");
  const publicKeyText = document
    .getElementById("encrypt-public-key")
    .value.trim();
  const mode = document.getElementById("encrypt-mode").value;
  const resultDiv = document.getElementById("encrypt-result");

  if (!fileInput.files.length) {
    showError(resultDiv, "Please select a file");
    return;
  }

  if (!publicKeyText) {
    showError(resultDiv, "Please provide a public key");
    return;
  }

  try {
    resultDiv.innerHTML = "<p>⏳ Encrypting...</p>";
    const file = fileInput.files[0];
    const result = await encryptFile(file, publicKeyText, mode);
    showEncryptResult(resultDiv, result, file.name);
  } catch (error) {
    showError(resultDiv, error.message);
  }
});

// Decrypt button
document.getElementById("decrypt-btn").addEventListener("click", async () => {
  const fileInput = document.getElementById("decrypt-file-input");
  const wrappedKeyInput = document.getElementById("wrapped-key-input");
  const privateKeyText = document
    .getElementById("decrypt-private-key")
    .value.trim();
  const passphrase = document.getElementById("decrypt-passphrase").value;
  const resultDiv = document.getElementById("decrypt-result");

  if (!fileInput.files.length) {
    showError(resultDiv, "Please select an encrypted file");
    return;
  }

  if (!wrappedKeyInput.files.length) {
    showError(resultDiv, "Please select a wrapped key file");
    return;
  }

  if (!privateKeyText) {
    showError(resultDiv, "Please provide a private key");
    return;
  }

  const ivInput = document.getElementById("iv-input");
  if (!ivInput.files.length) {
    showError(
      resultDiv,
      "Please provide an IV file. The IV file is required for decryption."
    );
    return;
  }

  try {
    resultDiv.innerHTML = "<p>⏳ Decrypting...</p>";
    const encryptedFile = fileInput.files[0];
    const wrappedKeyFile = wrappedKeyInput.files[0];
    const tagInput = document.getElementById("tag-input");

    // Read IV and tag files if provided
    let iv = null;
    let tag = null;
    // Default to CBC mode; switch to GCM only if tag file is provided
    let mode = "AES-CBC";

    if (ivInput.files.length > 0) {
      try {
        const ivText = await ivInput.files[0].text();
        const ivHex = ivText.trim().replace(/\s/g, "");

        // Validate hex string
        if (!/^[0-9a-fA-F]+$/.test(ivHex)) {
          throw new Error(
            "IV file contains invalid hex characters. IV must be a hexadecimal string."
          );
        }

        if (ivHex.length % 2 !== 0) {
          throw new Error(
            "IV file has odd number of hex characters. IV must have an even number of hex digits."
          );
        }

        iv = new Uint8Array(
          ivHex.match(/.{1,2}/g).map((byte) => parseInt(byte, 16))
        );

        // Auto-detect mode based on IV size: GCM uses 12 bytes, CBC uses 16 bytes
        if (iv.length === 12) {
          mode = "AES-GCM";
        } else if (iv.length === 16) {
          mode = "AES-CBC";
        } else {
          throw new Error(
            `Invalid IV size: ${iv.length} bytes. IV must be 12 bytes (GCM) or 16 bytes (CBC).`
          );
        }
      } catch (error) {
        showError(resultDiv, `Error reading IV file: ${error.message}`);
        return;
      }
    }

    if (tagInput.files.length > 0) {
      tag = new Uint8Array(await tagInput.files[0].arrayBuffer());
      mode = "AES-GCM"; // Tag files are only used with GCM mode
    }

    const result = await decryptFile(
      encryptedFile,
      wrappedKeyFile,
      privateKeyText,
      passphrase,
      iv,
      tag,
      mode
    );
    // Extract original filename from encrypted file name
    const originalName =
      encryptedFile.name.replace(/\.enc$/, "") || "decrypted";
    showDecryptResult(resultDiv, result, originalName);
  } catch (error) {
    showError(resultDiv, error.message);
  }
});

// Generate keys button
document
  .getElementById("generate-keys-btn")
  .addEventListener("click", async () => {
    const keySize = parseInt(document.getElementById("key-size").value);
    const resultDiv = document.getElementById("keys-result");

    try {
      resultDiv.innerHTML = "<p>⏳ Generating keypair...</p>";
      const keys = await generateKeyPair(keySize);
      showKeysResult(resultDiv, keys);
    } catch (error) {
      showError(resultDiv, error.message);
    }
  });

// Result display functions
function showError(div, message) {
  div.innerHTML = `<p class="error">❌ ${message}</p>`;
}

function showEncryptResult(div, result, originalName) {
  // Store IV and tag in result for later use
  const ivHex = Array.from(result.iv)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  const tagHex = result.tag
    ? Array.from(result.tag)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("")
    : "";

  div.innerHTML = `
        <div class="success">
            <p>✅ Encryption successful!</p>
            <div class="result-info">
                <p><strong>SHA-256 (Original):</strong> <code>${
                  result.sha256Original
                }</code></p>
                <p><strong>SHA-256 (Encrypted):</strong> <code>${
                  result.sha256Encrypted
                }</code></p>
                <p><strong>Size:</strong> ${result.bytesIn} → ${
    result.bytesOut
  } bytes</p>
                <p><strong>Time:</strong> ${result.elapsedMs.toFixed(2)} ms</p>
                <p><strong>IV:</strong> <code>${ivHex}</code></p>
                ${
                  result.tag
                    ? `<p><strong>Tag:</strong> <code>${tagHex}</code></p>`
                    : ""
                }
            </div>
            <div class="download-buttons">
                <button class="btn btn-success" id="download-encrypted-btn">📥 Download Encrypted</button>
                <button class="btn btn-success" id="download-key-btn">📥 Download Wrapped Key</button>
                <button class="btn btn-success" id="download-iv-btn">📥 Download IV</button>
                ${
                  result.tag
                    ? `<button class="btn btn-success" id="download-tag-btn">📥 Download Tag</button>`
                    : ""
                }
            </div>
            <p style="margin-top: 15px; font-size: 0.9em; color: #666;">
                💡 Save the IV and Tag files along with the encrypted file and wrapped key for decryption.
            </p>
        </div>
    `;

  // Add event listeners for download buttons
  document
    .getElementById("download-encrypted-btn")
    .addEventListener("click", () => {
      downloadFile(
        result.encrypted,
        originalName + ".enc",
        "application/octet-stream"
      );
    });

  document.getElementById("download-key-btn").addEventListener("click", () => {
    downloadFile(
      result.wrappedKey,
      originalName + ".key",
      "application/octet-stream"
    );
  });

  document.getElementById("download-iv-btn").addEventListener("click", () => {
    downloadFile(ivHex, originalName + ".iv", "text/plain");
  });

  if (result.tag) {
    document
      .getElementById("download-tag-btn")
      .addEventListener("click", () => {
        downloadFile(
          result.tag,
          originalName + ".tag",
          "application/octet-stream"
        );
      });
  }
}

function showDecryptResult(div, result, originalName = "decrypted") {
  div.innerHTML = `
        <div class="success">
            <p>✅ Decryption successful!</p>
            <div class="result-info">
                <p><strong>SHA-256:</strong> <code>${
                  result.sha256Decrypted
                }</code></p>
                <p><strong>Size:</strong> ${result.bytesOut} bytes</p>
                <p><strong>Time:</strong> ${result.elapsedMs.toFixed(2)} ms</p>
            </div>
            <button class="btn btn-success" id="download-decrypted-btn">📥 Download Decrypted File</button>
        </div>
    `;

  // Add event listener for download button
  document
    .getElementById("download-decrypted-btn")
    .addEventListener("click", () => {
      downloadFile(result.decrypted, originalName, "application/octet-stream");
    });
}

function showKeysResult(div, keys) {
  div.innerHTML = `
        <div class="success">
            <p>✅ Keypair generated!</p>
            <div class="form-group">
                <label>Public Key:</label>
                <textarea readonly class="key-display" id="public-key-textarea">${keys.publicKey}</textarea>
                <button class="btn btn-small" id="copy-public-btn">📋 Copy</button>
                <button class="btn btn-small" id="download-public-btn">📥 Download</button>
            </div>
            <div class="form-group">
                <label>Private Key:</label>
                <textarea readonly class="key-display" id="private-key-textarea">${keys.privateKey}</textarea>
                <button class="btn btn-small" id="copy-private-btn">📋 Copy</button>
                <button class="btn btn-small" id="download-private-btn">📥 Download</button>
                <p class="warning">⚠️ Keep your private key secure and never share it!</p>
            </div>
        </div>
    `;

  // Add event listeners for copy buttons
  document.getElementById("copy-public-btn").addEventListener("click", () => {
    const textarea = document.getElementById("public-key-textarea");
    textarea.select();
    copyToClipboard(keys.publicKey);
  });

  document.getElementById("copy-private-btn").addEventListener("click", () => {
    const textarea = document.getElementById("private-key-textarea");
    textarea.select();
    copyToClipboard(keys.privateKey);
  });

  // Add event listeners for download buttons
  document
    .getElementById("download-public-btn")
    .addEventListener("click", () => {
      downloadFile(keys.publicKey, "public_key.pem", "text/plain");
    });

  document
    .getElementById("download-private-btn")
    .addEventListener("click", () => {
      downloadFile(keys.privateKey, "private_key.pem", "text/plain");
    });
}

function downloadFile(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

function copyToClipboard(text) {
  // Try modern clipboard API first
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard
      .writeText(text)
      .then(() => {
        showToast("✅ Copied to clipboard!");
      })
      .catch((err) => {
        // Fallback to old method
        fallbackCopyToClipboard(text);
      });
  } else {
    // Fallback for older browsers
    fallbackCopyToClipboard(text);
  }
}

function fallbackCopyToClipboard(text) {
  const textArea = document.createElement("textarea");
  textArea.value = text;
  textArea.style.position = "fixed";
  textArea.style.left = "-999999px";
  textArea.style.top = "-999999px";
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();

  try {
    const successful = document.execCommand("copy");
    if (successful) {
      showToast("✅ Copied to clipboard!");
    } else {
      showToast("❌ Failed to copy. Please select and copy manually.");
    }
  } catch (err) {
    showToast("❌ Failed to copy. Please select and copy manually.");
  }

  document.body.removeChild(textArea);
}

function showToast(message) {
  // Create a simple toast notification
  const toast = document.createElement("div");
  toast.textContent = message;
  toast.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #333;
        color: white;
        padding: 12px 24px;
        border-radius: 8px;
        z-index: 10000;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        font-size: 14px;
    `;
  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s";
    setTimeout(() => {
      document.body.removeChild(toast);
    }, 300);
  }, 2000);
}
