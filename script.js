async function generateKey() {
    if (!localStorage.getItem("encryptionKey")) {
        const key = await crypto.subtle.generateKey(
            { name: "AES-CBC", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );
        const exportedKey = await crypto.subtle.exportKey("raw", key);
        
        localStorage.setItem("encryptionKey", arrayBufferToBase64(exportedKey));
        localStorage.setItem("iv", arrayBufferToBase64(crypto.getRandomValues(new Uint8Array(16))));
    }
}

function getStoredKeyAndIV() {
    return {
        keyData: base64ToArrayBuffer(localStorage.getItem("encryptionKey")),
        ivData: base64ToArrayBuffer(localStorage.getItem("iv"))
    };
}

function arrayBufferToBase64(buffer) {
    let binary = '';
    let bytes = new Uint8Array(buffer);
    bytes.forEach(byte => binary += String.fromCharCode(byte));
    return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
    let binary = window.atob(base64);
    let bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

async function encryptFile() {
    await generateKey();
    
    const fileInput = document.getElementById('fileInput').files[0];
    if (!fileInput) {
        document.getElementById('status').innerText = "Please select a file.";
        return;
    }

    // Prevent encryption of already encrypted files
    if (fileInput.name.endsWith(".locked")) {
        document.getElementById('status').innerText = "File is already encrypted!";
        return;
    }

    const { keyData, ivData } = getStoredKeyAndIV();
    const key = await crypto.subtle.importKey("raw", keyData, { name: "AES-CBC" }, true, ["encrypt"]);
    const iv = new Uint8Array(ivData);

    const reader = new FileReader();
    reader.onload = async function(event) {
        const fileData = new Uint8Array(event.target.result);

        const encryptedData = await crypto.subtle.encrypt(
            { name: "AES-CBC", iv: iv },
            key,
            fileData
        );

        const encryptedBlob = new Blob([encryptedData], { type: "application/octet-stream" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(encryptedBlob);
        link.download = fileInput.name + ".locked";
        link.click();

        document.getElementById('status').innerText = "File encrypted successfully!";
    };
    reader.readAsArrayBuffer(fileInput);
}

async function decryptFile() {
    const fileInput = document.getElementById('fileInput').files[0];
    if (!fileInput) {
        document.getElementById('status').innerText = "Please select an encrypted file.";
        return;
    }

    // Ensure the file has the correct format before decryption
    if (!fileInput.name.endsWith(".locked")) {
        document.getElementById('status').innerText = "File is not encrypted!";
        return;
    }

    const { keyData, ivData } = getStoredKeyAndIV();
    const key = await crypto.subtle.importKey("raw", keyData, { name: "AES-CBC" }, true, ["decrypt"]);
    const iv = new Uint8Array(ivData);

    const reader = new FileReader();
    reader.onload = async function(event) {
        const encryptedData = new Uint8Array(event.target.result);

        try {
            const decryptedData = await crypto.subtle.decrypt(
                { name: "AES-CBC", iv: iv },
                key,
                encryptedData
            );

            const decryptedBlob = new Blob([decryptedData], { type: "application/octet-stream" });
            const link = document.createElement("a");
            link.href = URL.createObjectURL(decryptedBlob);
            link.download = fileInput.name.replace(".locked", "");
            link.click();

            document.getElementById('status').innerText = "File decrypted successfully!";
        } catch (error) {
            document.getElementById('status').innerText = "Decryption failed! Key mismatch or invalid file.";
            console.error(error);
        }
    };
    reader.readAsArrayBuffer(fileInput);
}
