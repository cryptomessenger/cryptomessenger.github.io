function generateKey(password, salt, iterations) {
    let key = CryptoJS.PBKDF2(password, salt, {keySize: 256 / 32, iterations: iterations});
    return key;
}

function encryptMessage(btn) {
    let message = document.getElementById('message-chat').value;
    if (message === '') {
        return 0;
    }
    let configArray = document.getElementById('config').value.split('|');
    let user = configArray[0];
    if (user === 'A') {
        user = 'B';
    } else if (user === 'B') {
        user = 'A';
    }
    let iv = CryptoJS.lib.WordArray.random(16);
    let ciphertext = CryptoJS.AES.encrypt(message, key, {iv: iv}).toString();
    let encryptedArray = [user];
    encryptedArray.push(CryptoJS.enc.Base64.stringify(iv));
    encryptedArray.push(ciphertext);
    let encrypted = encryptedArray.join('|');
    navigator.clipboard.writeText(encrypted).then(() => {
        btn.innerHTML = 'Copied';
        setTimeout(() => {
            btn.innerHTML = 'Encrypt and copy';
        }, '1500');
    });
}

function decryptMessage() {
    let encrypted = document.getElementById('encrypted-message-chat').value;
    if (encrypted === '') {
        return 0;
    }
    let encryptedArray = encrypted.split('|');
    let user = encryptedArray[0];
    let iv = CryptoJS.enc.Base64.parse(encryptedArray[1]);
    let ciphertext = encryptedArray[2];
    let plaintext = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv}).toString(CryptoJS.enc.Utf8);
    let el = document.createElement('p');
    el.innerHTML = `${user}: ${plaintext}`;
    el.className = 'mb-4';
    document.getElementById('messages').appendChild(el);
}

function symmetricEncrypt() {
    let message = document.getElementById('message-symmetric').value;
    let password = document.getElementById('password-symmetric').value;
    if (message === '' || password === '') {
        return 0;
    }
    let iterations = parseInt(document.getElementById('iterations-symmetric').value);
    let salt = CryptoJS.lib.WordArray.random(32);
    let key = generateKey(password, salt, iterations);
    let iv = CryptoJS.lib.WordArray.random(16);
    let ciphertext = CryptoJS.AES.encrypt(message, key, {iv: iv}).toString();
    let encryptedArray = [iterations.toString()];
    encryptedArray.push(CryptoJS.enc.Base64.stringify(salt));
    encryptedArray.push(CryptoJS.enc.Base64.stringify(iv));
    encryptedArray.push(ciphertext);
    let encrypted = encryptedArray.join('|');
    document.getElementById('encrypted-message-symmetric').value = encrypted;
    expandTextarea('encrypted-message-symmetric');
}

function symmetricDecrypt() {
    let encrypted = document.getElementById('encrypted-message-symmetric').value;
    let password = document.getElementById('password-symmetric').value;
    if (encrypted === '' || password === '') {
        return 0;
    }
    let encryptedArray = encrypted.split('|');
    let iterations = parseInt(encryptedArray[0]);
    let salt = CryptoJS.enc.Base64.parse(encryptedArray[1]);
    let iv = CryptoJS.enc.Base64.parse(encryptedArray[2]);
    let ciphertext = encryptedArray[3];
    let key = generateKey(password, salt, iterations);
    let plaintext = CryptoJS.AES.decrypt(ciphertext, key, {iv: iv}).toString(CryptoJS.enc.Utf8);
    document.getElementById('message-symmetric').value = plaintext;
    document.getElementById('iterations-symmetric').value = iterations;
    document.getElementById('iterations-symmetric-display').innerHTML = iterations;
    expandTextarea('message-symmetric');
}

function createConfigA() {
    let parameterP = bigInt(document.getElementById('parameter-p').value);
    let password = document.getElementById('password-create').value;
    if (parameterP.bitLength() < 1024 || password === '') {
        return 0;
    }
    let iterations = parseInt(document.getElementById('iterations-create').value);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let publicKey = bigInt(2).modPow(privateKey, parameterP);
    let salt = CryptoJS.lib.WordArray.random(32);
    let configArray = ['A', CryptoJS.enc.Base64.stringify(salt)];
    configArray.push(iterations.toString());
    configArray.push(parameterP.toString())
    configArray.push(publicKey.toString());
    let config = configArray.join('|');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-a').classList.remove('hidden');
    });
}

function createConfigB() {
    let configArray = document.getElementById('config-a').value.split('|');
    let password = document.getElementById('password-confirm').value;
    if (configArray.length < 5 || password === '') {
        return 0;
    }
    let parameterP = bigInt(configArray[3]);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let publicKey = bigInt(2).modPow(privateKey, parameterP);
    configArray[0] = 'B';
    configArray[4] = publicKey.toString();
    let config = configArray.join('|');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-b').classList.remove('hidden');
    });
}

function generateKeyChat() {
    let configArray = document.getElementById('config').value.split('|');
    let password = document.getElementById('password-chat').value;
    if (configArray.length < 5 || password === '') {
        return 0;
    }
    let salt = CryptoJS.enc.Base64.parse(configArray[1]);
    let iterations = parseInt(configArray[2]);
    let parameterP = bigInt(configArray[3]);
    let interlocutorPublicKey = bigInt(configArray[4]);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let sharedKey = bigInt(interlocutorPublicKey).modPow(privateKey, parameterP);
    key = generateKey(sharedKey.toString(), salt, iterations);
    document.getElementById('chat-body').classList.remove('hidden');
}

function passwordToPrivateKey(password, parameterP) {
    let privateKey = '';
    for (let i = 0; i < password.length; i++) {
        if (privateKey.length === parameterP.toString().length) {
            break;
        }
        privateKey += password.charCodeAt(i).toString();
    }
    return bigInt(privateKey);
}

function switchPassword(btn, passwordId) {
    let password = document.getElementById(passwordId);
    let icon = btn.querySelector('i');
    if (password.type === 'password') {
        password.type = 'text';
        icon.classList.replace('bi-eye-slash', 'bi-eye');
    } else {
        password.type = 'password';
        icon.classList.replace('bi-eye', 'bi-eye-slash');
    }
}

function expandTextarea(textareaId) {
    let textarea = document.getElementById(textareaId);
    let heightLimit = 370;
    textarea.style.height = '';
    textarea.style.height = Math.min(textarea.scrollHeight, heightLimit) + 2 + 'px';
}

function clearInput(inputId) {
    document.getElementById(inputId).value = '';
    document.getElementById(inputId).style.height = '';
}

function displayValue(inputId) {
    let value = document.getElementById(inputId).value;
    document.getElementById(`${inputId}-display`).innerHTML = value;
}

function selectTab(tab) {
    let URLParams = new URLSearchParams(window.location.search);
    URLParams.set('tab', tab);
    window.location.search = URLParams;
}

function setTab() {
    let URLParams = new URLSearchParams(window.location.search);
    let tab = URLParams.get('tab');
    if (tab === null) {
        URLParams.set('tab', 'create');
        window.location.search = URLParams;
    } else {
        document.getElementById(`${tab}-btn`).disabled = true;
        document.getElementById(`${tab}-tab`).classList.remove('hidden');
    }
}

setTab();
var key;