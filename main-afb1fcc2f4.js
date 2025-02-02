function generateKey(password, salt, iterations) {
    let key = CryptoJS.PBKDF2(password, salt, {keySize: 256 / 32, iterations: iterations});
    return key;
}

function encryptMessage(btn) {
    let message = document.getElementById('message-chat').value;
    if (message === '') {
        return 0;
    }
    let configArray = document.getElementById('config').value.split('_');
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
    let encrypted = encryptedArray.join('_');
    navigator.clipboard.writeText(encrypted).then(() => {
        let btnText = btn.innerHTML;
        btn.innerHTML = 'Copied';
        btn.disabled = true;
        setTimeout(() => {
            btn.innerHTML = btnText;
            btn.disabled = false;
        }, '1500');
    });
}

function decryptMessage() {
    let encrypted = document.getElementById('encrypted-message-chat').value;
    if (encrypted === '') {
        return 0;
    }
    let encryptedArray = encrypted.split('_');
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
    let encrypted = encryptedArray.join('_');
    document.getElementById('encrypted-message-symmetric').value = encrypted;
    expandTextarea('encrypted-message-symmetric');
}

function symmetricDecrypt() {
    let encrypted = document.getElementById('encrypted-message-symmetric').value;
    let password = document.getElementById('password-symmetric').value;
    if (encrypted === '' || password === '') {
        return 0;
    }
    let encryptedArray = encrypted.split('_');
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
    let parameters = document.getElementById('parameters').value;
    let parametersArray = parameters.split('_');
    let parameterG = parseInt(parametersArray[0]);
    let parameterP = bigInt(parametersArray[1]);
    let password = document.getElementById('password-create').value;
    if (parameterP.bitLength() < 1024 || password === '') {
        return 0;
    }
    let iterations = parseInt(document.getElementById('iterations-create').value);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let publicKey = bigInt(parameterG).modPow(privateKey, parameterP);
    let salt = CryptoJS.lib.WordArray.random(32);
    let configArray = ['A', iterations.toString()];
    configArray.push(CryptoJS.enc.Base64.stringify(salt));
    configArray.push(parameterG.toString());
    configArray.push(parameterP.toString());
    configArray.push(publicKey.toString());
    let config = configArray.join('_');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-a').innerHTML = `Copied: ${config}`;
        document.getElementById('copied-a').classList.remove('hidden');
    });
}

function createConfigB() {
    let configArray = document.getElementById('config-a').value.split('_');
    let password = document.getElementById('password-confirm').value;
    if (configArray.length < 6 || password === '') {
        return 0;
    }
    let parameterG = parseInt(configArray[3]);
    let parameterP = bigInt(configArray[4]);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let publicKey = bigInt(parameterG).modPow(privateKey, parameterP);
    configArray[0] = 'B';
    configArray[5] = publicKey.toString();
    let config = configArray.join('_');
    navigator.clipboard.writeText(config).then(() => {
        document.getElementById('copied-b').innerHTML = `Copied: ${config}`;
        document.getElementById('copied-b').classList.remove('hidden');
    });
}

function generateKeyChat() {
    let configArray = document.getElementById('config').value.split('_');
    let password = document.getElementById('password-chat').value;
    if (configArray.length < 6 || password === '') {
        return 0;
    }
    let iterations = parseInt(configArray[1]);
    let salt = CryptoJS.enc.Base64.parse(configArray[2]);
    let parameterP = bigInt(configArray[4]);
    let interlocutorPublicKey = bigInt(configArray[5]);
    let privateKey = passwordToPrivateKey(password, parameterP);
    let sharedKey = bigInt(interlocutorPublicKey).modPow(privateKey, parameterP);
    key = generateKey(sharedKey.toString(), salt, iterations);
    document.getElementById('chat-body').classList.remove('hidden');
}

function passwordToPrivateKey(password, parameterP) {
    let hash256 = CryptoJS.SHA256(password).toString();
    let hash384 = CryptoJS.SHA384(password).toString();
    let hash512 = CryptoJS.SHA512(password).toString();
    let part256 = bigInt(hash256, 16).toString();
    let part384 = bigInt(hash384, 16).toString();
    let part512 = bigInt(hash512, 16).toString();
    let full = `${part256}${part384}${part512}`;
    let parameterPLength = parameterP.toString().length;
    let privateKey = bigInt(full.slice(0, parameterPLength - 1));
    return privateKey;
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

function expandTextarea(id) {
    let textarea = document.getElementById(id);
    textarea.style.setProperty('height', '');
    let heightLimit = 370;
    let value = Math.min(textarea.scrollHeight, heightLimit) + 2;
    let height = `${value}px`;
    textarea.style.setProperty('height', height);
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

function setDefaultParameters() {
    let randomIndex = Math.floor(Math.random() * defaultParameters.length);
    document.getElementById('parameters').value = defaultParameters[randomIndex];
    expandTextarea('parameters');
}

setTab();

let key;
let p1 = '2_1453856265658174212258980899741931113435364689249840857072969364196';
p1 += '713642442806566602916436362838411203158846824267432444130722951923548582';
p1 += '115862312053187382721271267936751941207912865662088636868402561261492261';
p1 += '542477655472595775653994390413791684279781809081408659500283432996158030';
p1 += '3721502232165165214601796408442734516728221165974574716379153167';
let p2 = '2_8656028806505982095326321049235561104042173168568505729179757804449';
p2 += '578346736149906348759626643458706475015957749967889733998903838230885624';
p2 += '594865734248158226568582806135364944456006812377599986439323482789560609';
p2 += '123903616577537215351230548134579725046867440710204574042201708977585319';
p2 += '352822902550993809625935135206670644813733135202081531882006223';
let p3 = '5_1346273105614869123852010059094346269056286846898087885579606473986';
p3 += '046803336654589280041249648650489389961287399273842749062827818101442192';
p3 += '731638668492276330459644946068067803852958538580338570211855464419088469';
p3 += '583862772103779114074016474019900448941812004096076632923071426460402090';
p3 += '5729991961217594417394573659698243685903851300181042849083187319';
let p4 = '5_9698386735097821995805434800552017746890746834947374321048399550491';
p4 += '815794209971175570817187604723987512763834509452589252354264064564412766';
p4 += '983847121898255665274076952700580890085019933034896868062018541570801089';
p4 += '280901633767959780773825022887792463398276934187672065108230041845671192';
p4 += '069760957613164087526854586433340900188944040932307092409028039';
let defaultParameters = [p1, p2, p3, p4];