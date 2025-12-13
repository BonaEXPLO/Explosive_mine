let LANG = 'fr';

// Helpers pour traductions
const t = (en, fr) => LANG === 'fr' ? fr : en;

// Screens
const welcomeScreen = document.getElementById('welcomeScreen');
const alertScreen = document.getElementById('alertScreen');
const choiceScreen = document.getElementById('choiceScreen');
const dashboardScreen = document.getElementById('dashboardScreen');
const createWalletModal = document.getElementById('createWalletModal');

// Boutons et langue
document.getElementById('langSelect').onchange = (e) => {
    LANG = e.target.value;
};

// Écran d'accueil -> alerte
document.getElementById('welcomeContinue').onclick = () => {
    welcomeScreen.style.display = 'none';
    alertScreen.style.display = 'block';
};

// Alerte -> choix
document.getElementById('alertContinue').onclick = () => {
    alertScreen.style.display = 'none';
    choiceScreen.style.display = 'block';
};

// ---------------- DASHBOARD ----------------
const startDashboard = () => {
    const update = async () => {
        try {
            const r = await fetch('/api/status');
            const s = await r.json();

            document.getElementById('height').textContent = Number(s.height).toLocaleString();
            document.getElementById('peers').textContent = s.peers;
            document.getElementById('address').textContent = s.address || t("No wallet loaded","Aucun wallet chargé");
            document.getElementById('balance').textContent = parseFloat(s.balance_exp).toFixed(6);
            document.getElementById('imani').textContent = parseFloat(s.balance_im).toFixed(4);

            const statusEl = document.getElementById('netStatus');
            statusEl.textContent = s.synced ? "SYNCED ✅" : "SYNCING ⏳";
            statusEl.style.background = s.synced ? "#00ff88" : "#ff0066";
        } catch(e) {
            console.log("⏳ " + t("Waiting for node...","En attente du nœud..."));
        }
    };

    update();
    setInterval(update, 4000);
};

// ---------------- WALLET ----------------
document.getElementById('createBtn').onclick = () => createWalletModal.style.display = 'flex';

document.getElementById('restoreBtn').onclick = async () => {
    const mnemonic = prompt(t("Enter your mnemonic:","Entrez votre phrase mnémonique :"));
    const pw = prompt(t("Enter your password:","Entrez votre mot de passe :"));
    if(!mnemonic || !pw) return;

    const r = await fetch('/api/wallet/restore', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:`mnemonic=${encodeURIComponent(mnemonic)}&password=${encodeURIComponent(pw)}`
    });

    const res = await r.json();
    if(res.success){
        alert(t("Wallet restored!","Wallet restauré !") + "\n" + res.address);
        choiceScreen.style.display = 'none';
        dashboardScreen.style.display = 'block';
        startDashboard();
    } else {
        alert(t("Error: ","Erreur : ") + res.message);
    }
};

// ---------------- CREATION WALLET ----------------
const revealBtn = document.getElementById('revealMnemonicBtn');
const mnemonicDisplay = document.getElementById('mnemonicDisplay');
const copyMnemonicBtn = document.getElementById('copyMnemonicBtn');
const stepVerify = document.getElementById('stepVerify');
const verifyForm = document.getElementById('verifyForm');
const stepPassword = document.getElementById('stepPassword');
const pw1 = document.getElementById('pw1');
const pw2 = document.getElementById('pw2');
const togglePw = document.getElementById('togglePw');
const createWalletBtn = document.getElementById('createWalletBtn');

let mnemonicWords = [];
let verifyIndexes = [];

// Étape 1 — Générer / révéler la phrase
revealBtn.onclick = async () => {
    const r = await fetch('/api/wallet/create-temp', { method:'POST' });
    const res = await r.json();
    if(res.success){
        mnemonicWords = res.data.mnemonic.split(' ');
        mnemonicDisplay.textContent = res.data.mnemonic;
        mnemonicDisplay.style.display = 'block';
        copyMnemonicBtn.style.display = 'inline-block';
        revealBtn.style.display = 'none';

        // Sélectionner 4 mots différents
        verifyIndexes = [];
        while(verifyIndexes.length < 4){
            const idx = Math.floor(Math.random() * 24);
            if(!verifyIndexes.includes(idx)) verifyIndexes.push(idx);
        }

        document.getElementById('verifyLabel1').textContent = verifyIndexes[0] + 1;
        document.getElementById('verifyLabel2').textContent = verifyIndexes[1] + 1;
        document.getElementById('verifyLabel3').textContent = verifyIndexes[2] + 1;
        document.getElementById('verifyLabel4').textContent = verifyIndexes[3] + 1;

        stepVerify.style.display = 'block';
    }
};

// Copier la phrase
copyMnemonicBtn.onclick = () => {
    navigator.clipboard.writeText(mnemonicDisplay.textContent);
    alert(t("Mnemonic copied!","Mnémonique copiée !"));
};

// Étape 2 — Vérifier 4 mots
verifyForm.onsubmit = (e) => {
    e.preventDefault();

    const inputs = [
        document.getElementById('word1').value.trim(),
        document.getElementById('word2').value.trim(),
        document.getElementById('word3').value.trim(),
        document.getElementById('word4').value.trim()
    ];

    let correct = true;
    for(let i=0;i<4;i++){
        if(inputs[i] !== mnemonicWords[verifyIndexes[i]]){
            correct = false;
            break;
        }
    }

    if(correct){
        stepVerify.style.display = 'none';
        stepPassword.style.display = 'block';
    } else {
        alert(t("Incorrect words!","❌ Mots incorrects ! Veuillez recommencer."));
    }
};

// Mot de passe visible / caché
togglePw.onchange = () => {
    const type = togglePw.checked ? 'text' : 'password';
    pw1.type = type;
    pw2.type = type;
};

// Étape 3 — Créer le wallet final
createWalletBtn.onclick = async () => {
    const password = pw1.value.trim();
    const confirm = pw2.value.trim();

    if(password !== confirm) return alert(t("Passwords do not match!","Les mots de passe ne correspondent pas !"));
    if(!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$/.test(password)){
        return alert(t("Weak password!","Mot de passe trop faible !"));
    }

    const r = await fetch('/api/wallet/create', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:`password=${encodeURIComponent(password)}&mnemonic=${encodeURIComponent(mnemonicDisplay.textContent)}`
    });

    const res = await r.json();
    if(res.success){
        alert(t("Wallet created! Address: ","Wallet créé ! Adresse : ") + res.data.address);
        createWalletModal.style.display = 'none';
        dashboardScreen.style.display = 'block';
        startDashboard();
    } else {
        alert(t("Error: ","Erreur : ") + res.message);
    }
};

// ---------------- REVEAL EXISTING WALLET ----------------
const revealExistingBtn = document.getElementById('revealExistingMnemonic');
revealExistingBtn.onclick = async () => {
    const pw = prompt(t("Enter your password:","Entrez votre mot de passe :"));
    if(!pw) return;

    const r = await fetch('/api/wallet/reveal', {
        method:'POST',
        headers:{'Content-Type':'application/x-www-form-urlencoded'},
        body:`password=${encodeURIComponent(pw)}`
    });
    const res = await r.json();
    if(res.success){
        alert(t("Mnemonic: ","Phrase mnémonique : ") + res.mnemonic);
    } else {
        alert(t("Invalid password!","Mot de passe incorrect !"));
    }
};

// ---------------- SEND / RECEIVE ----------------
const sendModal = document.getElementById('sendModal');
const receiveModal = document.getElementById('receiveModal');

document.getElementById('sendBtn').onclick = () => sendModal.style.display = 'flex';
document.getElementById('receiveBtn').onclick = () => {
    receiveModal.style.display = 'flex';
    document.getElementById('receiveAddress').textContent = document.getElementById('address').textContent;
};

// Fermer modales
[...document.querySelectorAll('.modal .close')].forEach(c => {
    c.onclick = () => c.parentElement.parentElement.style.display = 'none';
});

// Copier adresse
document.getElementById('copyReceiveBtn').onclick = () => {
    navigator.clipboard.writeText(document.getElementById('receiveAddress').textContent);
    alert(t("Address copied!","Adresse copiée !"));
};

// Validation adresse EXPLOSIVE
const isValidAddress = (addr) => {
    if(!addr.startsWith('explo')) return false;
    if(addr.length !== 53) return false;
    return true;
};

// Envoyer
document.getElementById('confirmSendBtn').onclick = async () => {
    const addr = document.getElementById('sendAddress').value.trim();
    const amount = parseFloat(document.getElementById('sendAmount').value);
    const pw = document.getElementById('sendPassword').value.trim();

    if(!isValidAddress(addr)) return alert(t("Invalid address!","Adresse invalide !"));
    if(isNaN(amount) || amount <= 0) return alert(t("Invalid amount!","Montant invalide !"));
    if(amount > parseFloat(document.getElementById('balance').textContent)) return alert(t("Insufficient balance!","Solde insuffisant !"));
    if(!pw) return alert(t("Password required!","Mot de passe requis !"));

    try {
        const r = await fetch('/api/wallet/send', {
            method:'POST',
            headers:{'Content-Type':'application/x-www-form-urlencoded'},
            body:`address=${encodeURIComponent(addr)}&amount=${amount}&password=${encodeURIComponent(pw)}`
        });
        const res = await r.json();
        if(res.success){
            alert(t("Transaction sent! TxID: ","Transaction envoyée ! TxID: ") + res.txid);
            sendModal.style.display = 'none';
            startDashboard();
        } else {
            alert(t("Error: ","Erreur : ") + res.message);
        }
    } catch(e) {
        alert(t("Network error or incorrect password!","Erreur réseau ou mot de passe incorrect !"));
    }
};
