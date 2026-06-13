// FORTRESS Password Strength Analyzer & Generator - Core Application Logic

// --- Word list for Memorable Passphrase Generator ---
const WORDLIST = [
    "quantum", "cyber", "fortress", "cipher", "shield", "nexus", "matrix", "beacon",
    "vector", "vertex", "glitch", "nebula", "aurora", "comet", "hazard", "kernel",
    "binary", "shadow", "beacon", "sensor", "vortex", "plasma", "carbon", "silicon",
    "crypto", "entropy", "bypass", "signal", "uplink", "fission", "fusion", "helium",
    "cobalt", "galaxy", "eclipse", "horizon", "gravity", "pulsar", "magnet", "photon",
    "proton", "neutron", "atomic", "cosmic", "strata", "basalt", "glacier", "tundra",
    "canyon", "desert", "forest", "jungle", "summit", "crater", "canyon", "trench",
    "octane", "diesel", "fossil", "hybrid", "rocket", "turbine", "rudder", "anchor",
    "spiral", "radius", "matrix", "tensor", "scalar", "octave", "rhythm", "melody",
    "indigo", "violet", "emerald", "amber", "copper", "bronze", "silver", "quartz"
];

// --- Helper Cryptographic Hash Functions (Web Crypto API) ---
async function hashSHA1(string) {
    const utf8 = new TextEncoder().encode(string);
    const hashBuffer = await crypto.subtle.digest('SHA-1', utf8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

async function hashSHA256(string) {
    const utf8 = new TextEncoder().encode(string);
    const hashBuffer = await crypto.subtle.digest('SHA-256', utf8);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- DOM Elements ---
const passwordInput = document.getElementById('password-input');
const togglePasswordBtn = document.getElementById('toggle-password-btn');
const eyeIconShow = togglePasswordBtn.querySelector('.eye-icon-show');
const eyeIconHide = togglePasswordBtn.querySelector('.eye-icon-hide');

const strengthBar = document.getElementById('strength-bar');
const strengthText = document.getElementById('strength-text');
const crackTimeText = document.getElementById('crack-time');
const entropyBadge = document.getElementById('entropy-badge');

const valList = document.getElementById('validation-list');
const rules = {
    length: valList.querySelector('[data-rule="length"]'),
    uppercase: valList.querySelector('[data-rule="uppercase"]'),
    lowercase: valList.querySelector('[data-rule="lowercase"]'),
    number: valList.querySelector('[data-rule="number"]'),
    symbol: valList.querySelector('[data-rule="symbol"]'),
    breached: valList.querySelector('[data-rule="breached"]')
};

const leakBadge = document.getElementById('leak-badge');
const leakDetails = document.getElementById('leak-details');

// Generator elements
const tabPassword = document.getElementById('tab-password');
const tabPassphrase = document.getElementById('tab-passphrase');
const passwordOptions = document.getElementById('password-options');
const passphraseOptions = document.getElementById('passphrase-options');
const generatedPassword = document.getElementById('generated-password');
const generateBtn = document.getElementById('generate-btn');
const copyBtn = document.getElementById('copy-btn');

const genLength = document.getElementById('gen-length');
const lengthVal = document.getElementById('length-val');
const genUpper = document.getElementById('gen-upper');
const genLower = document.getElementById('gen-lower');
const genNumbers = document.getElementById('gen-numbers');
const genSymbols = document.getElementById('gen-symbols');

const genWords = document.getElementById('gen-words');
const wordsVal = document.getElementById('words-val');
const genSeparator = document.getElementById('gen-separator');
const genCapitalize = document.getElementById('gen-capitalize');
const genAppendNumber = document.getElementById('gen-append-number');

// Database Simulator elements
const dbHistoryCount = document.getElementById('db-history-count');
const savePasswordBtn = document.getElementById('save-password-btn');
const dbAlert = document.getElementById('db-alert');
const historyEmpty = document.getElementById('history-empty');
const historyList = document.getElementById('history-list');

// State Variables
let generatorMode = 'password'; // 'password' or 'passphrase'
let dbHistory = [];
let leakCheckTimeout = null;

// --- Initialize App ---
document.addEventListener('DOMContentLoaded', () => {
    loadDatabaseHistory();
    setupEventListeners();
    triggerGenerator(); // Initial password generation
});

function setupEventListeners() {
    // Password Input Events
    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;
        analyzePassword(val);
        
        // Debounce HaveIBeenPwned leak checker to avoid hitting API limits/spamming
        clearTimeout(leakCheckTimeout);
        if (val) {
            updateLeakStatus('checking');
            leakCheckTimeout = setTimeout(() => {
                checkBreachAPI(val);
            }, 600);
        } else {
            resetLeakStatus();
        }
    });

    // Show/Hide Toggle
    togglePasswordBtn.addEventListener('click', () => {
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            eyeIconShow.classList.add('hidden');
            eyeIconHide.classList.remove('hidden');
        } else {
            passwordInput.type = 'password';
            eyeIconShow.classList.remove('hidden');
            eyeIconHide.classList.add('hidden');
        }
    });

    // Generator Tabs
    tabPassword.addEventListener('click', () => {
        generatorMode = 'password';
        tabPassword.classList.add('active');
        tabPassphrase.classList.remove('active');
        passwordOptions.classList.remove('hidden');
        passphraseOptions.classList.add('hidden');
    });

    tabPassphrase.addEventListener('click', () => {
        generatorMode = 'passphrase';
        tabPassphrase.classList.add('active');
        tabPassword.classList.remove('active');
        passphraseOptions.classList.remove('hidden');
        passwordOptions.classList.add('hidden');
    });

    // Slider Updates
    genLength.addEventListener('input', () => {
        lengthVal.textContent = genLength.value;
    });

    genWords.addEventListener('input', () => {
        wordsVal.textContent = genWords.value;
    });

    // Generate Action
    generateBtn.addEventListener('click', triggerGenerator);

    // Copy Action
    copyBtn.addEventListener('click', () => {
        const text = generatedPassword.textContent;
        if (text && text !== "Click Generate Below") {
            navigator.clipboard.writeText(text).then(() => {
                copyBtn.classList.add('copied');
                setTimeout(() => {
                    copyBtn.classList.remove('copied');
                }, 1800);
            });
        }
    });

    // Database Actions
    savePasswordBtn.addEventListener('click', savePasswordToSimulator);
}

// --- Password Analyzer & Crack Estimator ---
function analyzePassword(password) {
    if (!password) {
        resetAnalysis();
        return;
    }

    // Check individual criteria rules
    const rulesState = {
        length: password.length >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    // Update Checklist UI
    for (const [key, val] of Object.entries(rulesState)) {
        if (val) {
            rules[key].classList.add('valid');
            rules[key].classList.remove('invalid');
        } else {
            rules[key].classList.remove('valid');
            rules[key].classList.add('invalid');
        }
    }

    // Calculate Pool Size (R) based on character types present
    let poolSize = 0;
    if (rulesState.lowercase) poolSize += 26;
    if (rulesState.uppercase) poolSize += 26;
    if (rulesState.number) poolSize += 10;
    if (rulesState.symbol) poolSize += 33;
    if (poolSize === 0) poolSize = 95; // Default if nothing matches

    // Calculate Entropy: E = L * log2(R)
    const entropy = Math.round(password.length * Math.log2(poolSize));
    entropyBadge.textContent = `${entropy} Bits`;
    entropyBadge.classList.add('active-entropy');

    // Determine strength level
    let strength = 0; // 0: Very Weak, 1: Weak, 2: Medium, 3: Strong, 4: Very Strong
    if (entropy < 28) {
        strength = 0;
    } else if (entropy >= 28 && entropy < 36) {
        strength = 1;
    } else if (entropy >= 36 && entropy < 60) {
        strength = 2;
    } else if (entropy >= 60 && entropy < 80) {
        strength = 3;
    } else {
        strength = 4;
    }

    // Check if the password has all key character sets, reduce strength if missing basics
    const hasVariety = (rulesState.lowercase || rulesState.uppercase) && rulesState.number;
    if (strength >= 3 && !hasVariety) {
        strength = 2; // Cap at medium if lacks basic diversity
    }

    // Update Visual Strength Meter
    let strengthLabel = 'Very Weak';
    let meterWidth = '5%';
    let strengthColorHex = 'var(--clr-strength-0)';
    let strengthColorRgb = '244, 63, 94';

    switch (strength) {
        case 0:
            strengthLabel = 'Very Weak';
            meterWidth = '15%';
            strengthColorHex = 'var(--clr-strength-0)';
            strengthColorRgb = '244, 63, 94';
            break;
        case 1:
            strengthLabel = 'Weak';
            meterWidth = '35%';
            strengthColorHex = 'var(--clr-strength-1)';
            strengthColorRgb = '251, 113, 133';
            break;
        case 2:
            strengthLabel = 'Medium';
            meterWidth = '55%';
            strengthColorHex = 'var(--clr-strength-2)';
            strengthColorRgb = '251, 191, 36';
            break;
        case 3:
            strengthLabel = 'Strong';
            meterWidth = '80%';
            strengthColorHex = 'var(--clr-strength-3)';
            strengthColorRgb = '56, 189, 248';
            break;
        case 4:
            strengthLabel = 'Very Strong';
            meterWidth = '100%';
            strengthColorHex = 'var(--clr-strength-4)';
            strengthColorRgb = '16, 185, 129';
            break;
    }

    // Apply strength themes via custom CSS variables
    document.documentElement.style.setProperty('--strength-color', strengthColorHex);
    document.documentElement.style.setProperty('--strength-color-rgb', strengthColorRgb);
    
    strengthBar.style.width = meterWidth;
    strengthBar.style.backgroundColor = strengthColorHex;
    strengthText.textContent = strengthLabel;

    // Estimate Crack Time (assuming 10 billion/second guesses offline)
    const crackTime = estimateCrackTime(entropy);
    crackTimeText.textContent = `crack time: ${crackTime}`;
}

function resetAnalysis() {
    document.documentElement.style.setProperty('--strength-color', 'var(--text-muted)');
    document.documentElement.style.setProperty('--strength-color-rgb', '100, 116, 139');
    
    strengthBar.style.width = '0%';
    strengthText.textContent = 'Empty';
    crackTimeText.textContent = 'crack time: instant';
    
    entropyBadge.textContent = '0 Bits';
    entropyBadge.classList.remove('active-entropy');

    for (const rule of Object.values(rules)) {
        rule.classList.remove('valid');
        rule.classList.remove('invalid');
    }
}

function estimateCrackTime(entropy) {
    // Number of combinations
    const combinations = Math.pow(2, entropy);
    
    // Hashrate: 10 billion guesses/second (Standard GPU rig)
    const guessesPerSec = 10000000000;
    const seconds = (combinations / 2) / guessesPerSec; // Average time to find is half search space

    if (seconds < 1) return "instant";
    if (seconds < 60) return `${Math.round(seconds)} seconds`;
    
    const minutes = seconds / 60;
    if (minutes < 60) return `${Math.round(minutes)} minutes`;
    
    const hours = minutes / 60;
    if (hours < 24) return `${Math.round(hours)} hours`;
    
    const days = hours / 24;
    if (days < 365) return `${Math.round(days)} days`;
    
    const years = days / 365;
    if (years < 1000) return `${Math.round(years)} years`;
    if (years < 1000000) return `${Math.round(years / 1000)}k years`;
    return "centuries";
}

// --- HaveIBeenPwned API Range Integration (k-Anonymity) ---
async function checkBreachAPI(password) {
    try {
        const hash = await hashSHA1(password);
        const prefix = hash.substring(0, 5);
        const suffix = hash.substring(5);

        // Fetch range matching prefix
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        
        if (!response.ok) {
            throw new Error("API call failed");
        }

        const data = await response.text();
        const lines = data.split('\n');
        
        let leakCount = 0;
        for (const line of lines) {
            const [lineSuffix, count] = line.trim().split(':');
            if (lineSuffix === suffix) {
                leakCount = parseInt(count, 10);
                break;
            }
        }

        if (leakCount > 0) {
            updateLeakStatus('leaked', leakCount);
        } else {
            updateLeakStatus('safe');
        }
    } catch (error) {
        console.error("Failed to fetch HIBP range API:", error);
        updateLeakStatus('neutral', null, "Failed to connect to leak repository. Check your connection.");
    }
}

function updateLeakStatus(status, count = 0, customMessage = null) {
    leakBadge.className = 'leak-status-badge'; // Reset classes
    
    if (status === 'checking') {
        leakBadge.classList.add('checking');
        leakBadge.textContent = 'STATUS: SCANNING...';
        leakDetails.innerHTML = 'Connecting cryptographically to breach database...';
        document.documentElement.style.setProperty('--leak-border-color', 'var(--accent)');
        
        rules.breached.classList.remove('valid');
        rules.breached.classList.remove('invalid');
    } else if (status === 'safe') {
        leakBadge.classList.add('safe');
        leakBadge.textContent = 'STATUS: SECURE';
        leakDetails.innerHTML = '🛡️ Zero breaches detected. This password does not exist in any parsed credential leak files.';
        document.documentElement.style.setProperty('--leak-border-color', 'var(--clr-strength-4)');
        
        rules.breached.classList.add('valid');
        rules.breached.classList.remove('invalid');
    } else if (status === 'leaked') {
        leakBadge.classList.add('leaked');
        leakBadge.textContent = 'STATUS: LEAKED!';
        leakDetails.innerHTML = `⚠️ Exposed <strong>${count.toLocaleString()} times</strong> in public data leaks. Do not use this password online!`;
        document.documentElement.style.setProperty('--leak-border-color', 'var(--clr-strength-0)');
        
        rules.breached.classList.remove('valid');
        rules.breached.classList.add('invalid');
    } else {
        leakBadge.classList.add('neutral');
        leakBadge.textContent = 'STATUS: OFFLINE';
        leakDetails.innerHTML = customMessage || 'Unable to scan leaks. Re-type character to retry.';
        document.documentElement.style.setProperty('--leak-border-color', 'var(--text-muted)');
        
        rules.breached.classList.remove('valid');
        rules.breached.classList.remove('invalid');
    }
}

function resetLeakStatus() {
    leakBadge.className = 'leak-status-badge neutral';
    leakBadge.textContent = 'STATUS: WAITING';
    leakDetails.innerHTML = 'Enter a password to initiate a privacy-preserving breach check.';
    document.documentElement.style.setProperty('--leak-border-color', 'var(--text-muted)');
    
    rules.breached.classList.remove('valid');
    rules.breached.classList.remove('invalid');
}

// --- Password & Passphrase Generator ---
function triggerGenerator() {
    let result = '';
    if (generatorMode === 'password') {
        result = generateRandomPassword();
    } else {
        result = generateMemorablePassphrase();
    }
    
    generatedPassword.textContent = result;
    
    // Automatically evaluate the generated password in the analyzer if the analyzer is empty or we want to help user see how good it is
    // Let's copy to input to let user preview immediately!
    passwordInput.value = result;
    analyzePassword(result);
    clearTimeout(leakCheckTimeout);
    updateLeakStatus('checking');
    leakCheckTimeout = setTimeout(() => {
        checkBreachAPI(result);
    }, 600);
}

function generateRandomPassword() {
    const length = parseInt(genLength.value, 10);
    const useUpper = genUpper.checked;
    const useLower = genLower.checked;
    const useNumbers = genNumbers.checked;
    const useSymbols = genSymbols.checked;

    const lowerPool = 'abcdefghijklmnopqrstuvwxyz';
    const upperPool = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    const numberPool = '0123456789';
    const symbolPool = '!@#$%^&*()_+-=[]{}|;:,.<>?';

    let pool = '';
    let requiredCharacters = [];

    // Ensure we satisfy chosen parameters by pre-populating one character of each type
    if (useLower) {
        pool += lowerPool;
        requiredCharacters.push(getRandomChar(lowerPool));
    }
    if (useUpper) {
        pool += upperPool;
        requiredCharacters.push(getRandomChar(upperPool));
    }
    if (useNumbers) {
        pool += numberPool;
        requiredCharacters.push(getRandomChar(numberPool));
    }
    if (useSymbols) {
        pool += symbolPool;
        requiredCharacters.push(getRandomChar(symbolPool));
    }

    if (pool.length === 0) {
        return "Select character options!";
    }

    // Fill the remaining length with random selections from the total pool
    const remainingLength = length - requiredCharacters.length;
    const array = new Uint32Array(remainingLength);
    window.crypto.getRandomValues(array);

    for (let i = 0; i < remainingLength; i++) {
        const idx = array[i] % pool.length;
        requiredCharacters.push(pool[idx]);
    }

    // Shuffle the array to distribute required characters randomly
    return shuffleArray(requiredCharacters).join('');
}

function generateMemorablePassphrase() {
    const wordCount = parseInt(genWords.value, 10);
    const useSeparator = genSeparator.checked;
    const capitalize = genCapitalize.checked;
    const appendNum = genAppendNumber.checked;

    let selectedWords = [];
    const array = new Uint32Array(wordCount);
    window.crypto.getRandomValues(array);

    for (let i = 0; i < wordCount; i++) {
        let word = WORDLIST[array[i] % WORDLIST.length];
        if (capitalize) {
            word = word.charAt(0).toUpperCase() + word.slice(1);
        }
        selectedWords.push(word);
    }

    let result = selectedWords.join(useSeparator ? '-' : ' ');

    if (appendNum) {
        const numArr = new Uint32Array(1);
        window.crypto.getRandomValues(numArr);
        const randomNum = numArr[0] % 100; // number 0-99
        result += (useSeparator ? '-' : '') + randomNum;
    }

    return result;
}

function getRandomChar(pool) {
    const array = new Uint32Array(1);
    window.crypto.getRandomValues(array);
    return pool[array[0] % pool.length];
}

// Fisher-Yates Shuffle utilizing cryptographically secure indexes
function shuffleArray(array) {
    const rands = new Uint32Array(array.length);
    window.crypto.getRandomValues(rands);
    
    for (let i = array.length - 1; i > 0; i--) {
        const j = rands[i] % (i + 1);
        [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
}

// --- Enterprise Database Simulation (localStorage) ---
function loadDatabaseHistory() {
    const stored = localStorage.getItem('fortress_db_history');
    if (stored) {
        try {
            dbHistory = JSON.parse(stored);
        } catch (e) {
            dbHistory = [];
        }
    }
    updateDatabaseUI();
}

async function savePasswordToSimulator() {
    const password = passwordInput.value;
    
    if (!password) {
        showDBAlert('error', 'Cannot store an empty password.');
        return;
    }

    // Calculate SHA-256 for secure storage simulation
    const hash = await hashSHA256(password);
    
    // Check if hash matches any hash in the database history
    const isReused = dbHistory.some(entry => entry.hash === hash);

    if (isReused) {
        showDBAlert('error', '⛔ Enterprise policy violation! Cannot reuse any of your last 5 stored passwords.');
        dbAlert.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        return;
    }

    // Insert new entry at the top of the history stack
    const newEntry = {
        hash: hash.substring(0, 24) + '...', // truncate display hash
        timestamp: new Date().toLocaleTimeString() + ' ' + new Date().toLocaleDateString()
    };

    dbHistory.unshift(newEntry);
    
    // Enforce history size limit of 5 entries
    if (dbHistory.length > 5) {
        dbHistory.pop();
    }

    // Save to LocalStorage
    localStorage.setItem('fortress_db_history', JSON.stringify(dbHistory));

    showDBAlert('success', '✅ Password verified and stored in history map successfully. Next change cannot reuse this!');
    updateDatabaseUI();
}

function updateDatabaseUI() {
    dbHistoryCount.textContent = `${dbHistory.length} Stored`;

    if (dbHistory.length === 0) {
        historyEmpty.classList.remove('hidden');
        historyList.classList.add('hidden');
    } else {
        historyEmpty.classList.add('hidden');
        historyList.classList.remove('hidden');
        
        historyList.innerHTML = '';
        dbHistory.forEach((entry, index) => {
            const li = document.createElement('li');
            li.className = 'history-item';
            li.innerHTML = `
                <div>
                    <span class="history-index">[H-${index + 1}]</span>
                    <span class="history-hash" title="${entry.hash}">${entry.hash}</span>
                </div>
                <span class="history-date">${entry.timestamp.split(' ')[0]}</span>
            `;
            historyList.appendChild(li);
        });
    }
}

function showDBAlert(type, message) {
    dbAlert.classList.remove('hidden', 'error', 'success');
    dbAlert.classList.add(type);
    dbAlert.textContent = message;

    // Auto dismiss success alerts, leave errors
    if (type === 'success') {
        setTimeout(() => {
            dbAlert.classList.add('hidden');
        }, 5000);
    }
}
