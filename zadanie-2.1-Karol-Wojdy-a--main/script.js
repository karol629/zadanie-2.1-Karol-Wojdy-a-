/**
 * KeyForge — Advanced & Secure Password Generator
 * 100% Client-Side Cryptographic Implementation
 */

(function () {
  'use strict';

  // --- Character Definitions ---
  const CHAR_SETS = {
    uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
    lowercase: 'abcdefghijklmnopqrstuvwxyz',
    numbers: '0123456789',
    symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?/~',
    ambiguous: '1lI0O8B', // Characters easily confused
  };

  // Curated list of friendly, distinct Polish & universal words for Passphrase generation
  const PASSPHRASE_WORDS = [
    'planeta', 'bateria', 'zegar', 'kompas', 'kamien', 'wicher', 'diament',
    'piorun', 'sokol', 'tygrys', 'ocean', 'labirynt', 'krysztal', 'portal',
    'iskra', 'wektor', 'kwant', 'galaktyka', 'zamek', 'neon', 'sonar',
    'radar', 'orbita', 'feniks', 'bursztyn', 'pulsar', 'meteor', 'wulkan',
    'szmaragd', 'safir', 'granit', 'archipelag', 'satelita', 'kosmos', 'foton',
    'magnes', 'radar', 'szczyt', 'dolyna', 'jaskinia', 'kanion', 'laguna',
    'delta', 'pustynia', 'las', 'tundra', 'tajga', 'preria', 'step',
    'lodowiec', 'fala', 'przyplyw', 'prad', 'koral', 'rafa', 'glebia',
    'otchlan', 'orkan', 'tajfun', 'cyklon', 'zawic', 'bryza', 'halny',
    'szron', 'rosa', 'mgla', 'chmura', 'tecza', 'zorza', 'slonce',
    'ksiezyc', 'kometa', 'asteroida', 'nebula', 'zenit', 'horyzont', 'blask',
    'cienia', 'refleks', 'pryzmat', 'widmo', 'akord', 'rytm', 'tempo',
    'echo', 'fonia', 'harmonia', 'melodia', 'sygnal', 'impuls', 'faza'
  ];

  // --- DOM Elements ---
  const elements = {
    // Mode tabs
    tabRandom: document.getElementById('tab-random'),
    tabPassphrase: document.getElementById('tab-passphrase'),
    randomControls: document.getElementById('random-controls'),
    passphraseControls: document.getElementById('passphrase-controls'),

    // Password display & actions
    passwordDisplay: document.getElementById('password-display'),
    refreshBtn: document.getElementById('refresh-btn'),
    copyBtn: document.getElementById('copy-btn'),
    copyBtnText: document.getElementById('copy-btn-text'),
    generateMainBtn: document.getElementById('generate-main-btn'),
    toggleVisibilityBtn: document.getElementById('toggle-visibility-btn'),
    eyeIcon: document.getElementById('eye-icon'),

    // Strength & Metrics
    strengthText: document.getElementById('strength-text'),
    entropyValue: document.getElementById('entropy-value'),
    meterFill: document.getElementById('meter-fill'),
    crackTimeEstimate: document.getElementById('crack-time-estimate'),
    entropyQualityText: document.getElementById('entropy-quality-text'),

    // Random Controls
    lengthSlider: document.getElementById('length-slider'),
    lengthNumber: document.getElementById('length-number'),
    includeUppercase: document.getElementById('include-uppercase'),
    includeLowercase: document.getElementById('include-lowercase'),
    includeNumbers: document.getElementById('include-numbers'),
    includeSymbols: document.getElementById('include-symbols'),
    excludeAmbiguous: document.getElementById('exclude-ambiguous'),
    guaranteeAll: document.getElementById('guarantee-all'),

    // Passphrase Controls
    wordsCountSlider: document.getElementById('words-count-slider'),
    wordsCountDisplay: document.getElementById('words-count-display'),
    passphraseSeparator: document.getElementById('passphrase-separator'),
    passphraseCapitalize: document.getElementById('passphrase-capitalize'),
    passphraseAddNumber: document.getElementById('passphrase-add-number'),
    passphraseAddSymbol: document.getElementById('passphrase-add-symbol'),

    // History Modal
    toggleHistoryBtn: document.getElementById('toggle-history-btn'),
    historyBadge: document.getElementById('history-counter'),
    historyModal: document.getElementById('history-modal'),
    closeHistoryBtn: document.getElementById('close-history-btn'),
    clearHistoryBtn: document.getElementById('clear-history-btn'),
    historyList: document.getElementById('history-list'),

    // Toast
    toast: document.getElementById('toast'),
    toastMessage: document.getElementById('toast-message'),

    // Presets
    presetButtons: document.querySelectorAll('.preset-pill'),
  };

  // State
  let currentMode = 'random'; // 'random' | 'passphrase'
  let currentPassword = '';
  let isPasswordVisible = true;
  let isScrambling = false;
  let history = [];
  let toastTimeout = null;

  // --- Cryptographically Secure Pseudo-Random Number Generator (CSPRNG) ---
  /**
   * Generates a uniform random integer in the range [0, max - 1] without modulo bias.
   * Uses window.crypto.getRandomValues.
   */
  function secureRandomInt(max) {
    if (max <= 0) return 0;
    const range = 0x100000000; // 2^32
    const limit = range - (range % max);
    const buffer = new Uint32Array(1);
    let value;
    do {
      window.crypto.getRandomValues(buffer);
      value = buffer[0];
    } while (value >= limit);
    return value % max;
  }

  /**
   * Fisher-Yates shuffle with cryptographic randomness
   */
  function secureShuffle(array) {
    for (let i = array.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [array[i], array[j]] = [array[j], array[i]];
    }
    return array;
  }

  // --- Generator Algorithms ---

  /**
   * Generates a complex character-based password
   */
  function generateRandomPassword() {
    let length = parseInt(elements.lengthNumber.value, 10);
    if (isNaN(length) || length < 6) length = 6;
    if (length > 64) length = 64;

    const useUpper = elements.includeUppercase.checked;
    const useLower = elements.includeLowercase.checked;
    const useNumbers = elements.includeNumbers.checked;
    const useSymbols = elements.includeSymbols.checked;
    const excludeAmbiguous = elements.excludeAmbiguous.checked;
    const guarantee = elements.guaranteeAll.checked;

    // Filter sets if ambiguous exclusion is enabled
    const filterAmbiguous = (set) => {
      if (!excludeAmbiguous) return set;
      return set.split('').filter(c => !CHAR_SETS.ambiguous.includes(c)).join('');
    };

    const pools = [];
    if (useUpper) pools.push({ name: 'upper', chars: filterAmbiguous(CHAR_SETS.uppercase) });
    if (useLower) pools.push({ name: 'lower', chars: filterAmbiguous(CHAR_SETS.lowercase) });
    if (useNumbers) pools.push({ name: 'numbers', chars: filterAmbiguous(CHAR_SETS.numbers) });
    if (useSymbols) pools.push({ name: 'symbols', chars: filterAmbiguous(CHAR_SETS.symbols) });

    // Fallback if no sets chosen
    if (pools.length === 0) {
      elements.includeLowercase.checked = true;
      pools.push({ name: 'lower', chars: filterAmbiguous(CHAR_SETS.lowercase) });
    }

    const allChars = pools.map(p => p.chars).join('');
    if (allChars.length === 0) return 'Error';

    const resultChars = [];

    // Guarantee at least one character from each selected pool
    if (guarantee && length >= pools.length) {
      pools.forEach(p => {
        if (p.chars.length > 0) {
          const char = p.chars[secureRandomInt(p.chars.length)];
          resultChars.push(char);
        }
      });
    }

    // Fill the rest up to requested length
    while (resultChars.length < length) {
      const char = allChars[secureRandomInt(allChars.length)];
      resultChars.push(char);
    }

    // Shuffle characters to avoid predictable patterns
    secureShuffle(resultChars);

    return resultChars.join('');
  }

  /**
   * Generates a passphrase based on dictionary words
   */
  function generatePassphrase() {
    const wordCount = parseInt(elements.wordsCountSlider.value, 10) || 4;
    const separator = elements.passphraseSeparator.value;
    const capitalize = elements.passphraseCapitalize.checked;
    const addNumber = elements.passphraseAddNumber.checked;
    const addSymbol = elements.passphraseAddSymbol.checked;

    const words = [];
    for (let i = 0; i < wordCount; i++) {
      let word = PASSPHRASE_WORDS[secureRandomInt(PASSPHRASE_WORDS.length)];
      if (capitalize) {
        word = word.charAt(0).toUpperCase() + word.slice(1);
      }
      words.push(word);
    }

    // Optional random number injection
    if (addNumber && words.length > 0) {
      const num = secureRandomInt(100);
      const targetIndex = secureRandomInt(words.length);
      words[targetIndex] += num;
    }

    // Optional random symbol injection
    if (addSymbol && words.length > 0) {
      const symbolsList = '!@#$%^&*?';
      const symbol = symbolsList[secureRandomInt(symbolsList.length)];
      const targetIndex = secureRandomInt(words.length);
      words[targetIndex] += symbol;
    }

    return words.join(separator);
  }

  // --- Password Strength & Entropy Analysis ---

  /**
   * Computes entropy and evaluates crack resistance
   */
  function analyzePassword(password) {
    if (!password) {
      return { entropy: 0, level: 1, label: 'Brak', time: 'Natychmiast' };
    }

    let poolSize = 0;
    if (currentMode === 'passphrase') {
      const wordCount = parseInt(elements.wordsCountSlider.value, 10) || 4;
      let entropy = wordCount * Math.log2(PASSPHRASE_WORDS.length);
      if (elements.passphraseCapitalize.checked) entropy += wordCount * 1;
      if (elements.passphraseAddNumber.checked) entropy += Math.log2(100);
      if (elements.passphraseAddSymbol.checked) entropy += Math.log2(10);
      return calculateMetrics(entropy);
    }

    // Check charset coverage
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSymbol = /[^a-zA-Z0-9]/.test(password);

    if (hasLower) poolSize += 26;
    if (hasUpper) poolSize += 26;
    if (hasNumber) poolSize += 10;
    if (hasSymbol) poolSize += 32;

    if (poolSize === 0) poolSize = 1;

    const entropy = Math.round(password.length * Math.log2(poolSize));
    return calculateMetrics(entropy);
  }

  function calculateMetrics(entropy) {
    let level = 1;
    let label = 'Bardzo słabe';
    let labelClass = 'weak';
    let time = 'Ułamek sekundy';
    let quality = 'Zbyt słabe — podatne na atak słownikowy';

    if (entropy < 36) {
      level = 1;
      label = 'Bardzo słabe';
      labelClass = 'weak';
      time = '< 1 sekunda';
      quality = 'Hasło podatne na natychmiastowe złamanie';
    } else if (entropy < 55) {
      level = 2;
      label = 'Umiarkowane';
      labelClass = 'fair';
      time = 'Kilka godzin / dni';
      quality = 'Średnie bezpieczeństwo, zalecana większa długość';
    } else if (entropy < 75) {
      level = 3;
      label = 'Dobre';
      labelClass = 'good';
      time = 'Około 200 lat';
      quality = 'Dobre hasło do standardowych kont internetowych';
    } else if (entropy < 100) {
      level = 4;
      label = 'Bardzo silne';
      labelClass = 'strong';
      time = '100 milionów lat';
      quality = 'Zgodne z rygorystycznymi standardami NIST & OWASP';
    } else {
      level = 5;
      label = 'Nieprzeniknione';
      labelClass = 'invincible';
      time = 'Miliardy lat (Odporne na superkomputery)';
      quality = 'Maksymalna kryptograficzna odporność na złamanie';
    }

    return { entropy: Math.round(entropy), level, label, labelClass, time, quality };
  }

  // --- Rendering & Syntax Highlighting ---

  function renderPasswordDisplay(password, animate = false) {
    if (!password) {
      elements.passwordDisplay.innerHTML = '<span class="placeholder">Brak hasła</span>';
      return;
    }

    if (!isPasswordVisible) {
      elements.passwordDisplay.innerHTML = `<span class="char-hidden">${'•'.repeat(password.length)}</span>`;
      return;
    }

    if (animate) {
      runScrambleAnimation(password);
      return;
    }

    displayFormattedChars(password);
  }

  function displayFormattedChars(text) {
    let html = '';
    for (let i = 0; i < text.length; i++) {
      const char = text[i];
      let cls = 'char-lower';
      if (/[A-Z]/.test(char)) cls = 'char-upper';
      else if (/[0-9]/.test(char)) cls = 'char-number';
      else if (/[^a-zA-Z0-9]/.test(char)) cls = 'char-symbol';

      // Escape HTML
      const safeChar = char === '<' ? '&lt;' : (char === '>' ? '&gt;' : (char === '&' ? '&amp;' : char));
      html += `<span class="${cls}">${safeChar}</span>`;
    }
    elements.passwordDisplay.innerHTML = html;
  }

  /**
   * Cyberpunk / Matrix character scramble animation
   */
  function runScrambleAnimation(finalPassword) {
    if (isScrambling) return;
    isScrambling = true;

    const chars = '!<>-_\\/[]{}—=+*^?#________ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let iteration = 0;
    const maxIterations = Math.min(finalPassword.length, 14);
    const speed = 25;

    const interval = setInterval(() => {
      let scrambled = '';
      for (let i = 0; i < finalPassword.length; i++) {
        if (i < iteration) {
          const char = finalPassword[i];
          let cls = 'char-lower';
          if (/[A-Z]/.test(char)) cls = 'char-upper';
          else if (/[0-9]/.test(char)) cls = 'char-number';
          else if (/[^a-zA-Z0-9]/.test(char)) cls = 'char-symbol';
          const safe = char === '<' ? '&lt;' : (char === '>' ? '&gt;' : (char === '&' ? '&amp;' : char));
          scrambled += `<span class="${cls}">${safe}</span>`;
        } else {
          const randomChar = chars[Math.floor(Math.random() * chars.length)];
          scrambled += `<span class="char-symbol">${randomChar}</span>`;
        }
      }
      elements.passwordDisplay.innerHTML = scrambled;

      if (iteration >= finalPassword.length) {
        clearInterval(interval);
        displayFormattedChars(finalPassword);
        isScrambling = false;
      }
      iteration += Math.max(1, Math.floor(finalPassword.length / 8));
    }, speed);
  }

  function updateMetricsUI(metrics) {
    elements.strengthText.textContent = metrics.label;
    elements.strengthText.className = `strength-value ${metrics.labelClass}`;
    elements.entropyValue.textContent = metrics.entropy;
    elements.crackTimeEstimate.textContent = metrics.time;
    elements.entropyQualityText.textContent = metrics.quality;

    // Reset and apply level class
    elements.meterFill.className = `meter-fill strength-level-${metrics.level}`;
  }

  // --- Core Generation Trigger ---

  function generateAndDisplay(animate = true) {
    if (currentMode === 'random') {
      currentPassword = generateRandomPassword();
    } else {
      currentPassword = generatePassphrase();
    }

    renderPasswordDisplay(currentPassword, animate);
    const metrics = analyzePassword(currentPassword);
    updateMetricsUI(metrics);
    addToHistory(currentPassword);
  }

  // --- History Management ---

  function addToHistory(pwd) {
    if (!pwd || pwd.length === 0) return;
    // Don't add duplicate of previous entry
    if (history.length > 0 && history[0] === pwd) return;

    history.unshift(pwd);
    if (history.length > 20) history.pop();

    elements.historyBadge.textContent = history.length;
    renderHistoryList();
  }

  function renderHistoryList() {
    if (history.length === 0) {
      elements.historyList.innerHTML = '<div class="history-empty">Brak historii w bieżącej sesji.</div>';
      return;
    }

    let html = '';
    history.forEach((pwd, idx) => {
      const safePwd = pwd.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      html += `
        <div class="history-item">
          <span class="history-pwd-text">${safePwd}</span>
          <button type="button" class="history-copy-btn" data-index="${idx}">Kopiuj</button>
        </div>
      `;
    });
    elements.historyList.innerHTML = html;

    // Add copy listeners
    elements.historyList.querySelectorAll('.history-copy-btn').forEach(btn => {
      btn.addEventListener('click', (e) => {
        const index = parseInt(e.target.dataset.index, 10);
        copyToClipboard(history[index]);
      });
    });
  }

  // --- Clipboard Integration ---

  async function copyToClipboard(text) {
    if (!text) return;
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
      } else {
        // Fallback for non-https or restricted environments
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        document.execCommand('copy');
        textArea.remove();
      }

      showCopySuccess();
      showToast('Hasło skopiowane do schowka!');
    } catch (err) {
      console.error('Błąd kopiowania do schowka:', err);
      showToast('Nie udało się skopiować hasła');
    }
  }

  function showCopySuccess() {
    elements.copyBtn.classList.add('copied');
    elements.copyBtnText.textContent = 'Skopiowano!';
    setTimeout(() => {
      elements.copyBtn.classList.remove('copied');
      elements.copyBtnText.textContent = 'Kopiuj';
    }, 1800);
  }

  function showToast(msg) {
    if (toastTimeout) clearTimeout(toastTimeout);
    elements.toastMessage.textContent = msg;
    elements.toast.classList.remove('hidden');
    toastTimeout = setTimeout(() => {
      elements.toast.classList.add('hidden');
    }, 2400);
  }

  // --- Presets Implementation ---

  function applyPreset(presetKey) {
    elements.presetButtons.forEach(btn => {
      btn.classList.toggle('active', btn.dataset.preset === presetKey);
    });

    if (currentMode !== 'random') {
      switchMode('random');
    }

    switch (presetKey) {
      case 'ultra':
        setSliderValue(24);
        elements.includeUppercase.checked = true;
        elements.includeLowercase.checked = true;
        elements.includeNumbers.checked = true;
        elements.includeSymbols.checked = true;
        elements.excludeAmbiguous.checked = false;
        elements.guaranteeAll.checked = true;
        break;

      case 'balanced':
        setSliderValue(16);
        elements.includeUppercase.checked = true;
        elements.includeLowercase.checked = true;
        elements.includeNumbers.checked = true;
        elements.includeSymbols.checked = true;
        elements.excludeAmbiguous.checked = false;
        elements.guaranteeAll.checked = true;
        break;

      case 'readable':
        setSliderValue(16);
        elements.includeUppercase.checked = true;
        elements.includeLowercase.checked = true;
        elements.includeNumbers.checked = true;
        elements.includeSymbols.checked = true;
        elements.excludeAmbiguous.checked = true;
        elements.guaranteeAll.checked = true;
        break;

      case 'pin':
        setSliderValue(6);
        elements.includeUppercase.checked = false;
        elements.includeLowercase.checked = false;
        elements.includeNumbers.checked = true;
        elements.includeSymbols.checked = false;
        elements.excludeAmbiguous.checked = false;
        elements.guaranteeAll.checked = false;
        break;
    }

    generateAndDisplay(true);
  }

  function setSliderValue(val) {
    elements.lengthSlider.value = val;
    elements.lengthNumber.value = val;
    updateSliderBackground(elements.lengthSlider);
  }

  function updateSliderBackground(slider) {
    const min = slider.min || 6;
    const max = slider.max || 64;
    const value = slider.value;
    const percent = ((value - min) / (max - min)) * 100;
    slider.style.background = `linear-gradient(to right, #6366f1 0%, #06b6d4 ${percent}%, rgba(255, 255, 255, 0.1) ${percent}%, rgba(255, 255, 255, 0.1) 100%)`;
  }

  // --- Mode Switching ---

  function switchMode(mode) {
    currentMode = mode;
    if (mode === 'random') {
      elements.tabRandom.classList.add('active');
      elements.tabPassphrase.classList.remove('active');
      elements.randomControls.classList.remove('hidden');
      elements.passphraseControls.classList.add('hidden');
    } else {
      elements.tabRandom.classList.remove('active');
      elements.tabPassphrase.classList.add('active');
      elements.randomControls.classList.add('hidden');
      elements.passphraseControls.classList.remove('hidden');
      elements.presetButtons.forEach(btn => btn.classList.remove('active'));
    }
    generateAndDisplay(true);
  }

  // --- Event Listeners Setup ---

  function setupEventListeners() {
    // Mode tabs
    elements.tabRandom.addEventListener('click', () => switchMode('random'));
    elements.tabPassphrase.addEventListener('click', () => switchMode('passphrase'));

    // Generation buttons
    elements.generateMainBtn.addEventListener('click', () => generateAndDisplay(true));
    elements.refreshBtn.addEventListener('click', () => generateAndDisplay(true));

    // Copy actions
    elements.copyBtn.addEventListener('click', () => copyToClipboard(currentPassword));
    elements.passwordDisplay.addEventListener('click', () => copyToClipboard(currentPassword));

    // Password visibility toggle
    elements.toggleVisibilityBtn.addEventListener('click', () => {
      isPasswordVisible = !isPasswordVisible;
      renderPasswordDisplay(currentPassword, false);
      elements.eyeIcon.innerHTML = isPasswordVisible
        ? '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"></path><circle cx="12" cy="12" r="3"></circle>'
        : '<path d="M9.88 9.88a3 3 0 1 0 4.24 4.24"></path><path d="M10.73 5.08A10.43 10.43 0 0 1 12 5c7 0 10 7 10 7a13.16 13.16 0 0 1-1.67 2.68"></path><path d="M6.61 6.61A13.526 13.526 0 0 0 2 12s3 7 10 7a9.74 9.74 0 0 0 5.39-1.61"></path><line x1="2" x2="22" y1="2" y2="22"></line>';
    });

    // Length Slider & Number Input Sync
    elements.lengthSlider.addEventListener('input', (e) => {
      elements.lengthNumber.value = e.target.value;
      updateSliderBackground(elements.lengthSlider);
      generateAndDisplay(false);
      clearActivePresets();
    });

    elements.lengthNumber.addEventListener('change', (e) => {
      let val = parseInt(e.target.value, 10);
      if (isNaN(val) || val < 6) val = 6;
      if (val > 64) val = 64;
      e.target.value = val;
      elements.lengthSlider.value = val;
      updateSliderBackground(elements.lengthSlider);
      generateAndDisplay(false);
      clearActivePresets();
    });

    // Switches in random mode
    const checkboxes = [
      elements.includeUppercase,
      elements.includeLowercase,
      elements.includeNumbers,
      elements.includeSymbols,
      elements.excludeAmbiguous,
      elements.guaranteeAll
    ];

    checkboxes.forEach(cb => {
      cb.addEventListener('change', () => {
        // Prevent all character pools from being disabled
        if (!elements.includeUppercase.checked &&
            !elements.includeLowercase.checked &&
            !elements.includeNumbers.checked &&
            !elements.includeSymbols.checked) {
          cb.checked = true;
          showToast('Przynajmniej jeden typ znaków musi być aktywny!');
          return;
        }
        clearActivePresets();
        generateAndDisplay(false);
      });
    });

    // Passphrase controls
    elements.wordsCountSlider.addEventListener('input', (e) => {
      elements.wordsCountDisplay.textContent = e.target.value;
      updateSliderBackground(elements.wordsCountSlider);
      generateAndDisplay(false);
    });

    elements.passphraseSeparator.addEventListener('change', () => generateAndDisplay(false));
    elements.passphraseCapitalize.addEventListener('change', () => generateAndDisplay(false));
    elements.passphraseAddNumber.addEventListener('change', () => generateAndDisplay(false));
    elements.passphraseAddSymbol.addEventListener('change', () => generateAndDisplay(false));

    // Presets
    elements.presetButtons.forEach(btn => {
      btn.addEventListener('click', () => {
        applyPreset(btn.dataset.preset);
      });
    });

    function clearActivePresets() {
      elements.presetButtons.forEach(b => b.classList.remove('active'));
    }

    // History Modal
    elements.toggleHistoryBtn.addEventListener('click', () => {
      elements.historyModal.classList.remove('hidden');
    });

    elements.closeHistoryBtn.addEventListener('click', () => {
      elements.historyModal.classList.add('hidden');
    });

    elements.historyModal.addEventListener('click', (e) => {
      if (e.target === elements.historyModal) {
        elements.historyModal.classList.add('hidden');
      }
    });

    elements.clearHistoryBtn.addEventListener('click', () => {
      history = [];
      elements.historyBadge.textContent = '0';
      renderHistoryList();
      showToast('Wyczyszczono historię');
    });

    // Keyboard Shortcuts (Spacebar to regenerate, unless typing in an input)
    window.addEventListener('keydown', (e) => {
      if (e.code === 'Space' && !['INPUT', 'SELECT', 'TEXTAREA', 'BUTTON'].includes(e.target.tagName)) {
        e.preventDefault();
        generateAndDisplay(true);
      }
    });
  }

  // --- Initializer ---
  function init() {
    updateSliderBackground(elements.lengthSlider);
    updateSliderBackground(elements.wordsCountSlider);
    setupEventListeners();
    generateAndDisplay(true);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
