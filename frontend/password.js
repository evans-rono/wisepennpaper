// Password field enhancements: a reveal toggle, a live strength meter and a
// confirmation match indicator.
//
// The scoring here is guidance only — it mirrors the server's rules closely
// enough to be honest, but backend/password.js is the authority and will reject
// anything this misses. Nothing here gates submission; the server does that.

export const MIN_LENGTH = 12;

const COMMON = [
  'password', 'qwerty', '123456', '12345678', '123456789', 'iloveyou', 'admin', 'welcome',
  'letmein', 'monkey', 'dragon', 'sunshine', 'princess', 'football', 'baseball', 'shadow',
  'passw0rd', 'password1', 'qwertyuiop', 'abc123', 'changeme', 'wisepen', 'wisepennpaper',
  'nairobi', 'kenya', 'publishing', 'manuscript',
];

const LEET = { '@': 'a', '4': 'a', '3': 'e', '1': 'i', '!': 'i', '0': 'o', '$': 's', '5': 's', '7': 't', '+': 't' };
const normalise = (s) =>
  s.toLowerCase().replace(/[@4310!$57+]/g, (c) => LEET[c] ?? c).replace(/[^a-z0-9]/g, '');

// Trailing digits survive leet-decoding as noise ("1234" becomes "i2ea"), so
// the stripped forms are checked too. Mirrors variants() in backend/password.js.
function variants(password) {
  const lower = password.toLowerCase();
  const out = new Set();
  for (const base of [lower, lower.replace(/[^a-z0-9]/g, ''), normalise(password)]) {
    out.add(base);
    out.add(base.replace(/[^a-z]+$/, ''));
    out.add(normalise(base.replace(/[^a-z]+$/, '')));
  }
  out.delete('');
  return out;
}

const SEQUENCES = ['abcdefghijklmnopqrstuvwxyz', '1234567890', 'qwertyuiop', 'asdfghjkl', 'zxcvbnm'];
const ADJACENT = new Set();
for (const row of SEQUENCES) {
  for (let i = 1; i < row.length; i++) {
    ADJACENT.add(row[i - 1] + row[i]);
    ADJACENT.add(row[i] + row[i - 1]);
  }
}

const isRun = (s) => {
  const low = s.toLowerCase();
  let best = 1, run = 1;
  for (let i = 1; i < low.length; i++) {
    run = ADJACENT.has(low[i - 1] + low[i]) ? run + 1 : 1;
    if (run > best) best = run;
  }
  return best >= Math.max(6, Math.ceil(s.length * 0.6));
};

const LEVELS = ['Too weak', 'Weak', 'Fair', 'Good', 'Strong'];

// Mirrors COMPOSITION in backend/password.js. A rule shown here is a rule the
// server will actually enforce, so the meter never promises a password the
// submit would reject.
const RULES = [
  { id: 'length', label: (min) => `At least ${min} characters`, test: (pw, min) => pw.length >= min },
  { id: 'number', label: () => 'A number', test: (pw) => /\d/.test(pw) },
  { id: 'uppercase', label: () => 'A capital letter', test: (pw) => /[A-Z]/.test(pw) },
  { id: 'symbol', label: () => 'A special character', test: (pw) => /[^A-Za-z0-9\s]/.test(pw) },
];

export function rate(password, { email = '', name = '' } = {}) {
  const pw = String(password ?? '');
  // Nothing typed yet: stay quiet. The field's own help text already states the
  // requirement, and repeating it here read as a duplicated line.
  if (!pw) return { score: 0, label: '', hint: '' };
  if (pw.length < MIN_LENGTH) {
    return { score: 0, label: LEVELS[0], hint: `${MIN_LENGTH - pw.length} more character${pw.length === MIN_LENGTH - 1 ? '' : 's'} needed.` };
  }
  const norm = normalise(pw);
  const forms = variants(pw);
  if (COMMON.some((c) => forms.has(c))) {
    return { score: 0, label: LEVELS[0], hint: 'That is one of the most guessed passwords.' };
  }
  if (/^(.)\1+$/.test(pw) || isRun(pw)) {
    return { score: 0, label: LEVELS[0], hint: 'Avoid repeated characters or straight key runs.' };
  }
  const personal = [email.split('@')[0], name]
    .filter(Boolean)
    .flatMap((v) => String(v).toLowerCase().split(/[^a-z0-9]+/))
    .filter((p) => p.length >= 4);
  if (personal.some((p) => norm.includes(normalise(p)))) {
    return { score: 1, label: LEVELS[1], hint: 'Avoid your own name or email address.' };
  }
  if (COMMON.some((c) => c.length >= 6 && norm.includes(c))) {
    return { score: 1, label: LEVELS[1], hint: 'Contains a very common word — add something unrelated.' };
  }
  if (new Set(pw).size < 5) {
    return { score: 1, label: LEVELS[1], hint: 'Use a wider mix of characters.' };
  }

  const variety = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(pw)).length;
  let score = 2;
  if (pw.length >= 16) score++;
  if (pw.length >= 20 || variety >= 3) score++;
  score = Math.min(score, 4);
  const hint = score >= 4
    ? 'Strong. A passphrase of a few unrelated words is a good choice.'
    : 'Longer is better — try adding another word.';
  return { score, label: LEVELS[score], hint };
}

/* ------------------------------------------------------------ wiring */

function addReveal(input) {
  if (input.dataset.revealBound) return;
  input.dataset.revealBound = '1';
  const wrap = document.createElement('div');
  wrap.className = 'pw-field';
  input.parentNode.insertBefore(wrap, input);
  wrap.appendChild(input);

  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'pw-reveal';
  btn.setAttribute('aria-pressed', 'false');
  btn.setAttribute('aria-label', 'Show password');
  btn.textContent = 'Show';
  btn.addEventListener('click', () => {
    const shown = input.type === 'text';
    input.type = shown ? 'password' : 'text';
    btn.textContent = shown ? 'Show' : 'Hide';
    btn.setAttribute('aria-pressed', String(!shown));
    btn.setAttribute('aria-label', shown ? 'Show password' : 'Hide password');
    input.focus();
  });
  wrap.appendChild(btn);
  return wrap;
}

function addMeter(input, form) {
  // enhancePasswords may run over the same subtree more than once (a panel is
  // re-rendered, or a parent and child are both enhanced); without this the
  // meter would be appended again each time.
  if (input.dataset.meterBound) return;
  input.dataset.meterBound = '1';
  // Staff fields declare a longer minimum through minlength.
  const min = Number(input.getAttribute('minlength')) || MIN_LENGTH;

  const meter = document.createElement('div');
  meter.className = 'pw-meter';
  meter.innerHTML = `<div class="pw-bar"><i></i></div>
    <ul class="pw-checks">${RULES.map((r) =>
      `<li data-rule="${r.id}"><span class="pw-tick" aria-hidden="true"></span>${r.label(min)}</li>`).join('')}</ul>
    <p class="pw-note"><span class="pw-level"></span> <span class="pw-hint"></span></p>`;
  input.closest('.pw-field').after(meter);

  const bar = meter.querySelector('i');
  const level = meter.querySelector('.pw-level');
  const hint = meter.querySelector('.pw-hint');
  const items = RULES.map((rule) => [rule, meter.querySelector(`[data-rule="${rule.id}"]`)]);

  // The meter is decoration around the input's own description; announcing
  // every keystroke would be noise, so it is not a live region.
  const update = () => {
    const pw = input.value;
    let unmet = 0;
    for (const [rule, li] of items) {
      const met = rule.test(pw, min);
      if (!met) unmet++;
      li.classList.toggle('met', met && pw.length > 0);
      li.setAttribute('aria-label', `${rule.label(min)}: ${met && pw ? 'met' : 'not met'}`);
    }

    const context = {
      email: form?.querySelector('input[type=email]')?.value || '',
      name: form?.querySelector('input[name=name], input[name=full_name]')?.value || '',
    };
    const { score, label, hint: tip } = rate(pw, context);
    // Every rule has to pass before the bar claims anything beyond "too weak".
    const shown = unmet ? Math.min(score, 1) : score;
    meter.dataset.score = String(shown);
    bar.style.width = (pw ? (shown + 1) * 20 : 0) + '%';
    level.textContent = pw ? label : '';
    hint.textContent = pw && !unmet ? tip : '';
  };
  input.addEventListener('input', update);
  update();
}

function addMatch(passwordInput, confirmInput) {
  if (confirmInput.dataset.matchBound) return;
  confirmInput.dataset.matchBound = '1';
  const note = document.createElement('p');
  note.className = 'pw-match';
  note.setAttribute('role', 'status');
  confirmInput.closest('.pw-field').after(note);

  const update = () => {
    if (!confirmInput.value) {
      note.textContent = '';
      note.className = 'pw-match';
      confirmInput.setCustomValidity('');
      return;
    }
    const same = confirmInput.value === passwordInput.value;
    note.textContent = same ? 'Passwords match' : 'Passwords do not match yet';
    note.className = 'pw-match ' + (same ? 'ok' : 'err');
    confirmInput.setCustomValidity(same ? '' : 'The two passwords do not match.');
  };
  passwordInput.addEventListener('input', update);
  confirmInput.addEventListener('input', update);
}

/**
 * Enhances every password field inside `root`. Fields opting into the meter
 * carry data-pw-meter; a confirmation field points at its partner with
 * data-pw-confirm="<name of the password field>".
 */
export function enhancePasswords(root = document) {
  root.querySelectorAll('input[type=password]').forEach((input) => {
    const form = input.closest('form');
    addReveal(input);
    if (input.hasAttribute('data-pw-meter')) addMeter(input, form);
  });
  root.querySelectorAll('[data-pw-confirm]').forEach((confirmInput) => {
    const form = confirmInput.closest('form') || root;
    const partner = form.querySelector(`input[name="${confirmInput.dataset.pwConfirm}"]`);
    if (partner) addMatch(partner, confirmInput);
  });
}
