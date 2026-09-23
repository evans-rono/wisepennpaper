const COUNTRY_CODES = [
  ['KE', '+254', 'Kenya'], ['US', '+1', 'United States / Canada'], ['GB', '+44', 'United Kingdom'],
  ['UG', '+256', 'Uganda'], ['TZ', '+255', 'Tanzania'], ['ZA', '+27', 'South Africa'],
  ['NG', '+234', 'Nigeria'], ['GH', '+233', 'Ghana'], ['AU', '+61', 'Australia'],
  ['IN', '+91', 'India'], ['AE', '+971', 'United Arab Emirates'], ['DE', '+49', 'Germany'],
];

export function enhancePhoneFields(root = document) {
  root.querySelectorAll('input[data-phone-number]').forEach((input) => {
    const form = input.closest('form') || root;
    const select = form.querySelector(`select[data-phone-country="${input.dataset.phoneNumber}"]`);
    if (!select || select.dataset.ready) return;
    select.innerHTML = COUNTRY_CODES.map(([code, dial, name]) => `<option value="${code}">${dial} ${name}</option>`).join('');
    select.value = input.dataset.phoneCountry || 'KE';
    select.dataset.ready = 'true';
    const sync = () => {
      input.setCustomValidity('');
      if (input.value.trim() && !/^\+?[0-9 ()-]{6,20}$/.test(input.value.trim()))
        input.setCustomValidity('Enter a valid phone number for the selected country.');
    };
    input.addEventListener('input', sync);
    select.addEventListener('change', sync);
  });
}

export function enhanceEmailFields(root = document) {
  root.querySelectorAll('input[type=email]').forEach((input) => {
    const check = () => {
      input.setCustomValidity(input.value.trim() && !/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(input.value.trim())
        ? 'Enter a valid email address.' : '');
    };
    input.addEventListener('input', check);
    input.addEventListener('blur', check);
  });
}

export function setDynamicDateTime(root = document) {
  const today = () => {
    const now = new Date();
    return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  };
  const refresh = () => {
    const now = new Date();
    root.querySelectorAll('input[type=date][data-no-future]').forEach((input) => { input.max = today(); });
    root.querySelectorAll('input[type=date][data-future-date]').forEach((input) => { input.min = today(); });
    root.querySelectorAll('[data-timezone-offset]').forEach((input) => { input.value = String(now.getTimezoneOffset()); });
  };
  refresh();
  root.addEventListener('focusin', refresh);
  addEventListener('pageshow', refresh, { once: true });
  const scheduleRefresh = () => {
    const next = new Date();
    next.setHours(24, 0, 0, 25);
    setTimeout(() => { refresh(); scheduleRefresh(); }, Math.max(1000, next.getTime() - Date.now()));
  };
  scheduleRefresh();
}
