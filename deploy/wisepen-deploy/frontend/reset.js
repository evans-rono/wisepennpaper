import { postJson, setStatus } from '/shared.js';
import { enhancePasswords } from '/password.js';
import { initThemeToggle } from '/shared.js';

const form = document.querySelector('#resetForm');
const token = new URLSearchParams(location.search).get('token') || '';
form.addEventListener('submit', async (event) => {
  event.preventDefault();
  if (!form.reportValidity() || form.new_password.value !== form.confirm.value) {
    setStatus(form, 'Enter matching passwords.', false);
    return;
  }
  try {
    await postJson('/api/auth/reset-password', { token, code: form.code.value, new_password: form.new_password.value });
    setStatus(form, 'Password reset. You can now sign in.', true);
    form.reset();
    // reset() leaves the strength meter showing the old reading.
    form.querySelectorAll('input[type=password]').forEach((i) => i.dispatchEvent(new Event('input')));
  } catch (error) {
    setStatus(form, error.message, false);
  }
});

// Strength meter and the confirm-field match, as on every other password form.
enhancePasswords(document);
initThemeToggle();
