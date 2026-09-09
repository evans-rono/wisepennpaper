import { postJson, setStatus } from '/shared.js';

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
  } catch (error) {
    setStatus(form, error.message, false);
  }
});
