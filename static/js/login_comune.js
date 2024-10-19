const togglePassword = document.querySelector('.toggle-password');
const passwordInput = document.querySelector('#password-input');

togglePassword.addEventListener('click', () => {
    // Cambia il tipo di input tra 'password' e 'text'
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);

    // Cambia l'emoji per rappresentare lo stato della visibilità
    togglePassword.textContent = type === 'password' ? '👁️' : '🙈';
});

