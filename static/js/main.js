// FindBack Portal Scripts
document.addEventListener('DOMContentLoaded', function () {
    // Auto-dismiss standard alerts after 6 seconds
    document.querySelectorAll('.alert-dismissible').forEach(function (alert) {
        setTimeout(function () {
            const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
            if (bsAlert) { bsAlert.close(); }
        }, 6000);
    });

    // Show / hide password (eye button) on every password field
    var EYE = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
    var EYE_OFF = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
    document.querySelectorAll('input[type="password"]').forEach(function (input) {
        var small = input.classList.contains('form-control-sm');
        var group = document.createElement('div');
        group.className = 'input-group' + (small ? ' input-group-sm' : '');
        input.parentNode.insertBefore(group, input);
        group.appendChild(input);
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-outline-secondary';
        btn.setAttribute('aria-label', 'Show password');
        btn.title = 'Show / hide password';
        btn.innerHTML = EYE;
        btn.addEventListener('click', function () {
            var show = input.type === 'password';
            input.type = show ? 'text' : 'password';
            btn.innerHTML = show ? EYE_OFF : EYE;
            btn.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
        });
        group.appendChild(btn);
    });

    // CAPTCHA recycle button: fetch a new image without reloading (typed fields are kept)
    var refresh = document.getElementById('captcha-refresh');
    if (refresh) {
        refresh.addEventListener('click', function () {
            refresh.disabled = true;
            fetch(refresh.dataset.url, { credentials: 'same-origin', cache: 'no-store' })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    document.getElementById('captcha-image').innerHTML = data.svg;
                    document.querySelector('input[name="captcha_token"]').value = data.token;
                    var answer = document.getElementById('captcha_answer');
                    answer.value = '';
                    answer.focus();
                })
                .catch(function () { window.location.reload(); })
                .finally(function () { refresh.disabled = false; });
        });
    }
});
