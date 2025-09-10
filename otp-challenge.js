document.addEventListener('DOMContentLoaded', function() {
    console.log('OTP Challenge JS loaded');

    const otpInput = document.querySelector('.otp-input');
    const submitBtn = document.querySelector('.btn-primary');
    const form = document.getElementById('otp-form');

    // Focus on OTP input when page loads
    if (otpInput) {
        otpInput.focus();
    }

    // DEBUG: Log all form submission attempts
    if (form) {
        form.addEventListener('submit', function(e) {

            // Block ALL submissions except our button
            e.preventDefault();
            e.stopImmediatePropagation();
            return false;
        }, true); // Use capture phase
    }



    // Only handle manual button click
    if (submitBtn) {
        submitBtn.addEventListener('click', function(e) {
            console.log('Button clicked manually');
            e.preventDefault();

            const otpValue = otpInput?.value?.trim();

            if (!otpValue) {
                alert('Inserisci il codice OTP');
                return false;
            }

            // Show loading state
            submitBtn.disabled = true;
            submitBtn.textContent = 'Verifica in corso...';

            console.log('Manually submitting form with value:', otpValue);

            // Create new form data and submit manually via fetch
            const formData = new FormData(form);

            fetch(form.action, {
                method: 'POST',
                body: formData
            }).then(response => {
                if (response.redirected) {
                    window.location.href = response.url;
                } else {
                    return response.text().then(text => {
                        document.open();
                        document.write(text);
                        document.close();
                    });
                }
            }).catch(error => {
                console.error('Submit error:', error);
                alert('Errore durante la verifica');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Verifica OTP';
            });
        });
    }

    // DEBUG: Detect what's trying to submit the form
    const originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
        console.log('Form.submit() called on:', this);
        console.log('Stack trace:', new Error().stack);

        if (this === form) {
            console.log('Our form submit blocked!');
            return false;
        }

        return originalSubmit.call(this);
    };
});
