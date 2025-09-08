// PKCE Token Exchange JavaScript
console.log('PKCE Token Exchange script loaded');

document.addEventListener('DOMContentLoaded', function() {
    async function completeTokenExchange() {
        try {
            const tokenUrl = document.body.getAttribute('data-token-url');
            const authorizationCode = document.body.getAttribute('data-authorization-code');
            const codeVerifier = document.body.getAttribute('data-code-verifier');

            console.log('Completing token exchange...');
            console.log('Token URL:', tokenUrl);
            console.log('Authorization Code preview:', authorizationCode ? authorizationCode.substring(0, 10) + '...' : 'NULL');
            console.log('Code Verifier preview:', codeVerifier ? codeVerifier.substring(0, 10) + '...' : 'NULL');

            if (!tokenUrl || !authorizationCode || !codeVerifier) {
                throw new Error('Missing required parameters for token exchange');
            }

            const response = await fetch(tokenUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    authorization_code: authorizationCode,
                    code_verifier: codeVerifier
                })
            });

            console.log('Token response status:', response.status);

            if (!response.ok) {
                const errorText = await response.text();
                console.error('Token exchange error response:', errorText);
                throw new Error('Token exchange failed: ' + errorText);
            }

            const data = await response.json();
            console.log('Token exchange response:', data);

            if (data.success) {
                console.log('Authentication successful, redirecting to:', data.redirect_url);
                window.location.href = data.redirect_url;
            } else {
                throw new Error('Authentication failed - success flag is false');
            }

        } catch (error) {
            console.error('Token exchange error:', error);

            // Show error message
            const errorElement = document.getElementById('errorMessage');
            if (errorElement) {
                errorElement.textContent = 'Login failed: ' + error.message;
                errorElement.style.display = 'block';
            }

            // Hide spinner
            const spinner = document.querySelector('.spinner-border');
            if (spinner) {
                spinner.style.display = 'none';
            }

            // Hide progress bar
            const progress = document.querySelector('.progress');
            if (progress) {
                progress.style.display = 'none';
            }

            // Redirect back to login after 3 seconds
            setTimeout(() => {
                console.log('Redirecting back to login...');
                window.location.href = '/login';
            }, 3000);
        }
    }

    // Start token exchange after short delay
    console.log('Starting token exchange in 500ms...');
    setTimeout(completeTokenExchange, 500);
});
