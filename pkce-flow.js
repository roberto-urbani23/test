// PKCE Flow JavaScript
document.addEventListener('DOMContentLoaded', function() {
    let debugLog = [];

    function log(message) {
        console.log(message);
        debugLog.push(new Date().toLocaleTimeString() + ': ' + message);
        const debugElement = document.getElementById('debugLog');
        if (debugElement) {
            debugElement.textContent = debugLog.join('\n');
        }
    }

    window.toggleDebug = function() {
        const debugInfo = document.getElementById('debugInfo');
        if (debugInfo) {
            debugInfo.style.display = debugInfo.style.display === 'none' ? 'block' : 'none';
        }
    }

    // PKCE utility functions
    function generateCodeVerifier() {
        const array = new Uint8Array(32);
        window.crypto.getRandomValues(array);
        return base64URLEncode(array);
    }

    function generateCodeChallenge(codeVerifier) {
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hash = sha256.arrayBuffer(data);
        return base64URLEncode(new Uint8Array(hash));
    }

    function base64URLEncode(array) {
        return btoa(String.fromCharCode.apply(null, array))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    function updateProgress(step, percentage) {
        const progressBar = document.getElementById('progressBar');
        if (progressBar) {
            progressBar.style.width = percentage + '%';
        }

        // Update step indicators
        for (let i = 1; i <= 3; i++) {
            const stepElement = document.getElementById('step' + i);
            if (stepElement) {
                if (i < step) {
                    stepElement.className = 'step complete';
                } else if (i === step) {
                    stepElement.className = 'step active';
                } else {
                    stepElement.className = 'step';
                }
            }
        }
    }

    function showError(message) {
        const errorElement = document.getElementById('errorMessage');
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }

        const spinner = document.querySelector('.spinner-border');
        if (spinner) spinner.style.display = 'none';

        const progress = document.querySelector('.progress');
        if (progress) progress.style.display = 'none';
    }

    // Start PKCE flow
    async function startPKCEFlow() {
        try {
            log('Starting PKCE flow...');

            // Get authorize URL from data attribute
            const authorizeUrl = document.body.getAttribute('data-authorize-url');
            if (!authorizeUrl) {
                throw new Error('Authorize URL not found');
            }

            // Step 1: Generate PKCE parameters
            updateProgress(1, 33);
            log('Step 1: Generating PKCE parameters...');
            await new Promise(resolve => setTimeout(resolve, 1000));

            const codeVerifier = generateCodeVerifier();
            const codeChallenge = generateCodeChallenge(codeVerifier);
            log('Generated code_verifier length: ' + codeVerifier.length);
            log('Generated code_challenge: ' + codeChallenge.substring(0, 20) + '...');

            // Step 2: Get authorization code
            updateProgress(2, 66);
            log('Step 2: Getting authorization code...');
            log('Calling authorize URL: ' + authorizeUrl);

            const authorizeResponse = await fetch(authorizeUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    code_challenge: codeChallenge,
                    code_challenge_method: 'S256'
                })
            });

            log('Authorize response status: ' + authorizeResponse.status);

            if (!authorizeResponse.ok) {
                const errorText = await authorizeResponse.text();
                log('Authorize error response: ' + errorText);
                try {
                    const errorData = JSON.parse(errorText);
                    throw new Error(errorData.error || 'Authorization failed');
                } catch (parseError) {
                    throw new Error('Authorization failed: ' + errorText);
                }
            }

            const authorizeData = await authorizeResponse.json();
            log('Authorization code received: ' + authorizeData.authorization_code.substring(0, 10) + '...');
            log('Token URL: ' + authorizeData.token_url);

            // Step 3: Exchange for token
            updateProgress(3, 100);
            log('Step 3: Exchanging for token...');
            await new Promise(resolve => setTimeout(resolve, 500));

            const tokenResponse = await fetch(authorizeData.token_url, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    authorization_code: authorizeData.authorization_code,
                    code_verifier: codeVerifier
                })
            });

            log('Token response status: ' + tokenResponse.status);

            if (!tokenResponse.ok) {
                const errorText = await tokenResponse.text();
                log('Token error response: ' + errorText);
                try {
                    const errorData = JSON.parse(errorText);
                    throw new Error(errorData.error || 'Token exchange failed');
                } catch (parseError) {
                    throw new Error('Token exchange failed: ' + errorText);
                }
            }

            const tokenData = await tokenResponse.json();
            log('Token response: ' + JSON.stringify(tokenData));

            if (tokenData.success) {
                log('Success! Redirecting to: ' + tokenData.redirect_url);
                window.location.href = tokenData.redirect_url;
            } else {
                throw new Error('Authentication failed - success flag is false');
            }

        } catch (error) {
            log('ERROR: ' + error.message);
            console.error('PKCE flow error:', error);
            showError('Login failed: ' + error.message + '. Please try again.');

            // Show debug info automatically on error
            const debugInfo = document.getElementById('debugInfo');
            if (debugInfo) {
                debugInfo.style.display = 'block';
            }

            // Redirect back to login after 5 seconds
            setTimeout(() => {
                window.location.href = '/login';
            }, 5000);
        }
    }

    // Check if browser supports required APIs
    if (!window.crypto || !window.crypto.getRandomValues) {
        log('Browser does not support crypto APIs');
        showError('Your browser does not support secure random number generation. Please update your browser.');
    } else if (typeof sha256 === 'undefined') {
        log('SHA256 library not loaded');
        showError('Required cryptographic libraries failed to load. Please refresh the page.');
    } else {
        log('Browser check passed, starting flow...');
        // Show debug info immediately
        const debugInfo = document.getElementById('debugInfo');
        if (debugInfo) {
            debugInfo.style.display = 'block';
        }
        // Start the flow after a brief delay
        setTimeout(startPKCEFlow, 500);
    }
});
