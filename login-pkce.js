// Login PKCE JavaScript
console.log('Login PKCE script loaded');

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

function initializeLoginPKCE() {
    console.log('Initializing Login PKCE...');

    const form = document.getElementById('loginForm');

    if (!form) {
        console.error('Login form not found');
        return;
    }

    // Verify browser support
    if (!window.crypto || !window.crypto.getRandomValues) {
        console.error('Browser does not support crypto APIs');
        alert('Your browser does not support the required security features. Please update your browser.');
        return;
    }

    if (typeof sha256 === 'undefined') {
        console.error('SHA256 library not loaded');
        alert('Required cryptographic libraries failed to load. Please refresh the page.');
        return;
    }

    // Generate PKCE parameters
    try {
        console.log('Generating PKCE parameters...');
        const codeVerifier = generateCodeVerifier();
        const codeChallenge = generateCodeChallenge(codeVerifier);

        // Store parameters for form submission
        form.dataset.codeChallenge = codeChallenge;
        form.dataset.codeVerifier = codeVerifier;

        console.log('✅ PKCE parameters generated successfully');
        console.log('Code verifier length:', codeVerifier.length);
        console.log('Code challenge preview:', codeChallenge.substring(0, 20) + '...');

        return true;
    } catch (error) {
        console.error('Error generating PKCE parameters:', error);
        alert('Error generating security parameters: ' + error.message);
        return false;
    }
}

function appendPKCEToFormAction(form) {
    const codeChallenge = form.dataset.codeChallenge;
    const codeVerifier = form.dataset.codeVerifier;

    if (!codeChallenge || !codeVerifier) {
        console.error('PKCE parameters not found');
        return false;
    }

    const currentAction = form.action;
    const url = new URL(currentAction, window.location.origin);

    url.searchParams.set('code_challenge', codeChallenge);
    url.searchParams.set('code_verifier', codeVerifier);

    form.action = url.toString();

    console.log('✅ PKCE parameters added to form action URL');
    return true;
}

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing PKCE...');

    // Wait a bit for SHA256 library to load
    setTimeout(function() {
        const pkceGenerated = initializeLoginPKCE();

        // Setup form validation
        const form = document.getElementById('loginForm');
        if (form && pkceGenerated) {
            form.addEventListener('submit', function(e) {
                console.log('Form submission intercepted');

                if (!appendPKCEToFormAction(form)) {
                    e.preventDefault();
                    alert('Security parameters missing. Please refresh the page.');
                    return false;
                }

                console.log('✅ Form validation passed');
                console.log('Submitting with PKCE parameters in URL...');
                return true;
            });
        }
    }, 200);
});
