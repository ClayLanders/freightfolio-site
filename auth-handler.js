// Configuration
const config = {
    region: 'us-east-2',
    userPoolId: 'us-east-2_H5gKrDTsk',
    clientId: '55j4b92u9kgu0ufbuv31875guu',
    redirectUri: 'http://localhost:5137/auth-callback.html'
};

// Function to handle the authentication callback
async function handleAuthCallback() {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');

    if (code) {
        try {
            // Exchange the authorization code for tokens
            const tokenEndpoint = `https://cognito-idp.${config.region}.amazonaws.com/${config.userPoolId}/oauth2/token`;
            const tokenResponse = await fetch(tokenEndpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: new URLSearchParams({
                    grant_type: 'authorization_code',
                    client_id: config.clientId,
                    code: code,
                    redirect_uri: config.redirectUri
                })
            });

            const tokens = await tokenResponse.json();

            // Store tokens securely
            localStorage.setItem('id_token', tokens.id_token);
            localStorage.setItem('access_token', tokens.access_token);
            localStorage.setItem('refresh_token', tokens.refresh_token);

            // Redirect to home page
            window.location.href = 'http://localhost:5137';
        } catch (error) {
            console.error('Error exchanging code for tokens:', error);
            // Handle error appropriately
        }
    }
}

// Check if we're on the callback page
if (window.location.pathname === '/auth-callback.html') {
    handleAuthCallback();
}

// Function to check if user is authenticated
function isAuthenticated() {
    return !!localStorage.getItem('id_token');
}

// Function to get the current user's info from the ID token
function getCurrentUser() {
    const idToken = localStorage.getItem('id_token');
    if (idToken) {
        const payload = JSON.parse(atob(idToken.split('.')[1]));
        return {
            email: payload.email,
            sub: payload.sub,
            // Add other claims you need
        };
    }
    return null;
}

// Function to handle logout
function logout() {
    localStorage.removeItem('id_token');
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = 'http://localhost:5137';
} 