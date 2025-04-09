// Google OAuth2 Plug-and-Play Authentication for Replit
//
// This Express server implements Google OAuth 2.0 login, issuing a JWT in an HTTP-only cookie.
// Configure the environment variables in Replit (or a .env file) before running.
//
// Required ENV variables:
// - GOOGLE_CLIENT_ID: OAuth Client ID from Google Cloud Console.
// - GOOGLE_CLIENT_SECRET: OAuth Client Secret from Google Cloud Console.
// - GOOGLE_REDIRECT_URI: OAuth redirect URI (must match one set in Google console).
// - JWT_SECRET: Secret key for signing JWTs (use a strong, random string).
// - FRONTEND_URL: (optional) Base URL of frontend to redirect to after login/logout (e.g., "https://myapp.com" or ""); defaults to "/" if not provided.
// - PORT: Port for the server to listen on (defaults to 3000 if not provided).
//
// After configuring, start the server and visit /auth/google to begin OAuth login.
require('dotenv').config();

const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { google } = require('googleapis');
const crypto = require('crypto');

const app = express();
app.use(cookieParser());  // Parse cookies for reading JWT

// Load configuration from environment
const {
    GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET,
    GOOGLE_REDIRECT_URI,
    JWT_SECRET,
    FRONTEND_URL
} = process.env;
const port = process.env.PORT || 5006;

// In-memory storage for OAuth state to protect against CSRF and to store redirect URLs temporarily
const pendingStates = new Map();

// Middleware to protect routes by verifying the JWT in cookie
function authenticateJWT(req, res, next)
{
    const token = req.cookies.jwt;
    if (!token)
    {
        return res.status(401).json({ error: "Unauthorized" });
    }
    try
    {
        // Verify the token using the secret. If invalid or expired, an error will be thrown.
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;  // attach decoded user info to request
        return next();
    } catch (err)
    {
        return res.status(401).json({ error: "Unauthorized" });
    }
}

// Route 1: Start Google OAuth login
app.get('/auth/google', (req, res) =>
{
    // Determine where to redirect the user after a successful login
    let redirectAfterLogin = '/';              // default to root if FRONTEND_URL not set
    if (FRONTEND_URL) redirectAfterLogin = FRONTEND_URL;
    if (req.query.redirect)
    {
        // If a specific redirect path or URL is provided as a query param, validate it
        const requested = req.query.redirect;
        if (requested.startsWith('/'))
        {
            // Relative path (e.g. "/dashboard") – combine with FRONTEND_URL if available
            redirectAfterLogin = FRONTEND_URL
                ? FRONTEND_URL.replace(/\/$/, '') + requested  // ensure no double slash
                : requested;
        } else if (requested.match(/^https?:\/\//))
        {
            // Full URL – allow only if it starts with the FRONTEND_URL (to prevent open redirect attacks)
            if (FRONTEND_URL && requested.startsWith(FRONTEND_URL))
            {
                redirectAfterLogin = requested;
            } else
            {
                console.warn("Blocked an unauthorized redirect URL: " + requested);
                // (Falls back to default FRONTEND_URL if the requested URL is not allowed)
            }
        }
    }

    // Generate a random state string for CSRF protection and store the desired redirect URL
    const state = crypto.randomBytes(16).toString('hex');  // 32-char hex string
    pendingStates.set(state, redirectAfterLogin);

    // Create an OAuth2 client and generate the Google authorization URL
    const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
    const authUrl = oauth2Client.generateAuthUrl({
        // Request access to user's profile and email (OAuth scopes)
        scope: [ 'openid', 'profile', 'email' ],
        state: state,
        // You can add `access_type: 'offline'` to get a refresh token if needed
    });
    // Redirect the user to Google's OAuth 2.0 consent page
    res.redirect(authUrl);
});

// Route 2: OAuth callback - Google will redirect to this route with a code
app.get('/auth/google/callback', async (req, res) =>
{
    const code = req.query.code;
    const state = req.query.state;
    if (!code)
    {
        return res.status(400).send("Missing authorization code");
    }

    // Verify state to protect against CSRF and retrieve the original redirect URL
    let redirectAfterLogin = FRONTEND_URL || '/';
    if (state)
    {
        if (pendingStates.has(state))
        {
            redirectAfterLogin = pendingStates.get(state);
            pendingStates.delete(state);  // clear it to prevent reuse
        } else
        {
            console.warn("State mismatch or expired state (possible CSRF attack)");
            // We can choose to abort here for security. For this plugin, we'll proceed with default redirect.
        }
    }

    try
    {
        // Exchange the authorization code for access tokens
        const oauth2Client = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REDIRECT_URI);
        const tokenResponse = await oauth2Client.getToken(code);
        const tokens = tokenResponse.tokens;  // { access_token, id_token, refresh_token, ... }
        // Set credentials for further API calls (not strictly necessary for getting basic profile)
        oauth2Client.setCredentials(tokens);

        // Retrieve the user's profile information using Google's OAuth2 API
        const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
        const { data: profile } = await oauth2.userinfo.get();  // get user info (email, name, picture, etc.)
        // Prepare JWT payload with user info
        const payload = {
            id: profile.id,             // Google user ID (sub)
            email: profile.email,
            name: profile.name,
            avatar: profile.picture     // URL of the user's avatar image
        };

        // Sign a JWT with the user info. The token will expire (e.g., in 1 day).
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1d' });

        // Set the JWT as an HTTP-only cookie so it's not accessible via JS (helps mitigate XSS)
        res.cookie('jwt', token, {
            httpOnly: true,       // prevent JavaScript access to the cookie
            secure: true,         // cookie sent only over HTTPS (set false if testing on localhost over http)
            sameSite: 'Lax'       // Lax is default: cookie not sent on cross-site subrequests (CSRF mitigation)
        });

        // Redirect the user to the intended front-end page after login, with the session cookie now set
        return res.redirect(redirectAfterLogin);
    } catch (err)
    {
        console.error("Error during OAuth callback processing:", err);
        return res.status(500).send("Authentication failed. Please try again.");
    }
});

// Route 3: Protected endpoint to get current user info (if authenticated)
app.get('/me', authenticateJWT, (req, res) =>
{
    const userData = {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        avatar: req.user.avatar
    };
    res.json(userData);
});

// Route 4: Logout - clear the authentication cookie
app.get('/logout', (req, res) =>
{
    res.clearCookie('jwt', {
        httpOnly: true,
        secure: true,
        sameSite: 'Lax'
    });
    if (req.query.redirect)
    {
        return res.redirect(req.query.redirect);
    }
    if (FRONTEND_URL)
    {
        return res.redirect(FRONTEND_URL);
    }
    res.send("Logged out");
});

// Start the Express server with error handling for port conflicts
const server = app.listen(port, () =>
{
    console.log(`✅ OAuth server is running on port ${port}. OAuth redirect URI: ${GOOGLE_REDIRECT_URI}`);
});

server.on('error', (err) =>
{
    if (err.code === 'EADDRINUSE')
    {
        console.error(`Error: Port ${port} is already in use. Please free the port or set the PORT environment variable to a different value.`);
        process.exit(1);
    } else
    {
        console.error("Server error:", err);
        process.exit(1);
    }
});
