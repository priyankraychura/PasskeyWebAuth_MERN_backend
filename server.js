// server.js
const express = require('express');
const cors = require('cors');
const crypto = require('crypto');

const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());
app.use(cors());

// In-memory storage
const users = new Map(); // username -> user object
const authenticators = new Map(); // userId -> array of authenticators
const challenges = new Map(); // username -> challenge (for registration)
let loginChallenge = null; // For login challenges

// Configuration
const RP_NAME = 'Passkey Auth Demo';
const RP_ID = 'passkey-web-auth-mern.vercel.app';
const ORIGIN = 'https://passkey-web-auth-mern.vercel.app/';

// Utility to convert base64url to buffer
function base64urlToBuffer(base64url) {
    const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
    const padding = '='.repeat((4 - base64.length % 4) % 4);
    return Buffer.from(base64 + padding, 'base64');
}

// Utility to convert buffer to base64url
function bufferToBase64url(buffer) {
    return Buffer.from(buffer)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

/**
 * REGISTRATION - Step 1: Generate Options
 */
app.post('/api/register/options', async (req, res) => {
    try {
        const { username } = req.body;

        if (!username || username.trim() === '') {
            return res.status(400).json({ error: 'Username is required' });
        }

        if (users.has(username)) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Create user
        const userId = crypto.randomBytes(32);
        const user = {
            id: userId,
            username: username,
            createdAt: new Date()
        };

        users.set(username, user);
        authenticators.set(bufferToBase64url(userId), []);

        // Generate registration options
        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID: RP_ID,
            userID: userId,
            userName: username,
            attestationType: 'none',
            authenticatorSelection: {
                residentKey: 'required',
                userVerification: 'preferred',
                authenticatorAttachment: 'platform',
            },
        });

        // Store challenge
        challenges.set(username, options.challenge);

        console.log(`[REGISTRATION] Generated options for user: ${username}`);
        res.json(options);
    } catch (error) {
        console.error('[REGISTRATION] Error generating options:', error);
        res.status(500).json({ error: 'Failed to generate registration options' });
    }
});

/**
 * REGISTRATION - Step 2: Verify Response
 */
app.post('/api/register/verify', async (req, res) => {
    try {
        const { username, credential } = req.body;

        if (!username || !users.has(username)) {
            return res.status(400).json({ error: 'User not found' });
        }

        const user = users.get(username);
        const expectedChallenge = challenges.get(username);

        if (!expectedChallenge) {
            return res.status(400).json({ error: 'No challenge found' });
        }

        // Verify the credential
        const verification = await verifyRegistrationResponse({
            response: credential,
            expectedChallenge: expectedChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
        });

        const { verified, registrationInfo } = verification;

        if (!verified || !registrationInfo) {
            return res.status(400).json({ error: 'Registration verification failed' });
        }

        const userIdBase64url = bufferToBase64url(user.id);
        
        // Extract credential data for storage
        const credentialID = registrationInfo.credential.id; // base64url string
        const rawPublicKey = registrationInfo.credential.publicKey; // Uint8Array
        const counter = registrationInfo.credential.counter ?? 0;
        const transports = registrationInfo.credential.transports || [];

        // Convert to Buffer for storage
        const credPubKeyBuffer = Buffer.from(rawPublicKey);

        const userAuthenticators = authenticators.get(userIdBase64url) || [];
        
        // Store in format for verifyAuthenticationResponse (v11+ expects 'credential' with id as string, publicKey as Uint8Array/Buffer)
        const newAuthenticator = {
            id: credentialID, // base64url string
            publicKey: credPubKeyBuffer, // Buffer (raw public key bytes)
            counter: counter, // Number
            transports: transports,
            addedAt: new Date()
        };

        userAuthenticators.push(newAuthenticator);
        authenticators.set(userIdBase64url, userAuthenticators);

        console.log('[REGISTRATION] Successfully stored authenticator');
        console.log('[REGISTRATION] Credential ID:', credentialID);
        console.log('[REGISTRATION] Public key length:', credPubKeyBuffer.length);

        challenges.delete(username);

        res.json({ 
            verified: true,
            message: 'Registration successful! You can now login.'
        });
    } catch (error) {
        console.error('[REGISTRATION] Verification error:', error);
        res.status(500).json({ 
            error: 'Registration verification failed',
            details: error.message 
        });
    }
});

/**
 * LOGIN - Step 1: Generate Options
 */
app.post('/api/login/options', async (req, res) => {
    try {
        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            userVerification: 'preferred',
        });

        loginChallenge = options.challenge;

        console.log('[LOGIN] Generated authentication options');
        res.json(options);
    } catch (error) {
        console.error('[LOGIN] Error generating options:', error);
        res.status(500).json({ error: 'Failed to generate login options' });
    }
});

/**
 * LOGIN - Step 2: Verify Response
 */
app.post('/api/login/verify', async (req, res) => {
    try {
        const { credential } = req.body;

        if (!loginChallenge) {
            return res.status(400).json({ error: 'No login challenge found' });
        }

        if (!credential || !credential.response || !credential.response.userHandle) {
            return res.status(400).json({ error: 'Invalid credential response' });
        }

        const userHandle = credential.response.userHandle;
        console.log('[LOGIN] Received userHandle:', userHandle);

        // Find user by userHandle
        let user = null;
        let foundUsername = null;
        for (const [username, userData] of users.entries()) {
            const userIdBase64url = bufferToBase64url(userData.id);
            if (userIdBase64url === userHandle) {
                user = userData;
                foundUsername = username;
                console.log(`[LOGIN] Found user: ${username}`);
                break;
            }
        }

        if (!user) {
            loginChallenge = null;
            return res.status(404).json({ error: 'User not found' });
        }

        const userIdBase64url = bufferToBase64url(user.id);
        const userAuthenticators = authenticators.get(userIdBase64url);

        if (!userAuthenticators || userAuthenticators.length === 0) {
            loginChallenge = null;
            return res.status(400).json({ error: 'No authenticators found for user' });
        }

        // Find matching authenticator by comparing base64url id strings
        console.log('[LOGIN] Looking for credential ID:', credential.id);

        const authenticator = userAuthenticators.find(auth => 
            auth.id === credential.id
        );

        if (!authenticator) {
            loginChallenge = null;
            console.log('[LOGIN] Available authenticators:', 
                userAuthenticators.map(a => a.id)
            );
            return res.status(400).json({ error: 'Authenticator not recognized' });
        }

        console.log('[LOGIN] Found matching authenticator');
        console.log('[LOGIN] Authenticator data:', {
            id: authenticator.id,
            publicKey_length: authenticator.publicKey.length,
            publicKey_isBuffer: Buffer.isBuffer(authenticator.publicKey),
            counter: authenticator.counter
        });

        // Create credential object for v11+ verifyAuthenticationResponse
        const credentialForVerification = {
            id: authenticator.id, // base64url string
            publicKey: authenticator.publicKey, // Buffer (raw public key bytes)
            counter: authenticator.counter, // Number
            transports: authenticator.transports // Array or undefined
        };

        console.log('[LOGIN] Verification attempt with:', {
            hasId: !!credentialForVerification.id,
            idType: typeof credentialForVerification.id,
            hasPublicKey: !!credentialForVerification.publicKey,
            publicKeyType: typeof credentialForVerification.publicKey,
            counterType: typeof credentialForVerification.counter,
            counterValue: credentialForVerification.counter
        });

        // Verify authentication using 'credential' parameter (v11+)
        const verification = await verifyAuthenticationResponse({
            response: credential,
            expectedChallenge: loginChallenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            credential: credentialForVerification // Changed from 'authenticator' to 'credential'
        });

        const { verified, authenticationInfo } = verification;

        if (!verified) {
            loginChallenge = null;
            console.error('[LOGIN] Verification failed:', verification);
            return res.status(400).json({ error: 'Authentication verification failed', details: verification });
        }

        // Update counter
        authenticator.counter = authenticationInfo.newCounter;
        loginChallenge = null;

        console.log(`[LOGIN] Successfully authenticated user: ${foundUsername}`);
        console.log(`[LOGIN] New counter: ${authenticator.counter}`);
        
        res.json({ 
            verified: true,
            username: foundUsername,
            message: `Welcome back, ${foundUsername}!`
        });
    } catch (error) {
        loginChallenge = null;
        console.error('[LOGIN] Verification error:', error);
        console.error('[LOGIN] Error details:', {
            message: error.message,
            stack: error.stack
        });
        res.status(500).json({ 
            error: 'Authentication verification failed',
            details: error.message 
        });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    const stats = {
        status: 'ok',
        users: users.size,
        authenticators: Array.from(authenticators.values()).reduce((sum, auths) => sum + auths.length, 0),
        timestamp: new Date().toISOString()
    };
    res.json(stats);
});

// Debug endpoint to inspect stored authenticators
app.get('/api/debug/:username', (req, res) => {
    const { username } = req.params;
    const user = users.get(username);
    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }
    
    const userIdBase64url = bufferToBase64url(user.id);
    const userAuthenticators = authenticators.get(userIdBase64url) || [];
    
    res.json({
        user: { username, userId: userIdBase64url },
        authenticators: userAuthenticators.map(auth => ({
            id: auth.id,
            id_length: auth.id.length,
            publicKey_length: auth.publicKey.length,
            publicKey_isBuffer: Buffer.isBuffer(auth.publicKey),
            counter: auth.counter,
            transports: auth.transports
        }))
    });
});

const PORT = 4000;
app.listen(PORT, () => {
    console.log(`✅ Server running on http://localhost:${PORT}`);
    console.log(`📝 RP ID: ${RP_ID}`);
    console.log(`🌐 Origin: ${ORIGIN}`);
    console.log(`🔍 Debug: GET /api/debug/{username}`);
});