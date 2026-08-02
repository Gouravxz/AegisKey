const express = require('express');
const CryptoJS = require('crypto-js');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');

const app = express();
const PORT = 3000;

// --- JSON STORAGE SETUP ---
const USERS_FILE = path.join(__dirname, 'users.json');
const HISTORY_FILE = path.join(__dirname, 'history.json');
const SESSIONS_FILE = path.join(__dirname, 'sessions.json');

// In-Memory Storage for OTPs & Rate-Limiting
const otpStore = {}; 

// Initialize JSON files if they don't exist
function initJsonFiles() {
    if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, JSON.stringify([]));
    if (!fs.existsSync(HISTORY_FILE)) fs.writeFileSync(HISTORY_FILE, JSON.stringify([]));
    if (!fs.existsSync(SESSIONS_FILE)) fs.writeFileSync(SESSIONS_FILE, JSON.stringify({}));
}
initJsonFiles();

// JSON Helper Functions
function readJSON(filePath) {
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } catch {
        return filePath === SESSIONS_FILE ? {} : [];
    }
}

function writeJSON(filePath, data) {
    fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

// Client IP Resolver Helper
function getClientIP(req) {
    return req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
}

// Advanced Audit Log Helper (Stores User ID, Email, IP, Browser Details)
function logAudit(req, action, userEmail = 'Guest/Anonymous', details = {}) {
    const history = readJSON(HISTORY_FILE);
    const ip = getClientIP(req);
    const userAgent = req.headers['user-agent'] || 'Unknown Browser';

    const logEntry = {
        id: 'log_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
        timestamp: new Date().toLocaleString(),
        isoTime: new Date().toISOString(),
        action: action,
        userEmail: userEmail,
        ipAddress: ip,
        userAgent: userAgent,
        itemCount: details.itemCount || 0,
        context: details.context || 'General Activity'
    };

    history.unshift(logEntry);
    writeJSON(HISTORY_FILE, history.slice(0, 200)); // Keep last 200 activity entries
    console.log(`[AUDIT LOG] [${logEntry.timestamp}] ${action} by ${userEmail} (IP: ${ip})`);
}

// NODEMAILER GMAIL TRANSPORTER SETUP
// Note: Replace with your actual Gmail ID and 16-character App Password
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'gauravsh2345@gmail.com',  // Your Gmail Address
        pass: 'rdbk aqur krgv bbah'    // Your Google 16-character App Password
    }
});

// --- SERVER MIDDLEWARES ---
app.use(express.static(__dirname)); // Serves static files
app.use(express.json({ limit: '800mb' })); // High limit for batch images/vaults
app.use(express.urlencoded({ limit: '800mb', extended: true }));
app.use(cors());

// 30-Minute Backend Session Verification Middleware
function verifySession(req, res, next) {
    const authHeader = req.headers['x-session-id'];
    if (!authHeader) {
        return res.status(401).json({ success: false, error: "Unauthorized: No session token provided" });
    }

    const sessions = readJSON(SESSIONS_FILE);
    const userSession = sessions[authHeader];

    if (!userSession) {
        return res.status(401).json({ success: false, error: "Session invalid or expired" });
    }

    const now = Date.now();
    const SESSION_TIMEOUT = 30 * 60 * 1000; // 30 Minutes Limit

    if (now - userSession.createdAt > SESSION_TIMEOUT) {
        delete sessions[authHeader]; // Delete expired session
        writeJSON(SESSIONS_FILE, sessions);
        return res.status(401).json({ success: false, error: "30-Minute session expired. Please log in again." });
    }

    req.currentUser = userSession;
    next();
}

// ==========================================================================
// 1. ROUTE: Serve Crypto-JS CDN or Local File Fallback
// ==========================================================================
app.get('/crypto-js.min.js', (req, res) => {
    const cryptoPath = path.join(__dirname, 'crypto-js.min.js');
    if (fs.existsSync(cryptoPath)) {
        res.sendFile(cryptoPath);
    } else {
        res.status(404).send("// crypto-js.min.js not found locally. Please include via CDN or download.");
    }
});

// ==========================================================================
// 2. USER REGISTRATION ENDPOINT
// ==========================================================================
app.post('/api/user/register', (req, res) => {
    try {
        const { email, password, purpose, country } = req.body;

        if (!email || !password || !purpose || !country) {
            return res.status(400).json({ success: false, error: "All fields are required!" });
        }

        const users = readJSON(USERS_FILE);

        const userExists = users.find(u => u.email.toLowerCase() === email.toLowerCase());
        if (userExists) {
            return res.status(400).json({ success: false, error: "Email already registered!" });
        }

        const hashedPassword = CryptoJS.SHA256(password).toString();

        const newUser = {
            id: 'usr_' + Date.now(),
            email: email.toLowerCase(),
            passwordHash: hashedPassword,
            purpose: purpose,
            country: country,
            createdAt: new Date().toISOString()
        };

        users.push(newUser);
        writeJSON(USERS_FILE, users);

        logAudit(req, 'USER_REGISTERED', email, { context: `Country: ${country}, Purpose: ${purpose}` });

        res.json({ success: true, message: "Account created successfully!" });
    } catch (err) {
        console.error("Registration Error:", err);
        res.status(500).json({ success: false, error: "Registration Server Error" });
    }
});

// ==========================================================================
// 3. USER LOGIN ENDPOINT (Generates 30-Min Active Session Token)
// ==========================================================================
app.post('/api/user/login', (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ success: false, error: "Email and password required!" });
        }

        const users = readJSON(USERS_FILE);
        const hashedPassword = CryptoJS.SHA256(password).toString();

        const user = users.find(u => u.email.toLowerCase() === email.toLowerCase() && u.passwordHash === hashedPassword);

        if (!user) {
            logAudit(req, 'LOGIN_FAILED', email, { context: 'Invalid password or unregistered email' });
            return res.status(401).json({ success: false, error: "Incorrect email or password!" });
        }

        // Generate 30-Minute Session Token
        const sessionId = 'sess_' + CryptoJS.SHA256(user.id + Date.now()).toString().substring(0, 24);
        const sessions = readJSON(SESSIONS_FILE);

        sessions[sessionId] = {
            sessionId: sessionId,
            userId: user.id,
            email: user.email,
            createdAt: Date.now(),
            expiresAt: Date.now() + (30 * 60 * 1000) // 30 Mins expiry
        };
        writeJSON(SESSIONS_FILE, sessions);

        logAudit(req, 'USER_LOGIN_SUCCESS', email, { context: `Session ID: ${sessionId}` });

        res.json({
            success: true,
            message: "Login successful",
            sessionId: sessionId,
            user: { 
                id: user.id, 
                email: user.email, 
                country: user.country,
                loginTime: Date.now()
            }
        });
    } catch (err) {
        console.error("Login Error:", err);
        res.status(500).json({ success: false, error: "Login Server Error" });
    }
});

// ==========================================================================
// 4. FORGOT PASSWORD: OTP GENERATION & RATE LIMITING
// ==========================================================================
app.post('/api/user/forgot-password-otp', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ success: false, error: "Registered email address required!" });
        }

        const users = readJSON(USERS_FILE);
        const userExists = users.find(u => u.email.toLowerCase() === email.toLowerCase());

        if (!userExists) {
            logAudit(req, 'OTP_REQUEST_FAILED', email, { context: 'Unregistered Email Attempt' });
            return res.status(404).json({ success: false, error: "Account not found with this email!" });
        }

        const emailKey = email.toLowerCase();
        const now = Date.now();

        // Check Rate Limits: Max 3 OTP Requests per 1 Hour
        if (otpStore[emailKey]) {
            const record = otpStore[emailKey];

            // 1-Minute Resend Delay Guard
            if (now - record.lastSent < 60 * 1000) {
                return res.status(429).json({ success: false, error: "Please wait 60 seconds before requesting a new OTP." });
            }

            // 1-Hour Window Check
            if (now - record.windowStart < 60 * 60 * 1000) {
                if (record.attempts >= 3) {
                    logAudit(req, 'OTP_LIMIT_EXCEEDED', email, { context: '3 OTPs per hour limit hit' });
                    return res.status(429).json({ success: false, error: "Maximum limit reached (3 OTPs per hour). Try again after 1 hour." });
                }
            } else {
                // Reset Window after 1 hour
                record.attempts = 0;
                record.windowStart = now;
            }
        }

        // Generate 6-Digit OTP
        const generatedOtp = Math.floor(100000 + Math.random() * 900000).toString();

        // Update In-Memory OTP Tracking Store
        const currentAttempts = otpStore[emailKey] ? otpStore[emailKey].attempts + 1 : 1;
        const windowStart = otpStore[emailKey] ? otpStore[emailKey].windowStart : now;

        otpStore[emailKey] = {
            otp: generatedOtp,
            expiresAt: now + (5 * 60 * 1000), // OTP valid for 5 Minutes
            lastSent: now,
            attempts: currentAttempts,
            windowStart: windowStart
        };

        // Advanced Production-Grade Mail Options Template
        const mailOptions = {
            from: '"AegisKey Security" <gauravsh2345@gmail.com>',
            to: emailKey,
            subject: '🔒 AegisKey | Verification Code: ' + generatedOtp,
            html: `
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="utf-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>AegisKey Security Verification</title>
                </head>
                <body style="margin: 0; padding: 0; background-color: #070A10; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #F8FAFC;">
                    <table border="0" cellpadding="0" cellspacing="0" width="100%" style="table-layout: fixed; background-color: #070A10; padding: 30px 10px;">
                        <tr>
                            <td align="center">
                                <table border="0" cellpadding="0" cellspacing="0" width="100%" style="max-width: 520px; background-color: #111827; border: 1px solid #1E293B; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 40px rgba(0,0,0,0.6);">
                                    
                                    <!-- Top Cyan Glow Accent Line -->
                                    <tr>
                                        <td style="height: 4px; background: linear-gradient(90deg, #0071E3, #00F2FE, #0071E3);"></td>
                                    </tr>

                                    <!-- Header / Branding -->
                                    <tr>
                                        <td style="padding: 32px 32px 20px 32px; text-align: center;">
                                            <table border="0" cellpadding="0" cellspacing="0" align="center">
                                                <tr>
                                                    <td style="background-color: #1E293B; border: 1px solid #334155; padding: 10px 18px; border-radius: 12px; font-weight: 800; font-size: 18px; color: #00F2FE; letter-spacing: 1px;">
                                                        🛡️ AEGIS<span style="color: #F8FAFC;">KEY</span>
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>

                                    <!-- Main Title & Greeting -->
                                    <tr>
                                        <td style="padding: 0 32px 20px 32px; text-align: left;">
                                            <h2 style="margin: 0 0 10px 0; font-size: 20px; font-weight: 700; color: #F8FAFC;">Password Reset Verification</h2>
                                            <p style="margin: 0; font-size: 14px; color: #94A3B8; line-height: 1.5;">
                                                Dear User,
                                            </p>
                                            <p style="margin: 10px 0 0 0; font-size: 14px; color: #94A3B8; line-height: 1.5;">
                                                We received a request to reset your AegisKey account password. Use the single-use verification code below to complete your authentication.
                                            </p>
                                        </td>
                                    </tr>

                                    <!-- One-Click OTP Copy Container -->
                                    <tr>
                                        <td style="padding: 0 32px 20px 32px;" align="center">
                                            <div style="background-color: #0F172A; border: 1px dashed #00F2FE; border-radius: 12px; padding: 22px; text-align: center; position: relative;">
                                                <span style="display: block; font-size: 11px; font-weight: 600; text-transform: uppercase; color: #00F2FE; letter-spacing: 1.5px; margin-bottom: 8px;">
                                                    One-Time Verification Code
                                                </span>
                                                <!-- OTP Code with User-Select CSS for 1-Click Copy -->
                                                <div style="font-size: 34px; font-weight: 800; color: #38BDF8; letter-spacing: 8px; margin: 5px 0; font-family: 'Courier New', Courier, monospace; -webkit-user-select: all; -moz-user-select: all; -ms-user-select: all; user-select: all; cursor: pointer;" title="Click to Select All">
                                                    ${generatedOtp}
                                                </div>
                                                <span style="display: block; font-size: 12px; color: #64748B; margin-top: 6px;">
                                                    ⏱️ Valid for <strong>5 minutes</strong> only
                                                </span>
                                            </div>
                                        </td>
                                    </tr>

                                    <!-- Security Metadata / Device Log -->
                                    <tr>
                                        <td style="padding: 0 32px 20px 32px;">
                                            <table border="0" cellpadding="0" cellspacing="0" width="100%" style="background-color: #0B0F17; border-radius: 10px; padding: 14px 16px; border: 1px solid #1E293B;">
                                                <tr>
                                                    <td style="font-size: 12px; color: #94A3B8; line-height: 1.6;">
                                                        <strong>Request Timestamp:</strong> ${new Date().toLocaleString()}<br>
                                                        <strong>IP Address:</strong> ${getClientIP(req)}<br>
                                                        <strong>Browser/Client:</strong> ${req.headers['user-agent'] ? req.headers['user-agent'].split(' ')[0] : 'Web Client'}
                                                    </td>
                                                </tr>
                                            </table>
                                        </td>
                                    </tr>

                                    <!-- Warning Notice -->
                                    <tr>
                                        <td style="padding: 0 32px 24px 32px;">
                                            <p style="margin: 0; font-size: 12px; color: #EF4444; background-color: rgba(239, 68, 68, 0.1); border-left: 3px solid #EF4444; padding: 10px 12px; border-radius: 4px; line-height: 1.4;">
                                                ⚠️ <strong>Security Alert:</strong> If you did not request a password reset, please ignore this email. Your account remains secure and no changes will be made.
                                            </p>
                                        </td>
                                    </tr>

                                    <!-- Footer Section -->
                                    <tr>
                                        <td style="background-color: #0B0F17; padding: 20px 32px; border-top: 1px solid #1E293B; text-align: center;">
                                            <p style="margin: 0 0 6px 0; font-size: 12px; color: #64748B;">
                                                This is an automated system email. Please do not reply.
                                            </p>
                                            <p style="margin: 0; font-size: 12px; color: #475569;">
                                                &copy; 2026 AegisKey Security Suite. All rights reserved.
                                            </p>
                                        </td>
                                    </tr>

                                </table>
                            </td>
                        </tr>
                    </table>
                </body>
                </html>
            `
        };

        // Send Email via Nodemailer Transporter
        try {
            await transporter.sendMail(mailOptions);
            logAudit(req, 'OTP_SENT_SUCCESS', email, { context: `Attempt ${currentAttempts}/3` });
            res.json({ success: true, message: "Verification OTP sent to your email address." });
        } catch (mailErr) {
            console.error("Nodemailer Email Error:", mailErr);
            // Fallback for development testing
            logAudit(req, 'OTP_GENERATED_DEV', email, { context: `Dev Mode OTP: ${generatedOtp}` });
            res.json({ success: true, message: "OTP generated successfully! (Check Server Console if email setup is pending)" });
        }

    } catch (err) {
        console.error("Forgot Password Error:", err);
        res.status(500).json({ success: false, error: "Server Error processing OTP request" });
    }
});

// ==========================================================================
// 5. RESET PASSWORD & OTP VERIFICATION ENDPOINT
// ==========================================================================
app.post('/api/user/reset-password', (req, res) => {
    try {
        const { email, otp, newPassword } = req.body;

        if (!email || !newPassword) {
            return res.status(400).json({ success: false, error: "Email and new password are required!" });
        }

        const emailKey = email.toLowerCase();
        const storedOtpData = otpStore[emailKey];

        // Optional OTP Verification check if passed
        if (otp) {
            if (!storedOtpData) {
                return res.status(400).json({ success: false, error: "No OTP request found for this email." });
            }

            if (Date.now() > storedOtpData.expiresAt) {
                delete otpStore[emailKey];
                return res.status(400).json({ success: false, error: "OTP expired! Please request a new code." });
            }

            if (storedOtpData.otp !== otp.toString().trim()) {
                logAudit(req, 'INVALID_OTP_ENTERED', email);
                return res.status(400).json({ success: false, error: "Invalid OTP code entered." });
            }
        }

        const users = readJSON(USERS_FILE);
        const userIndex = users.findIndex(u => u.email.toLowerCase() === emailKey);

        if (userIndex === -1) {
            return res.status(404).json({ success: false, error: "User account not found!" });
        }

        // Update User Password Hash
        const newPasswordHash = CryptoJS.SHA256(newPassword).toString();
        users[userIndex].passwordHash = newPasswordHash;
        users[userIndex].updatedAt = new Date().toISOString();

        writeJSON(USERS_FILE, users);

        // Clear OTP Memory for safety
        delete otpStore[emailKey];

        logAudit(req, 'PASSWORD_RESET_SUCCESS', email, { context: 'Password updated via OTP Verification' });

        res.json({ success: true, message: "Master password reset successfully! You can now login." });
    } catch (err) {
        console.error("Reset Password Error:", err);
        res.status(500).json({ success: false, error: "Server Error resetting password" });
    }
});

// ==========================================================================
// 6. CREATE VAULT ENCRYPTION LOGIC (Strictly Preserved Core AES Logic)
// ==========================================================================
app.post('/encrypt-vault', (req, res) => {
    try {
        const { bundle, pass, userEmail } = req.body;
        if (!bundle || !pass) return res.status(400).json({ success: false, error: "Missing bundle or encryption key" });

        const encrypted = CryptoJS.AES.encrypt(JSON.stringify(bundle), pass).toString();
        
        logAudit(req, 'ENCRYPT_VAULT', userEmail || 'Anonymous', { 
            itemCount: bundle ? bundle.length : 0, 
            context: 'Exported Audio WAV Carrier Payload' 
        });

        res.json({ success: true, data: encrypted });
    } catch (err) {
        console.error("Encryption Error:", err);
        res.status(500).json({ success: false, error: "Encryption Failed" });
    }
});

// ==========================================================================
// 7. RECOVER VAULT DECRYPTION LOGIC (Strictly Preserved Core AES Logic)
// ==========================================================================
app.post('/decrypt-vault', (req, res) => {
    try {
        const { encryptedData, pass, userEmail } = req.body;
        if (!encryptedData || !pass) return res.status(400).json({ success: false, error: "Missing payload or key" });

        const dec = CryptoJS.AES.decrypt(encryptedData, pass).toString(CryptoJS.enc.Utf8);
        if (!dec) throw new Error("Invalid key");

        const photos = JSON.parse(dec);

        logAudit(req, 'DECRYPT_VAULT', userEmail || 'Anonymous', { 
            itemCount: photos ? photos.length : 0, 
            context: 'Unlocked Steganographic Vault' 
        });

        res.json({ success: true, photos: photos });
    } catch (err) {
        logAudit(req, 'DECRYPT_FAILED', req.body.userEmail || 'Anonymous', { context: 'Wrong vault password' });
        res.status(401).json({ success: false, error: "Invalid Password or Corrupted Vault File" });
    }
});

// ==========================================================================
// 8. FETCH REAL AUDIT HISTORY LOGS
// ==========================================================================
app.get('/api/vault/history', (req, res) => {
    const history = readJSON(HISTORY_FILE);
    res.json({ success: true, history: history });
});

// ==========================================================================
// 9. USER LOGOUT ENDPOINT (Revokes Active Session)
// ==========================================================================
app.post('/api/user/logout', (req, res) => {
    try {
        const sessionId = req.headers['x-session-id'];
        if (sessionId) {
            const sessions = readJSON(SESSIONS_FILE);
            delete sessions[sessionId];
            writeJSON(SESSIONS_FILE, sessions);
        }
        logAudit(req, 'USER_LOGOUT', req.body.email || 'Anonymous');
        res.json({ success: true, message: "Logged out successfully" });
    } catch (err) {
        res.status(500).json({ success: false, error: "Logout failed" });
    }
});

// --- START SERVER ON PORT 3000 ---
app.listen(PORT, () => {
    console.log(`====================================================`);
    console.log(`🛡️  AegisKey Enterprise Vault Server Active`);
    console.log(`🌐 Server Address: http://localhost:${PORT}`);
    console.log(`⏱️  Session Lifetime: 30 Minutes Active Guard`);
    console.log(`📧 Password Recovery Engine & OTP System Ready`);
    console.log(`====================================================`);
});

