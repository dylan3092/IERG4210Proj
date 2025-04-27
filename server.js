// Import environment variables
require('dotenv').config();

// Import required modules
const express = require('express');
const path = require('path');
const fs = require('fs'); // Make sure fs is imported at the top
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');
const cors = require('cors');
const multer = require('multer');
const crypto = require('crypto');
const xss = require('xss');
const https = require('https'); // Also import https at the top

const app = express();

// Trust the first hop from the reverse proxy (Apache)
app.set('trust proxy', 1); 

// Number of salt rounds for bcrypt
const SALT_ROUNDS = 12;

// Authentication utility functions
const authUtils = {
    // Hash a password with bcrypt
    async hashPassword(password) {
        try {
            const salt = await bcrypt.genSalt(SALT_ROUNDS);
            const hash = await bcrypt.hash(password, salt);
            return hash;
        } catch (error) {
            console.error('Error hashing password:', error);
            throw error;
        }
    },
    
    // Verify a password against a hash
    async verifyPassword(password, hash) {
        try {
            return await bcrypt.compare(password, hash);
        } catch (error) {
            console.error('Error verifying password:', error);
            return false;
        }
    },
    
    // Initialize the users table and create default users
    async initializeUsers(pool) {
        try {
            // Create users table if it doesn't exist
            await pool.query(`
                CREATE TABLE IF NOT EXISTS users (
                    userid INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) NOT NULL UNIQUE,
                    password VARCHAR(255) NOT NULL,
                    is_admin BOOLEAN DEFAULT FALSE,
                    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            `);
            
            console.log('Users table created or already exists');
            
            // Define initial users using environment variables
            const initialUsers = [
                {
                    email: process.env.ADMIN_EMAIL || 'admin@example.com',
                    password: process.env.ADMIN_PASSWORD || 'Admin@123',
                    admin: true
                },
                {
                    email: process.env.USER_EMAIL || 'user@example.com',
                    password: process.env.USER_PASSWORD || 'User@123',
                    admin: false
                }
            ];
            
            // Add each initial user if they don't already exist
            for (const user of initialUsers) {
                const [existingUsers] = await pool.query(
                    'SELECT * FROM users WHERE email = ?',
                    [user.email]
                );
                
                if (existingUsers.length === 0) {
                    const hashedPassword = await authUtils.hashPassword(user.password);
                    
                    // Use is_admin column name instead of admin
                    await pool.query(
                        'INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)',
                        [user.email, hashedPassword, user.admin]
                    );
                    
                    console.log(`User ${user.email} added`);
                } else {
                    console.log(`User ${user.email} already exists`);
                }
            }
        } catch (error) {
            console.error('Error initializing users:', error);
        }
    },
    
    // Check if a user is authenticated
    isAuthenticated(req) {
        return req.session && req.session.userId && req.session.isAuthenticated === true;
    },
    
    // Check if a user is an admin
    isAdmin(req) {
        return authUtils.isAuthenticated(req) && req.session.is_admin === true;
    },
    
    // Authentication middleware with enhanced security and logging
    authenticate: (req, res, next) => {
        if (authUtils.isAuthenticated(req)) {
            // Log authentication success
            const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            console.log(`[AUTH SUCCESS] User ${req.session.userEmail} authenticated from ${ipAddress}`);
            next();
        } else {
            // Log authentication failure
            const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
            console.log(`[AUTH FAILURE] Unauthenticated access attempt from ${ipAddress} to ${req.method} ${req.originalUrl}`);
            
            // Clear any existing invalid sessions
            if (req.session) {
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying invalid session:', err);
                    }
                    // Clear the session cookie
                    res.clearCookie('neon_session');
                    
                    // Redirect to login page for HTML requests
                    if (req.accepts('html')) {
                        return res.redirect('/login.html');
                    }
                    
                    // Return JSON error for API requests
                    res.status(401).json({ 
                        error: 'Authentication required',
                        message: 'You must be logged in to access this resource',
                        code: 'AUTH_REQUIRED'
                    });
                });
            } else {
                // Redirect to login page for HTML requests
                if (req.accepts('html')) {
                    return res.redirect('/login.html');
                }
                
                // Return JSON error for API requests
                res.status(401).json({ 
                    error: 'Authentication required',
                    message: 'You must be logged in to access this resource',
                    code: 'AUTH_REQUIRED'
                });
            }
        }
    },
    
    // Admin authorization middleware with enhanced security and logging
    authorizeAdmin: (req, res, next) => {
        const isAuthenticated = authUtils.isAuthenticated(req);
        const isAdmin = authUtils.isAdmin(req);
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.log(`[authorizeAdmin Check] Path: ${req.originalUrl}, Authenticated: ${isAuthenticated}, IsAdmin: ${isAdmin}, Session User:`, req.session.userEmail);
        
        if (isAuthenticated && isAdmin) {
            // Log admin authorization success
            console.log(`[ADMIN AUTH SUCCESS] Admin ${req.session.userEmail} authorized from ${ipAddress} for ${req.method} ${req.originalUrl}`);
            next();
        } else if (isAuthenticated) {
            // Log non-admin access attempt to admin resource
            console.log(`[ADMIN AUTH FAILURE - Not Admin] User ${req.session.userEmail} attempted access from ${ipAddress}: ${req.method} ${req.originalUrl}`);
            
            // Redirect to home page for HTML requests
            if (req.accepts('html')) {
                return res.redirect('/?error=not_authorized');
            }
            
            // Return JSON error for API requests
            res.status(403).json({ 
                error: 'Authorization required',
                message: 'Admin privileges required to access this resource',
                code: 'ADMIN_REQUIRED'
            });
        } else {
            // Log unauthenticated access attempt to admin resource
            console.log(`[ADMIN AUTH FAILURE - Not Authenticated] Unauthenticated access attempt from ${ipAddress}: ${req.method} ${req.originalUrl}`);
            
            // Redirect to login page for HTML requests
            if (req.accepts('html')) {
                return res.redirect('/login.html?error=auth_required&redirect=' + encodeURIComponent(req.originalUrl));
            }
            
            // Return JSON error for API requests
            res.status(401).json({ 
                error: 'Authentication required',
                message: 'You must be logged in as an admin to access this resource',
                code: 'AUTH_REQUIRED'
            });
        }
    }
};

// Generate a strong, persistent secret for the session
const getOrCreateSessionSecret = () => {
    // Use environment variable first (recommended for production)
    if (process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32) {
        return process.env.SESSION_SECRET;
    }
    
    // Generate a cryptographically secure random secret as fallback
    console.log('WARNING: No SESSION_SECRET environment variable set. Generating a random one.');
    console.log('This will invalidate all sessions when the server restarts.');
    console.log('For production, set a strong SESSION_SECRET environment variable.');
    
    // Use crypto.randomBytes for cryptographically secure randomness
    return crypto.randomBytes(64).toString('hex');
};

// Get or create a session secret
const SESSION_SECRET = getOrCreateSessionSecret();

// Session configuration
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false, // Don't create session until something stored
    name: 'neon_session', // Custom cookie name - not using a default predictable name
    cookie: {
        secure: true, // Always use secure cookies
        httpOnly: true,
        sameSite: 'lax', // Changed from 'strict' to 'lax' for redirect compatibility
        maxAge: 3 * 24 * 60 * 60 * 1000 // 3 days as per requirements
    },
    // Add custom session ID generation for maximum security
    genid: (req) => {
        // Generate a truly random session ID using crypto
        return crypto.randomBytes(32).toString('hex');
    }
}));

// Generate a strong, persistent secret for CSRF protection
const getOrCreateCsrfSecret = () => {
    // Use environment variable first (recommended for production)
    if (process.env.CSRF_SECRET && process.env.CSRF_SECRET.length >= 32) {
        return process.env.CSRF_SECRET;
    }
    
    // Generate a cryptographically secure random secret as fallback
    console.log('WARNING: No CSRF_SECRET environment variable set. Generating a random one.');
    console.log('This will invalidate all CSRF tokens when the server restarts.');
    console.log('For production, set a strong CSRF_SECRET environment variable.');
    
    // Use crypto.randomBytes for cryptographically secure randomness
    return crypto.randomBytes(64).toString('hex');
};

// Get or create a CSRF secret
const CSRF_SECRET = getOrCreateCsrfSecret();

// CSRF Protection Middleware
const csrfProtection = {
    // Generate a CSRF token based on multiple entropy sources
    generateToken: (req) => {
        if (!req.session) {
            throw new Error('Session middleware required');
        }
        
        // Get sources of entropy
        const sessionId = req.session.id;
        const timestamp = Date.now().toString();
        
        // Create data to hash - must match verification method
        const dataToHash = `${sessionId}:${timestamp}`;
        
        // Create a HMAC using the session ID and timestamp
        const hmac = crypto.createHmac('sha256', CSRF_SECRET);
        hmac.update(dataToHash);
        
        // Final token with timestamp component for expiration checks
        return `${hmac.digest('hex')}.${timestamp}`;
    },
    
    // Verify that the token is valid
    verifyToken: (req, token) => {
        if (!token) return false;
        
        try {
            // Split token to get timestamp and hash portions
            const [hash, timestamp] = token.split('.');
            
            // Bail if token format is incorrect
            if (!hash || !timestamp) return false;
            
            // Optional: Check if token is too old (e.g., more than 4 hours)
            const tokenAge = Date.now() - parseInt(timestamp, 10);
            if (tokenAge > 4 * 60 * 60 * 1000) { // 4 hours
                console.log('CSRF token expired');
                return false;
            }
            
            // Reconstruct expected hash using session ID and timestamp
            const sessionId = req.session.id;
            const dataToHash = `${sessionId}:${timestamp}`;
            
            const hmac = crypto.createHmac('sha256', CSRF_SECRET);
            hmac.update(dataToHash);
            
            const expectedHash = hmac.digest('hex');
            
            // Compare using timing-safe method to prevent timing attacks
            return crypto.timingSafeEqual(
                Buffer.from(hash),
                Buffer.from(expectedHash)
            );
        } catch (error) {
            console.error('CSRF token validation error:', error);
            return false;
        }
    },
    
    // Middleware to inject CSRF token into res.locals
    injectToken: (req, res, next) => {
        const csrfToken = csrfProtection.generateToken(req);
        res.locals.csrfToken = csrfToken;
        // Also add a hidden input field HTML snippet for convenience
        res.locals.csrfField = `<input type="hidden" name="_csrf" value="${csrfToken}">`;
        next();
    },
    
    // Middleware to verify CSRF token in requests
    verifyRequest: (req, res, next) => {
        // Skip CSRF check for GET, HEAD, OPTIONS requests - they should be safe
        if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
            return next();
        }
        
        // Get token from various possible sources
        const token = 
            req.body._csrf || 
            req.query._csrf || 
            req.headers['csrf-token'] || 
            req.headers['x-csrf-token'] || 
            req.headers['x-xsrf-token'];
        
        // Check for token existence and validity
        if (!token) {
            return res.status(403).json({ 
                error: 'CSRF token missing' 
            });
        }
        
        // Validate the token
        try {
            if (!csrfProtection.verifyToken(req, token)) {
                return res.status(403).json({ 
                    error: 'Invalid CSRF token' 
                });
            }
        } catch (error) {
            return res.status(403).json({ 
                error: 'CSRF validation error' 
            });
        }
        
        next();
    },
    
    // A simple API to get a new token (useful for SPA applications)
    getTokenAPI: (req, res) => {
        return res.json({ csrfToken: csrfProtection.generateToken(req) });
    }
};

// Origin validation middleware - Double verify the origin of requests
const validateOrigin = (req, res, next) => {
    const origin = req.headers.origin;
    const referer = req.headers.referer;
    
    // Get our host from the request
    const host = req.headers.host;
    
    // Skip check for GET requests - they should be safe
    if (req.method === 'GET') {
        return next();
    }
    
    if (origin) {
        // If origin header is present, check if it matches our domain
        const originHost = new URL(origin).host;
        if (originHost !== host) {
            return res.status(403).json({ error: 'Invalid origin' });
        }
    } else if (referer) {
        // If referer is present but origin is not, check referer
        const refererHost = new URL(referer).host;
        if (refererHost !== host) {
            return res.status(403).json({ error: 'Invalid referer' });
        }
    } else {
        // If neither origin nor referer is present for a non-GET request, reject
        // This is a conservative approach - you might want to relax this for APIs
        return res.status(403).json({ error: 'Origin validation failed' });
    }
    
    next();
};

// Middleware
app.use(express.static(__dirname)); // Serve files from the root directory
app.use(express.static('public'));  // Serve files from the public directory
app.use('/uploads', express.static('uploads'));
app.use('/js', express.static('public/js'));

// =========================================================================
// == SPECIAL ROUTES (Define BEFORE global body parsers if they have specific needs)
// =========================================================================

// PAYPAL IPN HANDLER - Use express.raw() BEFORE global parsers
app.post('/api/paypal-ipn', express.raw({ type: 'application/x-www-form-urlencoded', limit: '10mb' }), (req, res) => {
    // By using express.raw, req.body should *be* the raw Buffer
    const rawBodyBuffer = req.body;
    console.log(`[IPN Handler] Received raw buffer, length: ${rawBodyBuffer?.length}`);

    // Respond to PayPal immediately
    res.status(200).send('OK');

    // --- Process IPN verification --- 
    if (!rawBodyBuffer || rawBodyBuffer.length === 0) {
        console.error('[IPN] Verification failed: Raw body buffer was empty or missing.');
        return;
    }
    
    // Convert buffer to string for verification and manual parsing
    const rawBodyString = rawBodyBuffer.toString('utf8');
    console.log('[IPN] Raw body string:', rawBodyString);

    // Manually parse the necessary fields from the raw string for later use
    // (Using URLSearchParams is a safe way to handle urlencoded data)
    const parsedParams = new URLSearchParams(rawBodyString);
    const parsedBodyCopy = {};
    parsedParams.forEach((value, key) => { parsedBodyCopy[key] = value; });
    console.log('[IPN] Manually parsed body for checks:', parsedBodyCopy);

    // Use IIFE for async verification
    (async () => {
        try {
            // 1. Construct verification request body using URLSearchParams for robustness
            const originalParams = new URLSearchParams(rawBodyString);
            const verificationParams = new URLSearchParams();
            verificationParams.set('cmd', '_notify-verify');
            originalParams.forEach((value, key) => {
                verificationParams.append(key, value);
            });
            let verificationBody = verificationParams.toString();
            
            // 2. Send verification request back to PayPal Sandbox
            const options = {
                hostname: 'www.sandbox.paypal.com',  // Try main sandbox endpoint
                port: 443,
                path: '/cgi-bin/webscr',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8', // Explicitly add charset
                    'Content-Length': verificationBody.length,
                    'Connection': 'close',
                    'Host': 'www.sandbox.paypal.com', // Host should match hostname
                    'User-Agent': 'NodeJS-IPN-Verification',
                    'Accept': '*/*'
                }
            };

            console.log('[IPN] Sending verification request body (length):', verificationBody.length);
            const paypalRes = await new Promise((resolve, reject) => {
                const verificationReq = https.request(options, (paypalRes) => {
                    let data = '';
                    paypalRes.on('data', (chunk) => { data += chunk; });
                    paypalRes.on('end', () => resolve(data));
                });
                verificationReq.on('error', (e) => {
                    console.error('[IPN] Verification request error:', e);
                    reject(e);
                });
                verificationReq.write(verificationBody);
                verificationReq.end();
            });

            console.log('[IPN] Verification response from PayPal:', paypalRes);

            // 3. Process Verification Result (using manually parsed parsedBodyCopy)
            if (paypalRes === 'VERIFIED') {
                console.log('[IPN] VERIFIED. Processing payment data...');
                const { 
                    invoice, custom, txn_id, payment_status, mc_gross, mc_currency, receiver_email 
                } = parsedBodyCopy; // Use the manually parsed body

                // Basic checks
                if (!invoice || !custom || !txn_id) {
                     console.error('[IPN] Missing critical fields (invoice, custom, or txn_id).');
                     return; // Stop processing
                }

                // Fetch original order details from DB
                let connection;
                try {
                    connection = await pool.getConnection();
                    console.log(`[IPN] Checking database for Order ID: ${invoice}`); // Add log
                    const [orders] = await connection.query('SELECT * FROM orders WHERE order_id = ?', [invoice]);
                    
                    if (orders.length === 0) {
                        console.error(`[IPN] Order ID ${invoice} not found in database.`);
                        return; // Stop processing
                    }
                    const order = orders[0];
                    console.log(`[IPN] Found order:`, order); // Add log

                    // Perform validation checks
                    console.log(`[IPN] Validating order data...`); // Add log
                    if (order.status === 'COMPLETED') {
                        console.warn(`[IPN] Transaction ${txn_id} for Order ID ${invoice} already processed.`);
                        return; // Prevent double processing
                    }
                    if (payment_status !== 'Completed') {
                        console.warn(`[IPN] Payment status for Order ID ${invoice} is '${payment_status}', not 'Completed'. Ignoring.`);
                        return; 
                    }
                    const expectedEmail = process.env.PAYPAL_BUSINESS_EMAIL || 'sb-43rt9j39948135@business.example.com'; // Corrected default email based on logs
                    if (receiver_email !== expectedEmail) {
                        console.error(`[IPN] Receiver email mismatch for Order ID ${invoice}. Expected: ${expectedEmail}, Received: ${receiver_email}`);
                        return; 
                    }
                    if (mc_currency !== order.currency) {
                         console.error(`[IPN] Currency mismatch for Order ID ${invoice}. Expected: ${order.currency}, Received: ${mc_currency}`);
                         return; 
                    }
                    if (parseFloat(mc_gross) !== parseFloat(order.total_amount)) {
                         console.error(`[IPN] Amount mismatch for Order ID ${invoice}. Expected: ${order.total_amount}, Received: ${mc_gross}`);
                         return; 
                    }
                    if (custom !== order.digest) {
                         console.error(`[IPN] Digest mismatch for Order ID ${invoice}. Transaction may be tampered.`);
                         await connection.query('UPDATE orders SET status = ? WHERE order_id = ?', ['INVALID_DIGEST', invoice]);
                         return; 
                    }

                    // ALL CHECKS PASSED - Update order status
                    console.log(`[IPN] All checks passed for Order ID ${invoice}. Updating status to COMPLETED.`);
                    await connection.query(
                        'UPDATE orders SET status = ?, paypal_txn_id = ? WHERE order_id = ?',
                        ['COMPLETED', txn_id, invoice]
                    );
                    console.log(`[IPN] Order ID ${invoice} successfully marked as COMPLETED.`);

                } catch (dbError) {
                     console.error('[IPN] Database error during verification:', dbError);
                } finally {
                     if (connection) {
                        console.log(`[IPN] Releasing DB connection for order ${invoice}.`); // Add log
                        connection.release();
                     }
                }

            } else if (paypalRes === 'INVALID') {
                 console.error('[IPN] INVALID response from PayPal. IPN data may be fraudulent.');
            } else {
                 console.warn('[IPN] Received unexpected verification response from PayPal:', paypalRes);
            }
        } catch (verificationError) {
            console.error('[IPN] Error during async verification process:', verificationError);
        }
    })();
});

// =========================================================================
// == GLOBAL MIDDLEWARE (Body Parsers, Security Headers, CORS, Logging, etc.)
// =========================================================================

// GLOBAL Body Parsers - Define AFTER special routes like IPN
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Security headers middleware
app.use((req, res, next) => {
    // Prevent browsers from detecting MIME types incorrectly
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // Prevent clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // XSS protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer policy
    res.setHeader('Referrer-Policy', 'same-origin');
    
    // HTTP Strict Transport Security (force HTTPS)
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    
    next();
});

// Add CORS middleware first - before any CSRF or validation middleware
app.use((req, res, next) => {
    // Check if request is HTTP and not localhost
    if (req.headers['x-forwarded-proto'] !== 'https' && req.hostname !== 'localhost' && req.hostname !== '127.0.0.1') {
        // Redirect to HTTPS with same host and URL
        return res.redirect(301, `https://${req.headers.host}${req.url}`);
    }
    next();
});

app.use((req, res, next) => {
    // Set the specific origin instead of wildcard for credentials to work
    const origin = req.headers.origin;
    
    // Allow requests from both the main site and with port 3000
    if (origin) {
        res.header('Access-Control-Allow-Origin', origin);
        console.log(`Accepting request from origin: ${origin}`);
    }
    
    // Allow credentials (cookies, authorization headers, etc)
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, CSRF-Token, X-CSRF-Token');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        console.log('Handling OPTIONS preflight request');
        res.status(200).end();
        return;
    }
    
    next();
});

// Add request logging middleware
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Apply cookie parser middleware
app.use(cookieParser());

// Skip CSRF for login, logout, and API routes
app.use((req, res, next) => {
    // For login and logout endpoints, completely bypass protection
    if (req.path === '/api/login' || req.path === '/api/logout') {
        console.log('Completely bypassing protection for endpoint:', req.path);
        next();
        return;
    }
    
    // Skip CSRF for API endpoints that need to be accessed cross-origin
    if (req.path === '/api/categories' || req.path === '/api/products' || 
        req.path.startsWith('/api/products/')) {
        console.log('Skipping CSRF for:', req.path);
        next();
    } else {
        // For all other routes, apply CSRF protection
        csrfProtection.injectToken(req, res, () => {
            // Skip origin validation for API endpoints
            if (req.path === '/api/categories' || req.path === '/api/products' || 
                req.path.startsWith('/api/products/')) {
                next();
            } else {
                validateOrigin(req, res, next);
            }
        });
    }
});

// Apply CSRF validation for non-exempt routes
app.use((req, res, next) => {
    // For login and logout endpoints, already skipped in previous middleware
    if (req.path === '/api/login' || req.path === '/api/logout') {
        next();
        return;
    }
    
    // Skip CSRF validation for API endpoints
    if (req.path === '/api/categories' || req.path === '/api/products' || 
        req.path.startsWith('/api/products/')) {
        next();
    } else {
        csrfProtection.verifyRequest(req, res, next);
    }
});

// Add a route to get a CSRF token via API (useful for single page applications)
app.get('/api/csrf-token', csrfProtection.getTokenAPI);

// Input sanitization middleware
const sanitizeInput = (req, res, next) => {
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            if (typeof req.body[key] === 'string') {
                req.body[key] = xss(req.body[key]);
            }
        });
    }
    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === 'string') {
                req.query[key] = xss(req.query[key]);
            }
        });
    }
    if (req.params) {
        Object.keys(req.params).forEach(key => {
            if (typeof req.params[key] === 'string') {
                req.params[key] = xss(req.params[key]);
            }
        });
    }
    next();
};

// Apply sanitization middleware to all routes
app.use(sanitizeInput);

// Function to rotate session after successful login with enhanced security
const rotateSession = (req, originalData) => {
    return new Promise((resolve, reject) => {
        // Save the important session data before regeneration
        const userData = {
            userId: originalData.userId || null,
            userEmail: originalData.userEmail || null,
            is_admin: originalData.is_admin || false,
            isAuthenticated: originalData.isAuthenticated || false,
            // Add a login timestamp for potential inactivity checks
            loginTimestamp: Date.now()
        };
        
        // Record the old session ID for security logs
        const oldSessionId = req.session.id;
        
        // Generate a completely new session with a new ID
        req.session.regenerate((err) => {
            if (err) {
                console.error('Session rotation failed:', err);
                return reject(err);
            }
            
            // Restore user data to new session
            req.session.userId = userData.userId;
            req.session.userEmail = userData.userEmail;
            req.session.is_admin = userData.is_admin;
            req.session.isAuthenticated = userData.isAuthenticated;
            req.session.loginTimestamp = userData.loginTimestamp;
            
            // Add additional security measures
            req.session.userAgent = req.headers['user-agent'];
            req.session.ipAddress = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
            
            // Generate a unique token for this session (additional security)
            req.session.uniqueToken = crypto.randomBytes(32).toString('hex');
            
            console.log(`Session rotated with enhanced security: ${oldSessionId} → ${req.session.id}`);
            resolve();
        });
    });
};

// Add this near the top of server.js
const uploadDir = './uploads';
try {
    if (!require('fs').existsSync(uploadDir)) {
        require('fs').mkdirSync(uploadDir);
    }
} catch (err) {
    console.error('Error creating uploads directory:', err);
}

// Database connection
const dbConfig = {
    host: process.env.DB_HOST || 'localhost',
    user: process.env.DB_USER || 'root',
    password: process.env.DB_PASSWORD, // Using environment variable for security
    database: process.env.DB_NAME || 'shopping_db',
    port: process.env.DB_PORT || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};
console.log('[DB Connection] Creating pool with config:', dbConfig);

const pool = mysql.createPool(dbConfig);

// Define image sizes
const IMAGE_SIZES = {
    thumbnail: { width: 150, height: 150 },
    full: { width: 800, height: 800 }
};

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(file.originalname);
        // Store original filename in request for later use
        req.originalImageName = uniqueSuffix + ext;
        cb(null, req.originalImageName);
    }
});

const upload = multer({
    storage: storage,
    limits: {
        fileSize: 10 * 1024 * 1024 // 10MB
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png|gif/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
            return cb(null, true);
        }
        cb(new Error('Only images (jpg, jpeg, png, gif) are allowed!'));
    }
});

// Generate a cryptographically secure CSP nonce
const generateSecureNonce = () => {
    // Use 16 bytes (128 bits) of randomness for the nonce
    // This provides enough entropy to make nonces unguessable
    return crypto.randomBytes(16).toString('base64');
};

// Add this near the top, after creating the app
app.use((req, res, next) => {
    // Set the specific origin instead of wildcard for credentials to work
    const origin = req.headers.origin;
    
    // Allow requests from both the main site and with port 3000
    if (origin) {
        res.header('Access-Control-Allow-Origin', origin);
        console.log(`Accepting request from origin: ${origin}`);
    }
    
    // Allow credentials (cookies, authorization headers, etc)
    res.header('Access-Control-Allow-Credentials', 'true');
    res.header('Access-Control-Allow-Methods', 'GET, PUT, POST, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, CSRF-Token, X-CSRF-Token');
    
    // Handle preflight requests
    if (req.method === 'OPTIONS') {
        console.log('Handling OPTIONS preflight request');
        res.status(200).end();
        return;
    }
    
    // Generate a random nonce for this request
    const nonce = generateSecureNonce();
    
    // Add Content Security Policy header
    // This is a strict policy that helps prevent XSS attacks
    const cspDirectives = [
        // Default fallback - deny by default
        "default-src 'self'",
        // Scripts can be loaded from same origin and allow our external CDN
        // Also allow inline scripts with the generated nonce and unsafe-inline as a fallback
        `script-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000 http://s15.ierg4210.ie.cuhk.edu.hk 'nonce-${nonce}' 'unsafe-eval' 'unsafe-inline'`,
        // Styles can be loaded from same origin and allow our external CDN and inline styles
        "style-src 'self' https://cdn.jsdelivr.net http://s15.ierg4210.ie.cuhk.edu.hk:3000 http://s15.ierg4210.ie.cuhk.edu.hk 'unsafe-inline'",
        // Images can be loaded from same origin and data URIs
        "img-src 'self' data: http://s15.ierg4210.ie.cuhk.edu.hk:3000 http://s15.ierg4210.ie.cuhk.edu.hk",
        // Forms can only submit to same origin
        "form-action 'self'",
        // Frames can only load from same origin
        "frame-src 'self'",
        // Connect to only same origin and our API server
        "connect-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000 http://s15.ierg4210.ie.cuhk.edu.hk",
        // Font sources
        "font-src 'self' https://cdn.jsdelivr.net http://s15.ierg4210.ie.cuhk.edu.hk:3000 http://s15.ierg4210.ie.cuhk.edu.hk",
        // Media sources
        "media-src 'self'",
        // Object sources (plugins, etc)
        "object-src 'none'",
        // Base URI restriction to prevent base tag hijacking
        "base-uri 'self'",
        // Upgrade insecure requests
        "upgrade-insecure-requests"
    ];
    
    // Set CSP header - use report-only first to test before enforcing
    // Comment out for now as it may interfere with CORS
    // res.header('Content-Security-Policy-Report-Only', cspDirectives.join('; '));
    // res.header('Content-Security-Policy', cspDirectives.join('; '));
    
    // Make nonce available to templates if needed
    res.locals.cspNonce = nonce;
    
    next();
});

// Test database connection on server start
pool.getConnection()
    .then(async connection => {
        console.log('Successfully connected to MySQL database');
        
        // Initialize users table and default users
        await authUtils.initializeUsers(pool);
        
        // Check if categories table exists, create if not
        try {
            console.log('Checking categories table...');
            await pool.query(`
                CREATE TABLE IF NOT EXISTS categories (
                    catid INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) NOT NULL
                )
            `);
            console.log('Categories table exists or was created successfully');
            
            // Check if products table exists, create if not
            await pool.query(`
                CREATE TABLE IF NOT EXISTS products (
                    pid INT AUTO_INCREMENT PRIMARY KEY,
                    catid INT NOT NULL,
                    name VARCHAR(255) NOT NULL,
                    price DECIMAL(10, 2) NOT NULL,
                    description TEXT,
                    image VARCHAR(255),
                    thumbnail VARCHAR(255),
                    FOREIGN KEY (catid) REFERENCES categories(catid) ON DELETE CASCADE
                )
            `);
            console.log('Products table exists or was created successfully');
            
            // Count existing categories and products
            const [categoriesCount] = await pool.query('SELECT COUNT(*) as count FROM categories');
            const [productsCount] = await pool.query('SELECT COUNT(*) as count FROM products');
            
            console.log(`Database has ${categoriesCount[0].count} categories and ${productsCount[0].count} products`);
        } catch (error) {
            console.error('Error initializing database tables:', error);
        }
        
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to MySQL database:', err);
    });

// Categories API
app.get('/api/categories', async (req, res) => {
    try {
        console.log('Fetching categories from database...');
        const [rows] = await pool.query('SELECT * FROM categories');
        console.log('Categories fetched:', rows.length, 'items');
        console.log('Categories data:', JSON.stringify(rows));
        res.json(rows);
    } catch (error) {
        console.error('Error fetching categories:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/categories/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM categories WHERE catid = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Category not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching category:', error);
        res.status(500).json({ error: error.message });
    }
});

// Admin-only API routes - protected with admin authorization
// Create category (admin only)
app.post('/api/categories', authUtils.authorizeAdmin, async (req, res) => {
    try {
        console.log('Received category data:', req.body); // Debug log
        
        if (!req.body.name || req.body.name.trim() === '') {
            return res.status(400).json({ error: 'Category name is required' });
        }

        const [result] = await pool.query(
            'INSERT INTO categories (name) VALUES (?)', 
            [req.body.name.trim()]
        );
        
        res.json({ 
            catid: result.insertId, 
            name: req.body.name.trim() 
        });
    } catch (error) {
        console.error('Error creating category:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update category (admin only)
app.put('/api/categories/:id', authUtils.authorizeAdmin, async (req, res) => {
    try {
        const { name } = req.body;
        await pool.query('UPDATE categories SET name = ? WHERE catid = ?', [name, req.params.id]);
        res.json({ id: req.params.id, name });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete category (admin only)
app.delete('/api/categories/:id', authUtils.authorizeAdmin, async (req, res) => {
    try {
        await pool.query('DELETE FROM categories WHERE catid = ?', [req.params.id]);
        res.json({ message: 'Category deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Products API
app.get('/api/products', async (req, res) => {
    try {
        console.log('Fetching products from database...');
        let query = 'SELECT p.*, c.name as category_name FROM products p JOIN categories c ON p.catid = c.catid';
        
        const categoryId = req.query.category;
        let queryParams = [];
        
        if (categoryId) {
            query += ' WHERE p.catid = ?';
            queryParams.push(categoryId);
        }
        
        query += ' ORDER BY p.name';  // Optional: sort products by name
        
        const [rows] = await pool.query(query, queryParams);
        
        // Convert decimal strings to numbers
        const products = rows.map(product => ({
            ...product,
            price: Number(product.price)
        }));
        
        console.log(`Found ${products.length} products${categoryId ? ' in category ' + categoryId : ''}`);
        res.json(products);
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const query = 'SELECT p.*, c.name as category_name FROM products p JOIN categories c ON p.catid = c.catid WHERE p.pid = ?';
        
        const [rows] = await pool.query(query, [req.params.id]);
        
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ error: error.message });
    }
});

// Function to resize image and create thumbnail
async function processImage(originalPath, filename) {
    const ext = path.extname(filename);
    const baseFilename = path.basename(filename, ext);
    
    // Create thumbnail filename
    const thumbnailFilename = `${baseFilename}_thumb${ext}`;
    const thumbnailPath = path.join('./uploads', thumbnailFilename);

    // Resize original image (if larger than full size)
    await sharp(originalPath)
        .resize(IMAGE_SIZES.full.width, IMAGE_SIZES.full.height, {
            fit: 'inside',
            withoutEnlargement: true
        })
        .toFile(path.join('./uploads', `${baseFilename}_full${ext}`));

    // Create thumbnail
    await sharp(originalPath)
        .resize(IMAGE_SIZES.thumbnail.width, IMAGE_SIZES.thumbnail.height, {
            fit: 'cover'
        })
        .toFile(thumbnailPath);

    // Delete original uploaded file
    await fs.promises.unlink(originalPath);

    return {
        full: `${baseFilename}_full${ext}`,
        thumbnail: thumbnailFilename
    };
}

// Create product (admin only)
app.post('/api/products', authUtils.authorizeAdmin, upload.single('image'), async (req, res) => {
    try {
        console.log('Received product data:', req.body);
        console.log('Received file:', req.file);

        const { catid, name, price, description } = req.body;
        let imageFiles = null;

        if (req.file) {
            imageFiles = await processImage(
                req.file.path,
                req.originalImageName
            );
        }

        const [result] = await pool.query(
            'INSERT INTO products (catid, name, price, description, image, thumbnail) VALUES (?, ?, ?, ?, ?, ?)',
            [
                catid,
                name,
                price,
                description || null,
                imageFiles ? imageFiles.full : null,
                imageFiles ? imageFiles.thumbnail : null
            ]
        );

        res.json({
            pid: result.insertId,
            catid,
            name,
            price,
            description,
            image: imageFiles ? imageFiles.full : null,
            thumbnail: imageFiles ? imageFiles.thumbnail : null
        });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: error.message });
    }
});

// Update product (admin only)
app.put('/api/products/:id', authUtils.authorizeAdmin, upload.single('image'), async (req, res) => {
    try {
        const { catid, name, price, description } = req.body;
        let imageFiles = null;

        if (req.file) {
            // Delete old images if they exist
            const [oldProduct] = await pool.query(
                'SELECT image, thumbnail FROM products WHERE pid = ?',
                [req.params.id]
            );

            if (oldProduct[0].image) {
                await fs.promises.unlink(path.join('./uploads', oldProduct[0].image))
                    .catch(() => {});
            }
            if (oldProduct[0].thumbnail) {
                await fs.promises.unlink(path.join('./uploads', oldProduct[0].thumbnail))
                    .catch(() => {});
            }

            imageFiles = await processImage(
                req.file.path,
                req.originalImageName
            );
        }

        const updateQuery = imageFiles
            ? 'UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ?, thumbnail = ? WHERE pid = ?'
            : 'UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?';

        const updateParams = imageFiles
            ? [catid, name, price, description, imageFiles.full, imageFiles.thumbnail, req.params.id]
            : [catid, name, price, description, req.params.id];

        await pool.query(updateQuery, updateParams);

        res.json({
            id: req.params.id,
            catid,
            name,
            price,
            description,
            image: imageFiles ? imageFiles.full : undefined,
            thumbnail: imageFiles ? imageFiles.thumbnail : undefined
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Delete product (admin only)
app.delete('/api/products/:id', authUtils.authorizeAdmin, async (req, res) => {
    try {
        // Delete associated image
        const [oldProduct] = await pool.query('SELECT image FROM products WHERE pid = ?', [req.params.id]);
        if (oldProduct[0].image) {
            await fs.promises.unlink(path.join('./uploads', oldProduct[0].image)).catch(() => {});
        }

        await pool.query('DELETE FROM products WHERE pid = ?', [req.params.id]);
        res.json({ message: 'Product deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// Get products by category
app.get('/api/categories/:catid/products', async (req, res) => {
    try {
        const [rows] = await pool.query(
            'SELECT * FROM products WHERE catid = ?', 
            [req.params.catid]
        );
        res.json(rows);
    } catch (error) {
        console.error('Error fetching category products:', error);
        res.status(500).json({ error: error.message });
    }
});

// Add a route to handle CSP violation reports
app.post('/api/csp-report', express.json({ type: 'application/csp-report' }), (req, res) => {
    console.log('CSP Violation:', req.body);
    res.status(204).end();
});

// Also add a route for standard Reporting API reports
app.post('/api/csp-report', express.json({ type: 'application/reports+json' }), (req, res) => {
    console.log('CSP Violation (Reporting API):', req.body);
    res.status(204).end();
});

// Function to generate a secure login nonce
const generateLoginNonce = () => {
    return crypto.randomBytes(32).toString('hex');
};

// Route to get a login nonce - can be called before attempting login
app.get('/api/login-nonce', (req, res) => {
    // Generate a secure random nonce for this login attempt
    const loginNonce = generateLoginNonce();
    
    // Store the nonce in the session with an expiration time
    // Even unauthenticated users can have session for CSRF protection
    if (!req.session.loginNonces) {
        req.session.loginNonces = [];
    }
    
    // Keep a limited number of valid nonces with timestamps
    // This allows multiple login attempts while preventing nonce reuse
    req.session.loginNonces.push({
        nonce: loginNonce,
        created: Date.now(),
        used: false
    });
    
    // Keep only the 5 most recent nonces to prevent session bloat
    if (req.session.loginNonces.length > 5) {
        req.session.loginNonces.shift(); // Remove oldest
    }
    
    res.json({ nonce: loginNonce });
});

// Login endpoint with enhanced security
app.post('/api/login', async (req, res) => {
    try {
        console.log('Login attempt received:', req.body.email);
        const { email, password, loginNonce } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        // Verify login nonce to prevent login CSRF attacks
        let validNonce = false;
        
        if (req.session.loginNonces && loginNonce) {
            // Find the nonce in the session
            const nonceIndex = req.session.loginNonces.findIndex(n => 
                n.nonce === loginNonce && !n.used && 
                (Date.now() - n.created) < 15 * 60 * 1000 // 15 minutes max age
            );
            
            if (nonceIndex >= 0) {
                // Mark the nonce as used
                req.session.loginNonces[nonceIndex].used = true;
                validNonce = true;
            }
        }
        
        // Only require nonce in production for better security
        if (process.env.NODE_ENV === 'production' && !validNonce) {
            console.warn('Invalid or missing login nonce - possible CSRF attack from:', 
                req.headers['x-forwarded-for'] || req.connection.remoteAddress);
            return res.status(403).json({ error: 'Invalid login nonce', requireNonce: true });
        }

        // Use pool query instead of getDB
        const [users] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];
        
        if (!user) {
            console.log('User not found:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            console.log('Password mismatch for user:', email);
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        console.log('User authenticated successfully:', email);
        
        // Store temporary user data
        const sessionData = {
            userId: user.userid,
            userEmail: user.email,
            is_admin: user.is_admin === 1 || user.is_admin === true,
            isAuthenticated: true
        };
        
        try {
            // Rotate session to prevent session fixation attacks
            await rotateSession(req, sessionData);
            
            // Explicitly save the session before sending the response
            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('Error saving session after login rotation:', saveErr);
                    // Proceed with login but log the error
                    return res.status(500).json({ error: 'Session save error during login' }); 
                }
                
                console.log('Session saved after rotation. Sending success response.');
                // Return success response AFTER session is saved
                return res.status(200).json({ 
                    success: true,
                    user: {
                        email: user.email,
                        isAdmin: sessionData.is_admin
                    }
                });
            });

        } catch (sessionError) {
            console.error('Error during session rotation:', sessionError);
            return res.status(500).json({ error: 'Session error during login' });
        }
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/logout', async (req, res) => {
    try {
        console.log('Logout attempt received');
        
        if (!req.session || !req.session.isAuthenticated) {
            return res.status(200).json({ success: true, message: 'Already logged out' });
        }
        
        // Log who is logging out for audit purposes
        console.log(`User logged out: ${req.session.userEmail} (ID: ${req.session.userId})`);
        
        // Clear session data
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session:', err);
                return res.status(500).json({ error: 'Failed to logout' });
            }
            
            // Clear the session cookie by setting it to expire in the past
            res.clearCookie('neon_session', {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            });
            
            console.log('User logged out successfully');
            res.status(200).json({ success: true });
        });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password endpoint (requires authentication)
app.post('/api/change-password', authUtils.authenticate, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }

        // Get user from database
        const [users] = await pool.query('SELECT * FROM users WHERE userid = ?', [req.session.userId]);
        if (users.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        const user = users[0];
        
        // Verify current password
        const passwordMatch = await bcrypt.compare(currentPassword, user.password);
        if (!passwordMatch) {
            console.log('Password change attempt with incorrect current password for user:', user.email);
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Validate new password - Add your password policy here
        if (newPassword.length < 8) {
            return res.status(400).json({ error: 'New password must be at least 8 characters long' });
        }
        
        // Hash new password
        const hashedPassword = await authUtils.hashPassword(newPassword);
        
        // Update password in database
        await pool.query('UPDATE users SET password = ? WHERE userid = ?', [hashedPassword, user.userid]);
        
        console.log('Password changed successfully for user:', user.email);
        
        // Log action for security audit
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        console.log(`[PASSWORD CHANGE] User ${user.email} changed password from ${ipAddress}`);
        
        // Log out the user by destroying the session
        req.session.destroy((err) => {
            if (err) {
                console.error('Error destroying session after password change:', err);
                return res.status(500).json({ 
                    success: true, 
                    message: 'Password changed successfully, but session could not be cleared. Please log out manually.' 
                });
            }
            
            // Clear the session cookie
            res.clearCookie('neon_session', {
                path: '/',
                httpOnly: true,
                secure: true,
                sameSite: 'strict'
            });
            
            // Return success response
            res.status(200).json({ 
                success: true, 
                message: 'Password changed successfully. Please log in with your new password.' 
            });
        });
    } catch (error) {
        console.error('Password change error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Add specific route for login page
app.get('/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Add specific route for admin page - protected with admin authorization
app.get('/admin', authUtils.authorizeAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.get('/admin.html', authUtils.authorizeAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Add middleware to attach user info from session to res.locals
app.use((req, res, next) => {
    // Check if the user is authenticated
    res.locals.isAuthenticated = req.session && req.session.isAuthenticated === true;
    
    // If authenticated, add user info to res.locals for use in templates
    if (res.locals.isAuthenticated) {
        res.locals.user = {
            email: req.session.userEmail,
            isAdmin: req.session.is_admin
        };
        
        // Add session expiry time 
        const expiryDate = new Date(req.session.cookie._expires);
        const now = new Date();
        const hoursLeft = Math.floor((expiryDate - now) / (1000 * 60 * 60));
        
        // Log activity for authenticated users (helpful for debugging)
        console.log(`Authenticated request [${req.method}] ${req.path} by ${req.session.userEmail}`);
        
        // Extend session if less than 1 day left (rolling session)
        if (hoursLeft < 24) {
            console.log(`Extending session for ${req.session.userEmail} (was expiring in ${hoursLeft} hours)`);
            req.session.touch();
        }
    }
    
    next();
});

// Enhanced session validation middleware
app.use((req, res, next) => {
    // Skip for unauthenticated requests
    if (!req.session || !req.session.isAuthenticated) {
        return next();
    }
    
    // Check if session contains the necessary security information
    if (!req.session.uniqueToken || !req.session.userAgent || !req.session.ipAddress) {
        console.warn('Session missing security tokens - possible session hijacking attempt');
        req.session.destroy();
        return res.status(403).redirect('/login.html?error=session_invalid');
    }
    
    // Validate the user agent hasn't changed (prevents certain session hijacking attacks)
    const currentUserAgent = req.headers['user-agent'];
    if (req.session.userAgent !== currentUserAgent) {
        console.warn('User agent mismatch - possible session hijacking attempt');
        console.warn(`Stored: ${req.session.userAgent}`);
        console.warn(`Current: ${currentUserAgent}`);
        req.session.destroy();
        return res.status(403).redirect('/login.html?error=session_invalid');
    }
    
    // Check IP address for significant changes (optional, can cause false positives)
    const currentIp = req.headers['x-forwarded-for'] || req.connection.remoteAddress;
    // Only log for now, don't enforce, as legitimate IP changes can happen (mobile users, etc.)
    if (req.session.ipAddress !== currentIp) {
        console.warn(`IP address changed for user ${req.session.userEmail}: ${req.session.ipAddress} -> ${currentIp}`);
    }
    
    // Check for session expiration based on inactivity (optional)
    const inactivityPeriod = 60 * 60 * 1000; // 1 hour inactivity timeout
    
    if (req.session.lastActivity && (Date.now() - req.session.lastActivity > inactivityPeriod)) {
        console.log(`Session expired due to inactivity for user ${req.session.userEmail}`);
        req.session.destroy();
        return res.status(403).redirect('/login.html?error=session_expired');
    }
    
    // Update last activity timestamp
    req.session.lastActivity = Date.now();
    
    next();
});

// API endpoint to check authentication status
app.get('/api/auth/status', (req, res) => {
    if (authUtils.isAuthenticated(req)) {
        // Return user information but not sensitive data
        res.json({
            authenticated: true,
            user: {
                email: req.session.userEmail,
                isAdmin: req.session.is_admin === true
            },
            // Add session expiry info
            session: {
                expiresIn: new Date(req.session.cookie._expires) - new Date()
            }
        });
    } else {
        res.json({
            authenticated: false
        });
    }
});

// =========================================================================
// == ORDER CREATION API (/api/create-order)
// =========================================================================
app.post('/api/create-order', authUtils.authenticate, async (req, res) => {
    const userId = req.session.userId; 
    const userEmail = req.session.userEmail; 
    console.log(`[create-order] Starting order creation for user: ${userEmail} (ID: ${userId})`); // Log start

    // 1. Validate Incoming Data
    const cartItems = req.body.items; 
    console.log('[create-order] Raw cart items received:', cartItems); // Log input
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
        return res.status(400).json({ error: 'Invalid or empty cart data.' });
    }

    const validatedItemsInput = cartItems.map(item => ({
        pid: parseInt(item.pid), // Ensure pid is integer
        quantity: parseInt(item.quantity) // Ensure quantity is integer
    })).filter(item => 
        !isNaN(item.pid) && item.pid > 0 &&
        !isNaN(item.quantity) && item.quantity > 0 && item.quantity <= 100 // Add reasonable max quantity
    );

    if (validatedItemsInput.length !== cartItems.length) {
        console.warn('Some cart items failed basic validation:', cartItems, validatedItemsInput);
        return res.status(400).json({ error: 'Invalid item data in cart (PID or quantity).' });
    }
    
    const pids = validatedItemsInput.map(item => item.pid);
    console.log('[create-order] Validated PIDs:', pids); // Log validated PIDs
    if (pids.length === 0) {
         return res.status(400).json({ error: 'No valid items found in cart.' });
    }

    let connection;
    try {
        console.log('[create-order] Attempting to get DB connection...'); // Log connection attempt
        connection = await pool.getConnection();
        console.log('[create-order] DB connection obtained. Starting transaction...'); // Log connection success
        await connection.beginTransaction();
        console.log('[create-order] Transaction started.'); // Log transaction start

        // 2. Fetch Product Details & Calculate Total from DB
        const placeholders = pids.map(() => '?').join(',');
        const sql = `SELECT pid, name, price FROM products WHERE pid IN (${placeholders})`;
        console.log('[create-order] Fetching product details with SQL:', sql, pids); // Log product fetch query
        const [productsFromDb] = await connection.query(sql, pids);
        console.log('[create-order] Products fetched from DB:', productsFromDb); // Log fetched products

        if (productsFromDb.length !== pids.length) {
             console.error('[create-order] DB Fetch Error: Not all product IDs found. Rolling back.', pids, productsFromDb);
             await connection.rollback(); 
             return res.status(404).json({ error: 'One or more products not found.' });
        }

        let totalAmount = 0;
        const finalOrderItems = []; 
        const productMap = new Map(productsFromDb.map(p => [p.pid, p]));

        console.log('[create-order] Calculating total and preparing final items...'); // Log calculation start
        for (const inputItem of validatedItemsInput) {
            const product = productMap.get(inputItem.pid);
            if (!product) {
                 console.error('[create-order] Consistency Error: Product missing from map', inputItem.pid);
                 await connection.rollback(); 
                 return res.status(500).json({ error: 'Internal server error during price validation.' });
            }
            const priceFromDb = parseFloat(product.price);
            const itemTotal = priceFromDb * inputItem.quantity;
            totalAmount += itemTotal;

            finalOrderItems.push({
                pid: inputItem.pid,
                quantity: inputItem.quantity,
                name: product.name, // Needed for PayPal form later? Maybe not needed for digest itself
                price_at_purchase: priceFromDb
            });
        }
        console.log('[create-order] Total calculated:', totalAmount, 'Final items:', finalOrderItems); // Log calculation end

        // 3. Generate Salt and Digest
        const currency = 'HKD'; 
        const merchantEmail = process.env.PAYPAL_BUSINESS_EMAIL || 'sb-43rt9j39948135@business.example.com'; 
        const salt = crypto.randomBytes(16).toString('hex');
        const digestData = JSON.stringify({
            currency,
            merchant: merchantEmail,
            salt,
            items: finalOrderItems.map(item => ({
                 pid: item.pid, 
                 qty: item.quantity, 
                 price: item.price_at_purchase 
            })).sort((a, b) => a.pid - b.pid),
            total: totalAmount.toFixed(2)
        });
        const digest = crypto.createHash('sha256').update(digestData).digest('hex');
        console.log('[create-order] Salt and Digest generated:', { salt, digest }); // Log digest generation

        // 4. Store Order in DB
        const orderSql = 'INSERT INTO orders (user_id, user_email, total_amount, currency, salt, digest, status) VALUES (?, ?, ?, ?, ?, ?, ?)';
        const orderParams = [userId, userEmail, totalAmount.toFixed(2), currency, salt, digest, 'PENDING'];
        console.log('[create-order] Inserting into orders table:', orderSql, orderParams); // Log order insert query
        const [orderResult] = await connection.query(orderSql, orderParams);
        const orderId = orderResult.insertId;
        console.log('[create-order] Order inserted successfully. Order ID:', orderId); // Log order insert success

        // Insert items into order_items
        console.log('[create-order] Inserting order items...'); // Log item insert start
        const itemInsertPromises = finalOrderItems.map(item => {
            const itemSql = 'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)';
            const itemParams = [orderId, item.pid, item.quantity, item.price_at_purchase.toFixed(2)];
            // console.log('[create-order] Item SQL:', itemSql, itemParams); // Optional: Log each item query
            return connection.query(itemSql, itemParams);
        });
        await Promise.all(itemInsertPromises);
        console.log('[create-order] Order items inserted successfully.'); // Log item insert success

        // 5. Commit Transaction
        console.log('[create-order] Committing transaction...'); // Log commit attempt
        await connection.commit();
        console.log('[create-order] Transaction committed.'); // Log commit success

        // 6. Return Order ID and Digest to Client
        console.log('[create-order] Sending success response to client:', { orderId, digest }); // Log success response
        res.json({ orderId: orderId, digest: digest });

    } catch (error) {
        // Log the specific error that occurred *before* rollback
        console.error('[create-order] Error occurred within try block:', error); 
        if (connection) {
            console.log('[create-order] Rolling back transaction due to error.'); // Log rollback attempt
            await connection.rollback(); 
            console.log('[create-order] Transaction rolled back.'); // Log rollback success
        }
        // The generic error response is fine, the detailed error is in the log above
        res.status(500).json({ error: 'Failed to create order due to a server error.' });
    } finally {
        if (connection) {
            console.log('[create-order] Releasing DB connection.'); // Log connection release
            connection.release();
        }
    }
});

// Add a catch-all route handler for 404 errors
app.use((req, res, next) => {
    // API routes should return JSON
    if (req.path.startsWith('/api/')) {
        return res.status(404).json({ error: 'API endpoint not found' });
    }
    
    // For GET requests to HTML pages, serve a custom 404 page
    if (req.method === 'GET' && (req.accepts('html') || req.path.endsWith('.html'))) {
        return res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
    }
    
    // Default 404 handler
    res.status(404).send('404 - Not Found');
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: err.message });
});

// Existing HTTP server code - keep this for redirection
const httpPort = process.env.PORT || 3000;
const server = app.listen(httpPort, () => {
    console.log(`Server is listening on port ${httpPort}`);
    console.log(`Try opening http://localhost:${httpPort} in your browser`);
});

// Notify that we're relying on Apache for SSL
console.log('Running in HTTP mode only. SSL/HTTPS is managed by Apache.');
console.log('The server is listening on port 3000 for proxied connections.'); 
