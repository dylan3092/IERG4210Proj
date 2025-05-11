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
const sharp = require('sharp'); // <<< ADD THIS LINE
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY); // <<<<<< ADD STRIPE

const app = express();
app.disable('x-powered-by'); // <<< ADD THIS LINE

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
        const isAuthenticated = authUtils.isAuthenticated(req);
        const ipAddress = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
        const isAPIRequest = !req.accepts('html'); // Simplified check for API
        
        console.log(`[AUTH MIDDLEWARE] Path: ${req.originalUrl}, Method: ${req.method}, Authenticated: ${isAuthenticated}, IsAPI: ${isAPIRequest}, SessionID: ${req.session?.id}`); // <<< ADD AUTH LOG
        
        if (isAuthenticated) {
            // Log authentication success
            console.log(`[AUTH SUCCESS] User ${req.session.userEmail} authenticated from ${ipAddress}`);
            next();
        } else {
            // Log authentication failure
            console.log(`[AUTH FAILURE] Unauthenticated access attempt from ${ipAddress} to ${req.method} ${req.originalUrl}`);
            
            // Clear any existing invalid sessions
            if (req.session) {
                req.session.destroy((err) => {
                    if (err) {
                        console.error('Error destroying invalid session:', err);
                    }
                    // Clear the session cookie
                    res.clearCookie('neon_session');
                    
                    // Decide response based on request type
                    if (isAPIRequest) {
                        console.log('[AUTH FAILURE] Responding with 401 JSON for API request'); // <<< ADD API FAIL LOG
                        return res.status(401).json({ 
                            error: 'Authentication required',
                            message: 'You must be logged in to access this resource',
                            code: 'AUTH_REQUIRED'
                        });
                    } else {
                        console.log('[AUTH FAILURE] Redirecting to login.html for HTML request'); // <<< ADD HTML FAIL LOG
                        return res.redirect('/login.html');
                    }
                });
            } else {
                // Decide response based on request type (no session to destroy)
                 if (isAPIRequest) {
                     console.log('[AUTH FAILURE] Responding with 401 JSON for API request (no session)');
                     return res.status(401).json({ 
                         error: 'Authentication required',
                         message: 'You must be logged in to access this resource',
                         code: 'AUTH_REQUIRED'
                     });
                 } else {
                     console.log('[AUTH FAILURE] Redirecting to login.html for HTML request (no session)');
                     return res.redirect('/login.html');
                 }
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
            
            // Check if token is too old (more than 1 hour)
            const tokenAge = Date.now() - parseInt(timestamp, 10);
            if (tokenAge > 1 * 60 * 60 * 1000) { // 1 hour
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
app.use(express.static(path.join(__dirname, 'public')));  // Serve files from the public directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// <<< ADD EARLY LOGGING MIDDLEWARE HERE >>>
app.use((req, res, next) => {
    console.log(`[EARLY LOG] Request Received: ${req.method} ${req.originalUrl}`);
    // Optionally log headers if needed for debugging proxies etc.
    // console.log('[EARLY LOG] Headers:', req.headers);
    next(); // Pass control to the next middleware/route
});
// <<< END EARLY LOGGING MIDDLEWARE >>>

// =========================================================================
// == SPECIAL ROUTES (Define BEFORE global body parsers if they have specific needs)
// =========================================================================

// STRIPE WEBHOOK HANDLER - Use express.raw() BEFORE global parsers
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), async (req, res) => {
    const sig = req.headers['stripe-signature'];
    // Make sure to set STRIPE_WEBHOOK_SECRET in your .env file
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
        console.error('[Stripe Webhook] Error: STRIPE_WEBHOOK_SECRET not set in environment variables.');
        return res.status(500).send('Webhook configuration error.');
    }

    let event;

    try {
        // Use the raw body buffer received
        event = stripe.webhooks.constructEvent(req.body, sig, webhookSecret);
    } catch (err) {
        console.error(`[Stripe Webhook] Signature verification failed: ${err.message}`);
        console.error(`[Stripe Webhook] Signature Header: ${sig}`);
        return res.status(400).send(`Webhook Error: ${err.message}`);
    }

    console.log(`[Stripe Webhook] Received event: ${event.type}, ID: ${event.id}`);

    // Handle the event
    switch (event.type) {
        case 'checkout.session.completed':
            const session = event.data.object;
            console.log(`[Stripe Webhook] Checkout Session Completed for ID: ${session.id}`);

            // --- Fulfillment Logic ---
            // Retrieve orderId from metadata
            const orderId = parseInt(session.metadata?.orderId, 10); // Use optional chaining
            const paymentIntentId = session.payment_intent; // Can store this

            if (!orderId) {
                console.error('[Stripe Webhook] Error: Missing orderId in session metadata!', session.metadata);
                // Don't give potentially sensitive info back to caller
                return res.status(400).send('Webhook Error: Missing required metadata.');
            }
            if (!paymentIntentId) {
                 console.error('[Stripe Webhook] Error: Missing payment_intent in session!', session);
                 return res.status(400).send('Webhook Error: Missing payment intent.');
            }

            let connection;
            try {
                connection = await pool.getConnection();
                await connection.beginTransaction(); // Start transaction for update safety

                // Check if order exists and is PENDING
                const [orders] = await connection.query('SELECT * FROM orders WHERE order_id = ? FOR UPDATE', [orderId]);
                if (orders.length === 0) {
                     console.error(`[Stripe Webhook] Order ID ${orderId} not found.`);
                     await connection.rollback();
                     return res.status(404).send('Order not found.'); // Changed status code
                }
                const order = orders[0];

                // Check if already processed (idempotency)
                if (order.status !== 'PENDING') {
                     console.warn(`[Stripe Webhook] Order ${orderId} already processed or not pending. Status: ${order.status}.`);
                     await connection.rollback(); // Rollback, no changes needed
                     return res.status(200).json({ received: true, message: 'Order already processed or not in pending state.' }); // OK status, already handled
                }

                // Validate amount (optional but recommended)
                // Stripe amount is in cents
                const expectedAmountCents = Math.round(parseFloat(order.total_amount) * 100);
                if (session.amount_total !== expectedAmountCents) {
                    console.error(`[Stripe Webhook] Amount mismatch for Order ${orderId}. DB: ${order.total_amount} (${expectedAmountCents} cents), Stripe: ${session.amount_total} cents`);
                    // Update order status to indicate error, store payment intent ID
                    await connection.query('UPDATE orders SET status = ?, stripe_payment_intent_id = ?, stripe_session_id = ? WHERE order_id = ?', ['AMOUNT_MISMATCH', paymentIntentId, session.id, orderId]);
                    await connection.commit(); // Commit the error status
                    // Still return 400 as it's a processing error from webhook perspective
                    return res.status(400).send('Amount mismatch.');
                }

                 // Validate currency (optional but recommended)
                if (session.currency.toLowerCase() !== order.currency.toLowerCase()) {
                    console.error(`[Stripe Webhook] Currency mismatch for Order ${orderId}. DB: ${order.currency}, Stripe: ${session.currency}`);
                     await connection.query('UPDATE orders SET status = ?, stripe_payment_intent_id = ?, stripe_session_id = ? WHERE order_id = ?', ['CURRENCY_MISMATCH', paymentIntentId, session.id, orderId]);
                     await connection.commit();
                    return res.status(400).send('Currency mismatch.');
                }

                // Update order status to COMPLETED and store Stripe IDs
                const [updateResult] = await connection.query(
                    'UPDATE orders SET status = ?, stripe_payment_intent_id = ?, stripe_session_id = ? WHERE order_id = ? AND status = ?', // Add status check for safety
                    ['COMPLETED', paymentIntentId, session.id, orderId, 'PENDING']
                );

                if (updateResult.affectedRows > 0) {
                    await connection.commit(); // Commit successful update
                    console.log(`[Stripe Webhook] Order ${orderId} marked as COMPLETED.`);
                } else {
                    // This case should ideally not happen due to the SELECT FOR UPDATE and status check, but good to handle
                    console.warn(`[Stripe Webhook] Order ${orderId} status was not PENDING during update attempt, rolling back.`);
                    await connection.rollback();
                    return res.status(409).send('Conflict: Order status changed unexpectedly.'); // Conflict status
                }

            } catch (dbError) {
                console.error('[Stripe Webhook] Database error during fulfillment:', dbError);
                if (connection) await connection.rollback(); // Rollback on error
                // Don't send 200, Stripe will retry on server errors
                return res.status(500).send('Internal Server Error');
            } finally {
                if (connection) connection.release();
            }
            break;

        case 'payment_intent.succeeded':
            // Optional: Handle this event if needed, though checkout.session.completed is usually sufficient for Checkout flows
            const paymentIntent = event.data.object;
            console.log(`[Stripe Webhook] PaymentIntent Succeeded: ${paymentIntent.id}`);
            // Could add logic here if you initiate payments differently (e.g., PaymentIntents API directly)
            break;

         case 'payment_intent.payment_failed':
             const failedPaymentIntent = event.data.object;
             const paymentError = failedPaymentIntent.last_payment_error;
             console.log(`[Stripe Webhook] PaymentIntent Failed: ${failedPaymentIntent.id}, Reason: ${paymentError?.message} (Code: ${paymentError?.code})`);
             // Optionally update order status to FAILED. Need a way to link payment_intent back to orderId
             // This is harder if only checkout.session.completed stores the metadata reliably.
             // Consider logging the failed checkout session ID if available on the payment intent for easier lookup.
             // const sessionId = failedPaymentIntent.metadata?.checkout_session_id; // Check if Stripe adds this
             // if (sessionId) { /* find order by session id and update status */ }
             break;

        // ... handle other event types as needed

        default:
            console.log(`[Stripe Webhook] Unhandled event type ${event.type}`);
    }

    // Return a 200 response to acknowledge receipt of the event
    res.status(200).json({ received: true }); // Send JSON response as best practice
});

// =========================================================================
// == GLOBAL MIDDLEWARE (Body Parsers, Security Headers, CORS, Logging, etc.)
// =========================================================================

// GLOBAL Body Parsers - Define AFTER special routes like webhook
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// <<< ADD LOGGING AFTER BODY PARSERS >>>
app.use((req, res, next) => {
    // Log only for specific paths if needed to reduce noise, or log all
    // if (req.path === '/api/register' || req.path === '/api/login') { 
         console.log(`[BODY PARSER CHECK] Parsers finished for: ${req.method} ${req.originalUrl}`);
         // console.log('[BODY PARSER CHECK] req.body:', req.body); // Uncomment to log parsed body
    // }
    next();
});
// <<< END LOGGING AFTER BODY PARSERS >>>

// Security headers middleware - REMOVED (Handled by Apache)
/* // <<< TEMPORARILY COMMENT OUT ENTIRE CSP MIDDLEWARE BLOCK FOR DEBUGGING
app.use((req, res, next) => {
    // ... (OLD HEADER CODE)
});
*/ // <<< END TEMPORARY COMMENT OUT >>>

// <<< START HTTPS REDIRECTION MIDDLEWARE >>>
// Enforce HTTPS based on X-Forwarded-Proto header from Apache proxy
app.use((req, res, next) => {
    // app.set('trust proxy', 1) ensures req.secure reflects X-Forwarded-Proto
    // Redirect if not secure and the request is not coming from localhost
    if (!req.secure && req.hostname !== 'localhost' && req.hostname !== '127.0.0.1') {
        console.log(`Insecure request detected for host ${req.headers.host}, redirecting to HTTPS...`);
        // Use req.originalUrl to preserve the full path and query string
        return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    }
    // Proceed if the request is already secure or from localhost
    next(); 
});
// <<< END HTTPS REDIRECTION MIDDLEWARE >>>

// Add CORS middleware first - before any CSRF or validation middleware
// Define allowed origins
const allowedOrigins = [
    'https://s15.ierg4210.ie.cuhk.edu.hk', // Your main domain
    // Add any other trusted origins if necessary, e.g., 'http://localhost:8080' for local development
];

const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            // Origin is in the allowed list
            callback(null, true);
        } else {
            // Origin is not allowed
            console.warn(`CORS blocked for origin: ${origin}`); // Log blocked attempts
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true, // Allow cookies and authorization headers
    methods: 'GET, PUT, POST, DELETE, OPTIONS', // Allowed HTTP methods
    allowedHeaders: 'Origin, X-Requested-With, Content-Type, Accept, CSRF-Token, X-CSRF-Token', // Allowed headers
    optionsSuccessStatus: 200 // For legacy browser compatibility with OPTIONS preflight
};

// Use the cors middleware with options
app.use(cors(corsOptions));

// Remove or comment out the old custom CORS middleware:
/*
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
*/

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
    
    // Skip CSRF injection/validation for API endpoints that need to be accessed cross-origin
    if (req.path === '/api/categories' || req.path === '/api/products' || 
        req.path.startsWith('/api/products/')) {
        console.log('Skipping CSRF injection/validation for:', req.path);
        next();
    } else {
        // For all other routes, apply CSRF protection (injection and origin validation)
        csrfProtection.injectToken(req, res, () => {
                validateOrigin(req, res, next);
        });
    }
});

// Apply CSRF validation for non-exempt routes
app.use((req, res, next) => {
    // For login and logout endpoints, already skipped in previous middleware
    if (req.path === '/api/login' || req.path === '/api/logout' || req.path === '/api/register') {
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
// <<< UNCOMMENT START >>>
const sanitizeInput = (req, res, next) => {
    if (req.body) {
        Object.keys(req.body).forEach(key => {
            // Only sanitize strings, leave other types (like numbers from JSON) alone
            if (typeof req.body[key] === 'string') {
                // console.log(`Sanitizing body[${key}]: ${req.body[key]}`); // Optional: Log before sanitizing
                req.body[key] = xss(req.body[key]);
                // console.log(`Sanitized body[${key}]: ${req.body[key]}`); // Optional: Log after sanitizing
            }
        });
    }
    if (req.query) {
        Object.keys(req.query).forEach(key => {
            if (typeof req.query[key] === 'string') {
                // console.log(`Sanitizing query[${key}]: ${req.query[key]}`);
                req.query[key] = xss(req.query[key]);
                // console.log(`Sanitized query[${key}]: ${req.query[key]}`);
            }
        });
    }
    if (req.params) {
        Object.keys(req.params).forEach(key => {
            if (typeof req.params[key] === 'string') {
                // console.log(`Sanitizing params[${key}]: ${req.params[key]}`);
                req.params[key] = xss(req.params[key]);
                // console.log(`Sanitized params[${key}]: ${req.params[key]}`);
            }
        });
    }
    next();
};

// Apply sanitization middleware to all routes
app.use(sanitizeInput);
// <<< UNCOMMENT END >>>

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

// =========================================================================
// == REGISTRATION API
// =========================================================================
console.log('[SERVER STARTUP] Defining POST /api/register route...'); // <<< ADD STARTUP LOG
app.post('/api/register', async (req, res) => {
    console.log('[API /api/register] Handler function entered.'); // <<< ADD HANDLER ENTRY LOG
    try {
        const { email, password } = req.body;
        console.log('[API /api/register] Registration attempt received for email:', email);

        // --- Basic Server-Side Validation ---
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required.' });
        }
        // Regex for basic email validation (adjust as needed)
        if (!/^\S+@\S+\.\S+$/.test(email)) { 
             return res.status(400).json({ error: 'Invalid email format.' });
        }
        if (password.length < 8) {
             return res.status(400).json({ error: 'Password must be at least 8 characters long.' });
        }
        // --- End Validation ---
        
        let connection;
        try {
            connection = await pool.getConnection();
            console.log('[API /api/register] DB connection obtained.');

            // Check if email already exists
            const [existingUsers] = await connection.query('SELECT userid FROM users WHERE email = ?', [email]);
            if (existingUsers.length > 0) {
                console.warn('[API /api/register] Registration failed: Email already exists -', email);
                return res.status(409).json({ error: 'Email address already registered.' }); // 409 Conflict
            }
            
            console.log('[API /api/register] Email is unique. Proceeding with hashing password...');
            // Hash the password
            const hashedPassword = await authUtils.hashPassword(password);
            console.log('[API /api/register] Password hashed.');

            // Insert the new user (default is_admin is FALSE)
            const [insertResult] = await connection.query(
                'INSERT INTO users (email, password, is_admin) VALUES (?, ?, FALSE)',
                [email, hashedPassword]
            );
            const newUserId = insertResult.insertId;
            console.log(`[API /api/register] New user inserted with ID: ${newUserId}`);

            // --- Automatically Log In User ---
            // Prepare session data for the new user
            const sessionData = {
                userId: newUserId,
                userEmail: email,
                is_admin: false, // New users are not admins
                isAuthenticated: true
            };

            // Rotate session to establish login state
            await rotateSession(req, sessionData); 
            console.log(`[API /api/register] Session rotated for new user ID: ${newUserId}`);

            // Explicitly save the session before sending the response
            req.session.save((saveErr) => {
                if (saveErr) {
                    console.error('[API /api/register] Error saving session after registration rotation:', saveErr);
                    // Proceed with success response but log the error
                    // The client might need to log in manually if session save failed badly
                    return res.status(201).json({ 
                        success: true, 
                        user: { email: email, isAdmin: false },
                        warning: 'Registration successful, but session might not be fully saved.'
                    }); 
                }
                
                console.log('[API /api/register] Session saved after rotation. Sending success response.');
                // Return success response AFTER session is saved
                return res.status(201).json({ // 201 Created status
                    success: true,
                    user: {
                        email: email,
                        isAdmin: false
                    }
                });
            });
            // --- End Auto Login ---

        } catch (dbError) {
             console.error('[API /api/register] Database error during registration:', dbError);
             return res.status(500).json({ error: 'Database error during registration.' });
        } finally {
             if (connection) {
                 console.log('[API /api/register] Releasing DB connection');
                 connection.release();
             }
        }
    } catch (error) {
        console.error('[API /api/register] General error:', error);
        return res.status(500).json({ error: 'Internal server error during registration.' });
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
// == ADMIN-ONLY ORDER VIEW API
// =========================================================================
app.get('/api/admin/orders', authUtils.authorizeAdmin, async (req, res) => {
    console.log('[API /api/admin/orders] Request received');
    let connection;
    try {
        connection = await pool.getConnection();
        console.log('[API /api/admin/orders] DB connection obtained');

        // Query to get all orders along with their items and product names
        // Order by most recent first
        const sql = `
            SELECT 
                o.order_id, o.user_email, o.total_amount, o.currency, o.status, 
                o.stripe_session_id, o.created_at AS order_date,
                oi.product_id, oi.quantity, oi.price_at_purchase,
                p.name AS product_name
            FROM orders o
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            LEFT JOIN products p ON oi.product_id = p.pid
            ORDER BY o.created_at DESC, o.order_id DESC, oi.product_id ASC;
        `;
        console.log('[API /api/admin/orders] Executing SQL query');
        const [rows] = await connection.query(sql);
        console.log(`[API /api/admin/orders] Query returned ${rows.length} rows`);

        // Process rows into a structured format: group items by order_id
        const ordersMap = new Map();
        rows.forEach(row => {
            if (!ordersMap.has(row.order_id)) {
                ordersMap.set(row.order_id, {
                    order_id: row.order_id,
                    user_email: row.user_email,
                    total_amount: parseFloat(row.total_amount).toFixed(2),
                    currency: row.currency,
                    status: row.status,
                    stripe_session_id: row.stripe_session_id,
                    order_date: row.order_date,
                    items: []
                });
            }
            // Add item details if they exist (LEFT JOIN might produce nulls for orders with no items)
            if (row.product_id) {
                ordersMap.get(row.order_id).items.push({
                    product_id: row.product_id,
                    product_name: row.product_name || 'N/A',
                    quantity: row.quantity,
                    price_at_purchase: parseFloat(row.price_at_purchase).toFixed(2)
                });
            }
        });

        // Convert map values to an array
        const orders = Array.from(ordersMap.values());
        console.log(`[API /api/admin/orders] Processed into ${orders.length} distinct orders`);

        res.json(orders);

    } catch (error) {
        console.error('[API /api/admin/orders] Error fetching orders:', error);
        res.status(500).json({ error: 'Failed to fetch orders.' });
    } finally {
        if (connection) {
            console.log('[API /api/admin/orders] Releasing DB connection');
            connection.release();
        }
    }
});

// =========================================================================
// == USER ORDER HISTORY API
// =========================================================================
// <<< ADD LOG BEFORE ROUTE DEFINITION >>>
app.use('/api/user/orders', (req, res, next) => {
    console.log(`[PRE-HANDLER LOG] Request hit /api/user/orders path. Method: ${req.method}`);
    next();
});
// <<< END PRE-HANDLER LOG >>>
app.get('/api/user/orders', authUtils.authenticate, async (req, res) => {
    const userId = req.session.userId; // Get user ID from session
    console.log(`[API /api/user/orders] Request received for user ID: ${userId}`);
    
    if (!userId) {
        // This shouldn't happen if authUtils.authenticate works, but check anyway
        return res.status(401).json({ error: 'User not properly authenticated.' });
    }

    let connection;
    try {
        connection = await pool.getConnection();
        console.log('[API /api/user/orders] DB connection obtained');

        // Query to get the last 5 orders for the specific user, along with items
        const sql = `
            SELECT 
                o.order_id, o.user_email, o.total_amount, o.currency, o.status, 
                o.stripe_session_id, o.created_at AS order_date,
                oi.product_id, oi.quantity, oi.price_at_purchase,
                p.name AS product_name
            FROM (
                -- Select the 5 most recent order IDs for the user
                SELECT order_id
                FROM orders
                WHERE user_id = ?
                ORDER BY created_at DESC
                LIMIT 5
            ) AS recent_orders
            JOIN orders o ON recent_orders.order_id = o.order_id
            LEFT JOIN order_items oi ON o.order_id = oi.order_id
            LEFT JOIN products p ON oi.product_id = p.pid
            ORDER BY o.created_at DESC, o.order_id DESC, oi.product_id ASC;
        `;
        console.log('[API /api/user/orders] Executing SQL query');
        const [rows] = await connection.query(sql, [userId]);
        console.log(`[API /api/user/orders] Query returned ${rows.length} rows for user ${userId}`);

        // Process rows into structured format (same logic as admin orders)
        const ordersMap = new Map();
        rows.forEach(row => {
            if (!ordersMap.has(row.order_id)) {
                ordersMap.set(row.order_id, {
                    order_id: row.order_id,
                    user_email: row.user_email,
                    total_amount: parseFloat(row.total_amount).toFixed(2),
                    currency: row.currency,
                    status: row.status,
                    stripe_session_id: row.stripe_session_id,
                    order_date: row.order_date,
                    items: []
                });
            }
            if (row.product_id) {
                ordersMap.get(row.order_id).items.push({
                    product_id: row.product_id,
                    product_name: row.product_name || 'N/A',
                    quantity: row.quantity,
                    price_at_purchase: parseFloat(row.price_at_purchase).toFixed(2)
                });
            }
        });

        const orders = Array.from(ordersMap.values());
        console.log(`[API /api/user/orders] Processed into ${orders.length} distinct orders for user ${userId}`);

        res.json(orders);

    } catch (error) {
        console.error(`[API /api/user/orders] Error fetching orders for user ${userId}:`, error);
        res.status(500).json({ error: 'Failed to fetch order history.' });
    } finally {
        if (connection) {
            console.log('[API /api/user/orders] Releasing DB connection');
            connection.release();
        }
    }
});

// =========================================================================
// == ORDER CREATION API (/api/create-checkout-session) - REPLACES /api/create-order
// =========================================================================
// Rename endpoint for clarity
app.post('/api/create-checkout-session', authUtils.authenticate, async (req, res) => {
    const userId = req.session.userId;
    const userEmail = req.session.userEmail;
    console.log(`[create-checkout] Starting session creation for user: ${userEmail} (ID: ${userId})`); // Log start

    // 1. Validate Incoming Data
    const cartItems = req.body.items;
    console.log('[create-checkout] Raw cart items received:', cartItems); // Log input
    if (!Array.isArray(cartItems) || cartItems.length === 0) {
        return res.status(400).json({ error: 'Invalid or empty cart data.' });
    }

    // Reuse existing validation logic
    const validatedItemsInput = cartItems.map(item => ({
        pid: parseInt(item.pid),
        quantity: parseInt(item.quantity)
    })).filter(item =>
        !isNaN(item.pid) && item.pid > 0 &&
        !isNaN(item.quantity) && item.quantity > 0 && item.quantity <= 100
    );

    if (validatedItemsInput.length !== cartItems.length) {
        console.warn('[create-checkout] Some cart items failed basic validation:', cartItems, validatedItemsInput);
        return res.status(400).json({ error: 'Invalid item data in cart (PID or quantity).' });
    }

    const pids = validatedItemsInput.map(item => item.pid);
    console.log('[create-checkout] Validated PIDs:', pids); // Log validated PIDs
    if (pids.length === 0) {
         return res.status(400).json({ error: 'No valid items found in cart.' });
    }

    let connection;
    try {
        console.log('[create-checkout] Attempting to get DB connection...');
        connection = await pool.getConnection();
        console.log('[create-checkout] DB connection obtained. Starting transaction...');
        await connection.beginTransaction();
        console.log('[create-checkout] Transaction started.');

        // 2. Fetch Product Details & Calculate Total from DB (Same as before)
        const placeholders = pids.map(() => '?').join(',');
        const sql = `SELECT pid, name, price, description, thumbnail FROM products WHERE pid IN (${placeholders})`; // Fetch more details for Stripe
        console.log('[create-checkout] Fetching product details with SQL:', sql, pids);
        const [productsFromDb] = await connection.query(sql, pids);
        console.log('[create-checkout] Products fetched from DB:', productsFromDb);

        if (productsFromDb.length !== pids.length) {
             console.error('[create-checkout] DB Fetch Error: Not all product IDs found. Rolling back.', pids, productsFromDb);
             await connection.rollback();
             return res.status(404).json({ error: 'One or more products not found.' });
        }

        let totalAmount = 0;
        const finalOrderItems = [];
        const productMap = new Map(productsFromDb.map(p => [p.pid, p]));

        console.log('[create-checkout] Calculating total and preparing final items...');
        for (const inputItem of validatedItemsInput) {
            const product = productMap.get(inputItem.pid);
            if (!product) {
                 console.error('[create-checkout] Consistency Error: Product missing from map', inputItem.pid);
                 await connection.rollback();
                 return res.status(500).json({ error: 'Internal server error during price validation.' });
            }
            const priceFromDb = parseFloat(product.price);
            const itemTotal = priceFromDb * inputItem.quantity;
            totalAmount += itemTotal;

            finalOrderItems.push({
                pid: inputItem.pid,
                quantity: inputItem.quantity,
                name: product.name, // Needed for Stripe line item
                description: product.description, // Optional for Stripe
                thumbnail: product.thumbnail, // Optional for Stripe
                price_at_purchase: priceFromDb
            });
        }
        // Ensure total amount has max 2 decimal places
        totalAmount = parseFloat(totalAmount.toFixed(2));
        console.log('[create-checkout] Total calculated:', totalAmount, 'Final items:', finalOrderItems);

        // 3. Store Order in DB (NO salt/digest anymore)
        const currency = 'hkd'; // Ensure lowercase for Stripe API consistency
        const orderSql = 'INSERT INTO orders (user_id, user_email, total_amount, currency, status) VALUES (?, ?, ?, ?, ?)';
        // Use uppercase currency for DB consistency if preferred
        const orderParams = [userId, userEmail, totalAmount, currency.toUpperCase(), 'PENDING'];
        console.log('[create-checkout] Inserting into orders table:', orderSql, orderParams);
        const [orderResult] = await connection.query(orderSql, orderParams);
        const orderId = orderResult.insertId;
        console.log('[create-checkout] Order inserted successfully. Order ID:', orderId);

        // Insert items into order_items (Same as before)
        console.log('[create-checkout] Inserting order items...');
        const itemInsertPromises = finalOrderItems.map(item => {
            const itemSql = 'INSERT INTO order_items (order_id, product_id, quantity, price_at_purchase) VALUES (?, ?, ?, ?)';
            const itemParams = [orderId, item.pid, item.quantity, item.price_at_purchase.toFixed(2)];
            return connection.query(itemSql, itemParams);
        });
        await Promise.all(itemInsertPromises);
        console.log('[create-checkout] Order items inserted successfully.');

        // 4. Create Stripe Checkout Session
        console.log('[create-checkout] Creating Stripe Checkout Session...');
        // Construct line items for Stripe
        const line_items = finalOrderItems.map(item => {
             // Construct the image URL - *adjust path if needed*
            const imageUrl = item.thumbnail
                ? `${req.protocol}://${req.get('host')}/uploads/${item.thumbnail}`
                : undefined; // Or provide a default placeholder image URL

             return {
                 price_data: {
                    currency: currency, // Use lowercase currency for Stripe API
                    product_data: {
                        name: item.name,
                         // Add description and images if available
                        description: item.description || undefined,
                        images: imageUrl ? [imageUrl] : undefined,
                    },
                    unit_amount: Math.round(item.price_at_purchase * 100), // Price in cents!
                },
                quantity: item.quantity,
            };
        });

        // Define Success and Cancel URLs (using environment variables is better)
        const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
        const successUrl = `${baseUrl}/checkout-success.html?session_id={CHECKOUT_SESSION_ID}`;
        const cancelUrl = `${baseUrl}/checkout-cancel.html`;

        console.log('[create-checkout] Line Items for Stripe:', JSON.stringify(line_items, null, 2));
        console.log(`[create-checkout] Success URL: ${successUrl}`);
        console.log(`[create-checkout] Cancel URL: ${cancelUrl}`);

        const session = await stripe.checkout.sessions.create({
            payment_method_types: ['card'], // Add other methods like 'alipay', 'wechat_pay' if needed
            line_items: line_items,
            mode: 'payment',
            success_url: successUrl,
            cancel_url: cancelUrl,
            client_reference_id: orderId.toString(), // Link Stripe session to your order ID
            customer_email: userEmail || undefined, // Prefill email if available
            metadata: {
                // Store your internal order ID! Crucial for webhook fulfillment.
                orderId: orderId.toString()
                // Add any other relevant metadata (e.g., userId)
            }
            // billing_address_collection: 'required', // Uncomment to require billing address on Stripe page
            // shipping_address_collection: { // Example for shipping
            //    allowed_countries: ['US', 'CA', 'HK'], // Restrict countries if needed
            // },
        });

        console.log(`[create-checkout] Stripe Session created: ${session.id}`);

        // 5. Update Order with Stripe Session ID (Optional but Recommended)
        await connection.query('UPDATE orders SET stripe_session_id = ? WHERE order_id = ?', [session.id, orderId]);
        console.log(`[create-checkout] Order ${orderId} updated with Stripe session ID.`);

        // 6. Commit Transaction
        console.log('[create-checkout] Committing transaction...');
        await connection.commit();
        console.log('[create-checkout] Transaction committed.');

        // 7. Return Session ID to Client
        console.log('[create-checkout] Sending session ID to client:', { sessionId: session.id });
        res.json({ sessionId: session.id }); // Send only the session ID

    } catch (error) {
        // Log the specific error that occurred *before* rollback
        console.error('[create-checkout] Error occurred:', error);
        if (connection) {
            console.log('[create-checkout] Rolling back transaction due to error.');
            await connection.rollback();
            console.log('[create-checkout] Transaction rolled back.');
        }
        // Send a generic error message to the client
        res.status(500).json({ error: 'Failed to create checkout session due to a server error.' });
    } finally {
        if (connection) {
            console.log('[create-checkout] Releasing DB connection.');
            connection.release();
        }
    }
});

// <<< ADD EXPLICIT ROUTE FOR HOMEPAGE >>>
app.get('/', (req, res) => {
    // Ensure index.html exists in the root directory
    res.sendFile(path.join(__dirname, 'index.html'), (err) => {
        if (err) {
            console.error(`Error sending index.html: ${err.message}`);
            // If index.html can't be sent for some reason, fall back to a generic error or 404
            res.status(500).send('Error loading homepage.');
        }
    });
});
// <<< END HOMEPAGE ROUTE >>>

// <<< ADD EXPLICIT ROUTE FOR REGISTER PAGE >>>
app.get('/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'), (err) => {
        if (err) {
            console.error(`Error sending register.html: ${err.message}`);
            res.status(500).send('Error loading registration page.');
        }
    });
});
// <<< END REGISTER PAGE ROUTE >>>

// <<< ADD EXPLICIT ROUTE FOR /index.html PAGE >>>
app.get('/index.html', (req, res) => {
    // Serve the same index.html file as the root route
    res.sendFile(path.join(__dirname, 'index.html'), (err) => {
        if (err) {
            console.error(`Error sending index.html (explicit path): ${err.message}`);
            res.status(500).send('Error loading homepage.');
        }
    });
});
// <<< END /index.html PAGE ROUTE >>>

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



