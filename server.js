const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const sharp = require('sharp');
const xss = require('xss');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');
const session = require('express-session');
const bcrypt = require('bcrypt'); // For password hashing

const app = express();

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
                    admin BOOLEAN DEFAULT FALSE,
                    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                )
            `);
            
            console.log('Users table created or already exists');
            
            // Define initial users
            const initialUsers = [
                {
                    email: 'admin@example.com',
                    password: 'Admin@123',
                    admin: true
                },
                {
                    email: 'user@example.com',
                    password: 'User@123',
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
                    await pool.query(
                        'INSERT INTO users (email, password, admin) VALUES (?, ?, ?)',
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
        return req.session && req.session.userId && req.session.isAuthenticated;
    },
    
    // Check if a user is an admin
    isAdmin(req) {
        return req.session && req.session.isAdmin === true;
    },
    
    // Authentication middleware
    authenticate(req, res, next) {
        if (authUtils.isAuthenticated(req)) {
            next();
        } else {
            res.status(401).json({ error: 'Authentication required' });
        }
    },
    
    // Admin authorization middleware
    authorizeAdmin(req, res, next) {
        if (authUtils.isAuthenticated(req) && authUtils.isAdmin(req)) {
            next();
        } else {
            res.status(403).json({ error: 'Admin privileges required' });
        }
    }
};

// Session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'strict', // Helps prevent CSRF - additional protection
        maxAge: 3 * 24 * 60 * 60 * 1000 // 3 days as per requirements
    }
}));

// CSRF Protection Middleware
const csrfProtection = {
    // Generate a CSRF token based on session ID and a secret
    generateToken: (req) => {
        if (!req.session) {
            throw new Error('Session middleware required');
        }
        
        const sessionId = req.session.id;
        // Create a HMAC using the session ID and a secret key
        const hmac = crypto.createHmac('sha256', process.env.CSRF_SECRET || 'csrf-secret-key');
        hmac.update(sessionId);
        return hmac.digest('hex');
    },
    
    // Verify that the token is valid
    verifyToken: (req, token) => {
        if (!token) return false;
        const expectedToken = csrfProtection.generateToken(req);
        // Use timing-safe comparison to prevent timing attacks
        return crypto.timingSafeEqual(
            Buffer.from(token),
            Buffer.from(expectedToken)
        );
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

// Apply cookie parser middleware
app.use(cookieParser());

// Add CSRF protection to all requests
app.use(csrfProtection.injectToken);
app.use(validateOrigin);

// Apply CSRF validation middleware to all routes that accept data
app.use(csrfProtection.verifyRequest);

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
const pool = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: 'P@ssWord1', // Make sure this matches your MySQL password
    database: 'shopping_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});

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

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));
app.use('/js', express.static('public/js'));  // Ensure public/js directory is properly served

// Add this near the top, after creating the app
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');  // Or specific domain
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type');
    
    // Generate a random nonce for this request
    const nonce = crypto.randomBytes(16).toString('base64');
    
    // Add Content Security Policy header
    // This is a strict policy that helps prevent XSS attacks
    const cspDirectives = [
        // Default fallback - deny by default
        "default-src 'self'",
        // Scripts can be loaded from same origin and allow our external CDN
        // Also allow inline scripts with the generated nonce and unsafe-inline as a fallback
        `script-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000 'nonce-${nonce}' 'unsafe-eval' 'unsafe-inline'`,
        // Styles can be loaded from same origin and allow our external CDN and inline styles
        "style-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000 'unsafe-inline'",
        // Images can be loaded from same origin and data URIs
        "img-src 'self' data: http://s15.ierg4210.ie.cuhk.edu.hk:3000",
        // Forms can only submit to same origin
        "form-action 'self'",
        // Frames can only load from same origin
        "frame-src 'self'",
        // Connect to only same origin
        "connect-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000",
        // Font sources
        "font-src 'self' http://s15.ierg4210.ie.cuhk.edu.hk:3000",
        // Media sources
        "media-src 'self'",
        // Object sources (plugins, etc)
        "object-src 'none'",
        // Base URI restriction to prevent base tag hijacking
        "base-uri 'self'",
        // Upgrade insecure requests
        "upgrade-insecure-requests",
        // Report violations to this endpoint
        "report-to csp-endpoint"
    ];
    
    // Set CSP header - use report-only first to test before enforcing
    // Comment this line and uncomment the next one when you're ready to enforce
    res.header('Content-Security-Policy-Report-Only', cspDirectives.join('; '));
    // res.header('Content-Security-Policy', cspDirectives.join('; '));
    
    // Set up CSP reporting
    res.header('Reporting-Endpoints', 'csp-endpoint="/api/csp-report"');
    
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
        console.log('Categories fetched:', rows);
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

app.post('/api/categories', async (req, res) => {
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

app.put('/api/categories/:id', async (req, res) => {
    try {
        const { name } = req.body;
        await pool.query('UPDATE categories SET name = ? WHERE catid = ?', [name, req.params.id]);
        res.json({ id: req.params.id, name });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/categories/:id', async (req, res) => {
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
    await fs.unlink(originalPath);

    return {
        full: `${baseFilename}_full${ext}`,
        thumbnail: thumbnailFilename
    };
}

app.post('/api/products', upload.single('image'), async (req, res) => {
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

app.put('/api/products/:id', upload.single('image'), async (req, res) => {
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
                await fs.unlink(path.join('./uploads', oldProduct[0].image))
                    .catch(() => {});
            }
            if (oldProduct[0].thumbnail) {
                await fs.unlink(path.join('./uploads', oldProduct[0].thumbnail))
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

app.delete('/api/products/:id', async (req, res) => {
    try {
        // Delete associated image
        const [oldProduct] = await pool.query('SELECT image FROM products WHERE pid = ?', [req.params.id]);
        if (oldProduct[0].image) {
            await fs.unlink(path.join('./uploads', oldProduct[0].image)).catch(() => {});
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

// Add a simple login route with CSRF protection
app.get('/api/login-form', (req, res) => {
    // Generate a login-specific nonce for this request
    const loginNonce = crypto.randomBytes(16).toString('base64');
    
    // Store the nonce in session for validation
    req.session.loginNonce = loginNonce;
    
    // Return the login form
    res.send(`
        <form method="POST" action="/api/login">
            <h2>Admin Login</h2>
            <div>
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div>
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <!-- CSRF Protection -->
            <input type="hidden" name="_csrf" value="${res.locals.csrfToken}">
            
            <!-- Double CSRF protection for login - prevents login CSRF -->
            <input type="hidden" name="loginNonce" value="${loginNonce}">
            
            <button type="submit">Login</button>
        </form>
    `);
});

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const db = await getDB();
        const user = await db.get('SELECT * FROM users WHERE email = ?', [email]);
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate a session ID and save it
        const sessionId = crypto.randomBytes(64).toString('hex');
        const now = new Date().getTime();
        const expiresAt = now + (24 * 60 * 60 * 1000); // 24 hours

        await db.run(
            'INSERT INTO sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)',
            [sessionId, user.userid, expiresAt]
        );

        // Set the session cookie
        res.cookie('sessionId', sessionId, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000, // 24 hours
            sameSite: 'strict'
        });

        // Store user data in session for use in the client
        req.session.userId = user.userid;
        req.session.userEmail = user.email;
        req.session.isAdmin = user.is_admin === 1;
        
        return res.status(200).json({ 
            success: true,
            user: {
                email: user.email,
                isAdmin: user.is_admin === 1
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout endpoint
app.post('/api/logout', async (req, res) => {
    try {
        const sessionId = req.cookies.sessionId;
        
        if (sessionId) {
            const db = await getDB();
            
            // Delete the session from the database
            await db.run('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
            
            // Clear the session cookie
            res.clearCookie('sessionId');
            
            // Clear session data
            req.session.destroy();
        }
        
        res.status(200).json({ success: true });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Change password endpoint
app.post('/api/change-password', async (req, res) => {
    try {
        const sessionId = req.cookies.sessionId;
        if (!sessionId) {
            return res.status(401).json({ error: 'Not authenticated' });
        }
        
        const db = await getDB();
        const session = await db.get('SELECT * FROM sessions WHERE session_id = ?', [sessionId]);
        
        if (!session) {
            return res.status(401).json({ error: 'Invalid session' });
        }
        
        // Check if session is expired
        const now = new Date().getTime();
        if (now > session.expires_at) {
            await db.run('DELETE FROM sessions WHERE session_id = ?', [sessionId]);
            return res.status(401).json({ error: 'Session expired' });
        }
        
        const { currentPassword, newPassword } = req.body;
        if (!currentPassword || !newPassword) {
            return res.status(400).json({ error: 'Current password and new password are required' });
        }
        
        // Get user from database
        const user = await db.get('SELECT * FROM users WHERE userid = ?', [session.user_id]);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
        
        // Verify current password
        const match = await bcrypt.compare(currentPassword, user.password);
        if (!match) {
            return res.status(401).json({ error: 'Current password is incorrect' });
        }
        
        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);
        
        // Update password in database
        await db.run('UPDATE users SET password = ? WHERE userid = ?', [hashedPassword, user.userid]);
        
        return res.status(200).json({ success: true });
    } catch (error) {
        console.error('Change password error:', error);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: err.message });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}).on('error', (err) => {
    console.error('Server failed to start:', err);
}); 