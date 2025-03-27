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
const bcrypt = require('bcryptjs'); // Changed from bcrypt to bcryptjs

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
                    is_admin BOOLEAN DEFAULT FALSE,
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
    
    // Authentication middleware
    authenticate(req, res, next) {
        if (authUtils.isAuthenticated(req)) {
            next();
        } else {
            // Redirect to login page for HTML requests
            if (req.accepts('html')) {
                return res.redirect('/login.html');
            }
            res.status(401).json({ error: 'Authentication required' });
        }
    },
    
    // Admin authorization middleware
    authorizeAdmin(req, res, next) {
        if (authUtils.isAuthenticated(req) && authUtils.isAdmin(req)) {
            next();
        } else {
            // Redirect to login page for HTML requests
            if (req.accepts('html')) {
                return res.redirect('/login.html');
            }
            res.status(403).json({ error: 'Admin privileges required' });
        }
    }
};

// Session configuration
app.use(session({
    secret: crypto.randomBytes(32).toString('hex'),
    resave: false,
    saveUninitialized: false, // Don't create session until something stored
    name: 'neon_session', // Custom cookie name
    cookie: {
        secure: true, // Always use secure cookies
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

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(__dirname)); // Serve files from the root directory
app.use(express.static('public'));  // Serve files from the public directory
app.use('/uploads', express.static('uploads'));
app.use('/js', express.static('public/js'));

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

// Function to rotate session after successful login
const rotateSession = (req, originalData) => {
    return new Promise((resolve, reject) => {
        // Save the important session data before regeneration
        const userData = {
            userId: originalData.userId || null,
            userEmail: originalData.userEmail || null,
            is_admin: originalData.is_admin || false,
            isAuthenticated: originalData.isAuthenticated || false
        };
        
        // Generate new session ID
        const oldSessionId = req.session.id;
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
            
            console.log(`Session rotated: ${oldSessionId} → ${req.session.id}`);
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
    const nonce = crypto.randomBytes(16).toString('base64');
    
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
        console.log('Login attempt received:', req.body.email);
        const { email, password } = req.body;
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
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
            
            // Return success response
            return res.status(200).json({ 
                success: true,
                user: {
                    email: user.email,
                    isAdmin: sessionData.is_admin
                }
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

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
}).on('error', (err) => {
    console.error('Server failed to start:', err);
}); 
