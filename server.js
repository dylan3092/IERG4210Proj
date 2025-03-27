const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');
const sharp = require('sharp');
const xss = require('xss');
const crypto = require('crypto');

const app = express();

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
    .then(connection => {
        console.log('Successfully connected to MySQL database');
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