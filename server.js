const express = require('express');
const mysql = require('mysql2/promise');
const multer = require('multer');
const path = require('path');
const fs = require('fs/promises');

const app = express();

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
    password: 'P@ssWord1',
    database: 'shopping_db'
});

// Multer configuration for file uploads
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
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

// Test database connection
pool.getConnection()
    .then(connection => {
        console.log('Database connected successfully');
        connection.release();
    })
    .catch(err => {
        console.error('Error connecting to the database:', err);
    });

// Categories API
app.get('/api/categories', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM categories');
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
        let query = `
            SELECT p.*, c.name as category_name 
            FROM products p 
            JOIN categories c ON p.catid = c.catid
        `;
        
        // Add category filter if provided
        const categoryId = req.query.category;
        if (categoryId) {
            query += ' WHERE p.catid = ?';
            const [rows] = await pool.query(query, [categoryId]);
            res.json(rows);
        } else {
            const [rows] = await pool.query(query);
            res.json(rows);
        }
    } catch (error) {
        console.error('Error fetching products:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/products/:id', async (req, res) => {
    try {
        const [rows] = await pool.query('SELECT * FROM products WHERE pid = ?', [req.params.id]);
        if (rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        res.json(rows[0]);
    } catch (error) {
        console.error('Error fetching product:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/products', upload.single('image'), async (req, res) => {
    try {
        console.log('Received product data:', req.body); // Debug log
        console.log('Received file:', req.file); // Debug log

        const { catid, name, price, description } = req.body;
        const image = req.file ? req.file.filename : null;

        // Validate required fields
        if (!catid || !name || !price) {
            return res.status(400).json({ error: 'Category, name, and price are required' });
        }

        const [result] = await pool.query(
            'INSERT INTO products (catid, name, price, description, image) VALUES (?, ?, ?, ?, ?)',
            [catid, name, price, description || null, image]
        );

        res.json({
            pid: result.insertId,
            catid,
            name,
            price,
            description,
            image
        });
    } catch (error) {
        console.error('Error creating product:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/products/:id', upload.single('image'), async (req, res) => {
    try {
        const { catid, name, price, description } = req.body;
        const image = req.file ? req.file.filename : null;

        // If new image uploaded, delete old image
        if (image) {
            const [oldProduct] = await pool.query('SELECT image FROM products WHERE pid = ?', [req.params.id]);
            if (oldProduct[0].image) {
                await fs.unlink(path.join('./uploads', oldProduct[0].image)).catch(() => {});
            }
        }

        const updateQuery = image
            ? 'UPDATE products SET catid = ?, name = ?, price = ?, description = ?, image = ? WHERE pid = ?'
            : 'UPDATE products SET catid = ?, name = ?, price = ?, description = ? WHERE pid = ?';
        
        const updateParams = image
            ? [catid, name, price, description, image, req.params.id]
            : [catid, name, price, description, req.params.id];

        await pool.query(updateQuery, updateParams);
        
        res.json({
            id: req.params.id,
            catid,
            name,
            price,
            description,
            image: image || oldProduct[0].image
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