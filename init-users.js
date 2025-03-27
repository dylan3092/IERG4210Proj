/**
 * This script initializes the users table with an admin and a regular user
 * Passwords are properly salted and hashed before storage
 */
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

// Database connection configuration
const dbConfig = {
    host: 'localhost',
    user: 'root',
    password: 'P@ssWord1', // Make sure this matches your MySQL password
    database: 'shopping_db',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
};

// Initial users to be added
const initialUsers = [
    {
        email: 'admin@example.com',
        password: 'Admin@123',  // Strong password for admin
        admin: true
    },
    {
        email: 'user@example.com',
        password: 'User@123',   // Strong password for regular user
        admin: false
    }
];

// Number of salt rounds for bcrypt (higher is more secure but slower)
const SALT_ROUNDS = 12;

// Function to hash a password
async function hashPassword(password) {
    try {
        const salt = await bcrypt.genSalt(SALT_ROUNDS);
        const hash = await bcrypt.hash(password, salt);
        return hash;
    } catch (error) {
        console.error('Error hashing password:', error);
        throw error;
    }
}

// Function to add a user with a hashed password
async function addUser(connection, user) {
    try {
        const hashedPassword = await hashPassword(user.password);
        
        // Check if the user already exists
        const [existingUsers] = await connection.query(
            'SELECT * FROM users WHERE email = ?',
            [user.email]
        );
        
        if (existingUsers.length > 0) {
            console.log(`User with email ${user.email} already exists. Skipping.`);
            return;
        }
        
        // Insert the new user
        const [result] = await connection.query(
            'INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)',
            [user.email, hashedPassword, user.admin]
        );
        
        console.log(`User ${user.email} added successfully with ID: ${result.insertId}`);
    } catch (error) {
        console.error(`Error adding user ${user.email}:`, error);
        throw error;
    }
}

// Main function to initialize users
async function initializeUsers() {
    let connection;
    
    try {
        // Create a connection to the database
        connection = await mysql.createConnection(dbConfig);
        
        console.log('Connected to database successfully');
        
        // Create the users table if it doesn't exist
        await connection.query(`
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
        
        // Add each initial user
        for (const user of initialUsers) {
            await addUser(connection, user);
        }
        
        console.log('All users have been initialized');
    } catch (error) {
        console.error('Error initializing users:', error);
    } finally {
        if (connection) {
            await connection.end();
            console.log('Database connection closed');
        }
    }
}

// Run the initialization
initializeUsers(); 