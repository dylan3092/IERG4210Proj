const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
require('dotenv').config();

// Database configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'ierg4210',
};

// Admin user to create
const adminUser = {
  email: 'admin@example.com',
  password: 'Admin123!',
  is_admin: 1
};

// Create admin user
async function createAdminUser() {
  let connection;
  
  try {
    // Connect to database
    connection = await mysql.createConnection(dbConfig);
    console.log('Connected to database successfully');
    
    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(adminUser.password, salt);
    
    // Check if user already exists
    const [rows] = await connection.execute(
      'SELECT * FROM users WHERE email = ?',
      [adminUser.email]
    );
    
    if (rows.length > 0) {
      console.log(`User ${adminUser.email} already exists`);
      return;
    }
    
    // Insert the admin user
    const result = await connection.execute(
      'INSERT INTO users (email, password, is_admin) VALUES (?, ?, ?)',
      [adminUser.email, hashedPassword, adminUser.is_admin]
    );
    
    console.log(`Admin user ${adminUser.email} created successfully`);
    console.log('Default password: Admin123!');
    console.log('Please change this password after first login');
    
  } catch (error) {
    console.error('Error creating admin user:', error);
  } finally {
    if (connection) {
      await connection.end();
      console.log('Database connection closed');
    }
  }
}

// Run the function
createAdminUser(); 