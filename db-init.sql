-- Create the users table if it doesn't exist
CREATE TABLE IF NOT EXISTS users (
    userid INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL, -- Will store hashed password
    admin BOOLEAN DEFAULT FALSE,     -- Flag to distinguish admin from normal users
    createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Add an index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email); 