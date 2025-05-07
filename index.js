const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(express.json());

// Hardcode PostgreSQL connection
const pool = new Pool({
  connectionString: 'postgresql://postgres:IfBEKvLYTwpTlNfcjMFmJUBsmKHlRJXM@trolley.proxy.rlwy.net:54009/railway', // Replace with your actual PostgreSQL connection string
  ssl: {
    rejectUnauthorized: false,
  },
});

// Hardcode environment variables
const jwtSecret = 'Redouane*_boundra*_19031965'; // Replace with your JWT secret key
const port = process.env.PORT || 3000; // Default to port 3000 if not set

// Root endpoint
app.get('/', (req, res) => {
  res.send('Hello, welcome to the private user site!');
});

// Registration endpoint
app.post('/register', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    // Hash the password before saving it
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into database
    const query = 'INSERT INTO users (email, password) VALUES ($1, $2)';
    await pool.query(query, [email, hashedPassword]);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  // Validate input
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required' });
  }

  try {
    // Check if the user exists in the database
    const query = 'SELECT * FROM users WHERE email = $1';
    const result = await pool.query(query, [email]);

    // If user not found, return error
    if (result.rows.length === 0) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // Compare password with stored hash
    const isMatch = await bcrypt.compare(password, user.password);

    // If password doesn't match, return error
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: user.id }, jwtSecret, { expiresIn: '1h' });

    res.json({ message: 'Login successful', token });
  } catch (error) {
    console.error('Error logging in user:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Protected route (requires authentication)
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is protected content', userId: req.userId });
});

// Middleware to authenticate JWT token
function authenticateToken(req, res, next) {
  // Get token from Authorization header
  const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];

  // If no token is provided, return an error
  if (!token) {
    return res.status(403).json({ message: 'Access denied' });
  }

  // Verify the token
  jwt
