
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());


const pool = new Pool({
  user: 'Redouane',
  host: 'localhost',
  database: 'blacktiger',
  password: 'redouane_01',
  port: 5432,
});


const JWT_SECRET = 'Redouane*_boundra*_19031965';

app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    
    const hashedPassword = await bcrypt.hash(password, 10);

    
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING id',
      [email, hashedPassword]
    );

   
    res.status(201).json({ message: 'User created', userId: result.rows[0].id });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error creating user' });
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    
    const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '1h' });

    
    res.json({ token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error logging in' });
  }
});


const jwtMiddleware = (req, res, next) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(403).send('Token is required');
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).send('Invalid token');
    }
    req.user = decoded; 
    next(); 
  });
};


app.get('/protected', jwtMiddleware, (req, res) => {
  res.json({ message: 'You are authorized to view this content' });
});

app.get("/", (req, res) => {
  res.send("Server is working! Welcome to the homepage.");
});


const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
