const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Client } = require('pg');
require('dotenv').config();

const app = express();

app.use(express.json());

const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false,
    },
});

client.connect()
    .then(() => console.log('Connected to PostgreSQL'))
    .catch(err => console.error('Failed to connect to the database', err));

const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];

    if (!token) {
        return res.status(403).send('Access denied');
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('Invalid token');
        }
        req.user = user;
        next();
    });
};

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const query = 'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id';
    const values = [username, email, hashedPassword];

    try {
        const result = await client.query(query, values);
        res.status(201).send({ userId: result.rows[0].id });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error creating user');
    }
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    const query = 'SELECT * FROM users WHERE email = $1';
    try {
        const result = await client.query(query, [email]);

        if (result.rows.length === 0) {
            return res.status(400).send('User not found');
        }

        const user = result.rows[0];

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(400).send('Invalid password');
        }

        const token = jwt.sign({ userId: user.id, username: user.username }, process.env.JWT_SECRET, {
            expiresIn: '1h', 
        });

        res.status(200).send({ token });
    } catch (err) {
        console.error(err);
        res.status(500).send('Error logging in');
    }
});

app.get('/profile', authenticateJWT, (req, res) => {
    res.status(200).send(`Welcome, ${req.user.username}!`);
});

const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
