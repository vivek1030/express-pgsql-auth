const express = require('express');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { check, validationResult } = require('express-validator');
const dotenv = require('dotenv');
const cors = require('cors');

dotenv.config();

const app = express();

app.use(bodyParser.json());

// Configure CORS with allowed origins
// const allowedOrigins = ['https://yourdomain.com', 'http://localhost:3000']; // Add your allowed origins here
// app.use(cors({
//     origin: function (origin, callback) {
//         if (allowedOrigins.includes(origin)) {
//             callback(null, true);
//         } else {
//             callback(new Error('Not allowed by CORS'));
//         }
//     }
// }));

// CREATE TABLE users (
//     id SERIAL PRIMARY KEY,
//     username VARCHAR(50) NOT NULL UNIQUE,
//     email VARCHAR(100) NOT NULL UNIQUE,
//     password VARCHAR(100) NOT NULL
// );

const { Pool } = require('pg');
const pool = new Pool({
    connectionString: `postgresql://${process.env.DB_USER}:${process.env.DB_PASSWORD}@${process.env.DB_HOST}/db1`,
});

// Validation middleware for user registration
const validateUserRegistration = [
    check('username').not().isEmpty().withMessage('Username is required'),
    check('email').isEmail().withMessage('Invalid email'),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

// Validation middleware for user login
const validateUserLogin = [
    check('email').isEmail().withMessage('Invalid email'),
    check('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
];

app.post('/register', validateUserRegistration, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    try {
        await pool.query('INSERT INTO users (username, email, password) VALUES ($1, $2, $3)',
            [req.body.username, req.body.email, hashedPassword]);
        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.post('/login', validateUserLogin, async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    try {
        const user = await pool.query('SELECT * FROM users WHERE email = $1', [req.body.email]);
        if (user.rows.length === 0 || !await bcrypt.compare(req.body.password, user.rows[0].password)) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Create a JWT token
        const token = jwt.sign({ id: user.rows[0].id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

function validateJwt(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Invalid token format' });
    }

    const token = authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ message: 'Authorization token missing' });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = { id: decoded.id };
        next();
    });
}

app.get('/userinfo', validateJwt, async (req, res) => {
    try {
        const user = await pool.query('SELECT id, username, email FROM users WHERE id = $1', [req.user.id]);
        if (user.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ user: user.rows[0] });
    } catch (error) {
        res.status(500).json({ message: 'Internal server error' });
    }
});

app.use((req, res) => {
    res.status(404).json({ message: 'Not Found' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server started on port ${PORT}`);
});
