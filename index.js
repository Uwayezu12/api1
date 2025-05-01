require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// PostgreSQL connection
const pool = new Pool({
  host: process.env.PGHOST,
  user: process.env.PGUSER,
  password: process.env.PGPASSWORD,
  database: process.env.PGDATABASE,
  port: process.env.PGPORT,
});

// JWT Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Signup
app.post('/api/signup', async (req, res) => {
  const { username, email, password } = req.body;

  // Validate input
  if (!username || !email || !password) {
    return res.status(400).json({ error: 'Username, email, and password are required' });
  }

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert the user into the database
    await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3)',
      [username, email, hashedPassword]
    );

    // Respond with success
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    // Handle unique constraint violation (e.g., duplicate username or email)
    if (err.code === '23505') {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Handle other errors
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    // Query the database for the user by username
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    // Check if the user exists
    if (!user) return res.status(400).json({ error: 'User not found' });

    // Compare the provided password with the stored password hash
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    // Generate a JWT token
    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '10h' });

    // Respond with the token
    res.json({ token });
  } catch (err) {
    // Handle any errors
    res.status(500).json({ error: err.message });
  }
});

// ========== SECURED PRODUCT API ========== //

app.post('/api/products', authenticateToken, async (req, res) => {
  const { productName, description, quantity, price } = req.body;
  try {
    const result = await pool.query(
      'INSERT INTO products (productname, description, quantity, price) VALUES ($1, $2, $3, $4) RETURNING *',
      [productName, description, quantity, price]
    );
    res.json(result.rows[0]);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.get('/api/products', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products ORDER BY productid');
    res.json(result.rows);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.get('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM products WHERE productid = $1', [req.params.id]);
    result.rows.length ? res.json(result.rows[0]) : res.status(404).send('Product not found');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.put('/api/products/:id', authenticateToken, async (req, res) => {
  const { productName, description, quantity, price } = req.body;
  try {
    const result = await pool.query(
      'UPDATE products SET productname = $1, description = $2, quantity = $3, price = $4 WHERE productid = $5 RETURNING *',
      [productName, description, quantity, price, req.params.id]
    );
    result.rowCount ? res.json(result.rows[0]) : res.status(404).send('Product not found');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.patch('/api/products/:id', authenticateToken, async (req, res) => {
  const { quantity } = req.body;
  try {
    const result = await pool.query(
      'UPDATE products SET quantity = $1 WHERE productid = $2 RETURNING quantity',
      [quantity, req.params.id]
    );
    result.rowCount ? res.json(result.rows[0]) : res.status(404).send('Product not found');
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.delete('/api/products/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query('DELETE FROM products WHERE productid = $1', [req.params.id]);
    result.rowCount ? res.status(200).json({ message: 'Product deleted successfully' }) : res.status(404).json({ error: 'Product not found' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
