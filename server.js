// 1️⃣ Import dependencies
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// 2️⃣ Initialize express app
const app = express();
app.use(express.json());

// 3️⃣ Initialize the database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// 4️⃣ Admin Registration endpoint
app.post('/admin/register', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required.' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      'INSERT INTO users (email, password, role) VALUES ($1, $2, $3) RETURNING *',
      [email, hashedPassword, 'ADMIN']
    );
    res.status(201).json({ message: 'Admin created successfully', admin: result.rows[0] });
  } catch (err) {
    res.status(500).json({ error: 'Error creating admin' });
  }
});

// 5️⃣ Admin Login endpoint
app.post('/admin/login', async (req, res) => {
  const { email, password } = req.body;

  const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
  const user = result.rows[0];

  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const validPassword = await bcrypt.compare(password, user.password);
  if (!validPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user.id, role: user.role }, 'YOUR_SECRET_KEY', { expiresIn: '1d' });

  res.json({ message: 'Login successful', token });
});

// 6️⃣ Middleware to protect routes
const authenticateAdmin = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) {
    return res.status(403).json({ error: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, 'YOUR_SECRET_KEY');
    req.user = decoded;
    if (decoded.role !== 'ADMIN') {
      return res.status(403).json({ error: 'Access denied' });
    }
    next();
  } catch (err) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// 7️⃣ Example of a protected route
app.get('/admin/products', authenticateAdmin, async (req, res) => {
  const result = await pool.query('SELECT * FROM products');
  res.json(result.rows);
});

// 8️⃣ Start the server
app.listen(3000, () => {
  console.log('Server is running on port 3000');
});
