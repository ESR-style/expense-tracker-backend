const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// Database connection
const pool = new Pool({
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASSWORD,
  host: process.env.POSTGRES_HOST,
  port: process.env.POSTGRES_PORT,
  database: process.env.POSTGRES_DATABASE,
  ssl: {
    rejectUnauthorized: false
  }
});

// Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
// Register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Check if user exists
    const userExists = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (userExists.rows.length > 0) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );

    // Generate token
    const token = jwt.sign(
      { id: newUser.rows[0].user_id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token });
  } catch (err) {
    console.error('Error during registration:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (user.rows.length === 0) {
      return res.status(400).json({ error: 'User does not exist' });
    }

    // Validate password
    const validPassword = await bcrypt.compare(password, user.rows[0].password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid password' });
    }

    // Generate token
    const token = jwt.sign(
      { id: user.rows[0].user_id },
      process.env.JWT_SECRET,
      { expiresIn: '1d' }
    );

    res.json({ token, name: user.rows[0].name });
  } catch (err) {
    console.error('Error during login:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's expenses
app.get('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const expenses = await pool.query(
      'SELECT * FROM transactions WHERE user_id = $1 AND type = $2 ORDER BY date DESC',
      [req.user.id, 'expense']
    );
    res.json(expenses.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new expense
app.post('/api/expenses', authenticateToken, async (req, res) => {
  try {
    const { category, amount, description } = req.body;
    const newExpense = await pool.query(
      'INSERT INTO transactions (user_id, type, category, amount, description) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [req.user.id, 'expense', category, amount, description]
    );
    res.json(newExpense.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Delete expense
app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM transactions WHERE transaction_id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json({ message: 'Transaction deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update expense
app.put('/api/expenses/:id', authenticateToken, async (req, res) => {
  try {
    const { category, amount, description } = req.body;
    const result = await pool.query(
      'UPDATE transactions SET category = $1, amount = $2, description = $3 WHERE transaction_id = $4 AND user_id = $5 RETURNING *',
      [category, amount, description, req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get all loans
app.get('/api/loans', authenticateToken, async (req, res) => {
  try {
    const loans = await pool.query(
      'SELECT * FROM new_loans WHERE user_id = $1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json(loans.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add new loan
app.post('/api/loans', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { person_name, type, amount, description, due_date } = req.body;

    // Validation
    if (!person_name?.trim()) {
      return res.status(400).json({ error: 'Person name is required' });
    }
    if (!type?.trim()) {
      return res.status(400).json({ error: 'Type is required' });
    }
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    if (!description?.trim()) {
      return res.status(400).json({ error: 'Description is required' });
    }

    const newLoan = await client.query(
      'INSERT INTO new_loans (user_id, person_name, type, amount, description, due_date) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [req.user.id, person_name.trim(), type.trim(), amount, description.trim(), due_date]
    );

    return res.status(201).json(newLoan.rows[0]);
  } catch (err) {
    console.error('Loan creation error:', err);
    return res.status(500).json({ error: 'Failed to create loan' });
  } finally {
    client.release();
  }
});

// Update loan
app.put('/api/loans/:id', authenticateToken, async (req, res) => {
  const client = await pool.connect();
  
  try {
    const { person_name, type, amount, description, status, due_date } = req.body;

    // Validation
    if (!person_name?.trim()) {
      return res.status(400).json({ error: 'Person name is required' });
    }
    if (!type?.trim()) {
      return res.status(400).json({ error: 'Type is required' });
    }
    if (!amount || isNaN(amount) || amount <= 0) {
      return res.status(400).json({ error: 'Valid amount is required' });
    }
    if (!description?.trim()) {
      return res.status(400).json({ error: 'Description is required' });
    }

    const updatedLoan = await client.query(
      'UPDATE new_loans SET person_name = $1, type = $2, amount = $3, description = $4, status = $5, due_date = $6, updated_at = CURRENT_TIMESTAMP WHERE loan_id = $7 AND user_id = $8 RETURNING *',
      [person_name.trim(), type.trim(), amount, description.trim(), status, due_date, req.params.id, req.user.id]
    );

    if (updatedLoan.rows.length === 0) {
      return res.status(404).json({ error: 'Loan not found' });
    }

    res.json(updatedLoan.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  } finally {
    client.release();
  }
});

// Delete loan
app.delete('/api/loans/:id', authenticateToken, async (req, res) => {
  try {
    const result = await pool.query(
      'DELETE FROM new_loans WHERE loan_id = $1 AND user_id = $2 RETURNING *',
      [req.params.id, req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Loan not found' });
    }

    res.json({ message: 'Loan deleted successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));