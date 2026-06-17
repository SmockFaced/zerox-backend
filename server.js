const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zerox-super-secret-key-CHANGE-THIS-IN-PRODUCTION-2026';

app.use(helmet());
app.use(cors());
app.use(express.json());

// Database
const db = new sqlite3.Database('./zerox.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT DEFAULT 'user',
    balance INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    price REAL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product TEXT,
    amount REAL,
    date TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'Active'
  )`);

  // Seed default accounts
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (row.count === 0) {
      const adminHash = bcrypt.hashSync('admin123', 10);
      const userHash = bcrypt.hashSync('demo', 10);
      
      db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['admin', adminHash, 'admin']);
      db.run("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ['smockfaced', userHash, 'user']);
    }
  });

  // Seed products
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row.count === 0) {
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Day", 2.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Week", 7.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["HWID Spoofer Month", 10]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Chess Month", 4]);
    }
  });
});

// Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "Access denied" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role }, 
      JWT_SECRET, 
      { expiresIn: '7d' }
    );

    res.json({ token, role: user.role, username: user.username });
  });
});

// Get current user
app.get('/api/me', authenticateToken, (req, res) => {
  db.get("SELECT id, username, role, balance FROM users WHERE id = ?", [req.user.id], (err, user) => {
    res.json(user);
  });
});

// Buy Credits
app.post('/api/buy-credits', authenticateToken, (req, res) => {
  db.run("UPDATE users SET balance = balance + 250 WHERE id = ?", [req.user.id], function(err) {
    if (err) return res.status(500).json({ error: "Failed" });
    db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], (err, row) => {
      res.json({ message: "250 Credits added", balance: row.balance });
    });
  });
});

// Get Products
app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM products", [], (err, rows) => res.json(rows));
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin only" });
  db.all("SELECT id, username, role, balance FROM users", [], (err, rows) => res.json(rows));
});

app.put('/api/admin/users/:id/balance', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin only" });
  const { balance } = req.body;
  db.run("UPDATE users SET balance = ? WHERE id = ?", [balance, req.params.id], () => {
    res.json({ message: "Balance updated" });
  });
});

app.post('/api/admin/products', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: "Admin only" });
  const { name, price } = req.body;
  db.run("INSERT INTO products (name, price) VALUES (?, ?)", [name, price], function(err) {
    res.json({ id: this.lastID });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Zerox backend running on port ${PORT}`);
});
