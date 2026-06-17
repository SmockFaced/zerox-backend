const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet'); // Add this

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zerox-super-secret-key-CHANGE-THIS-IN-PRODUCTION';

app.use(helmet());
app.use(cors({ origin: '*' })); // Change to your frontend URL later
app.use(express.json());

// Database setup
const db = new sqlite3.Database('./zerox.db', (err) => {
  if (err) console.error(err);
  else console.log('Connected to SQLite database');
});

// Create tables
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
    date TEXT,
    status TEXT
  )`);

  // Seed default admin + user if empty
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (row.count === 0) {
      const hashedAdmin = bcrypt.hashSync('admin123', 10);
      const hashedUser = bcrypt.hashSync('demo', 10);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
        ['admin', hashedAdmin, 'admin', 0]);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
        ['smockfaced', hashedUser, 'user', 0]);
    }
  });

  // Seed some products
  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row.count === 0) {
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Day", 2.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Week", 7.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["HWID Spoofer Month", 10]);
    }
  });
});

// Middleware to verify JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// ==================== AUTH ROUTES ====================
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const hashed = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
    [username, hashed, 'user', 0], function(err) {
      if (err) return res.status(400).json({ error: "Username already exists" });
      res.json({ message: "User created" });
    });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (!user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, username: user.username });
  });
});

// ==================== USER ROUTES ====================
app.get('/api/me', authenticateToken, (req, res) => {
  db.get("SELECT id, username, role, balance FROM users WHERE id = ?", [req.user.id], (err, user) => {
    res.json(user);
  });
});

app.post('/api/buy-credits', authenticateToken, (req, res) => {
  const amount = 250;
  db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: "Failed" });
    db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], (err, row) => {
      res.json({ message: "Credits added", balance: row.balance });
    });
  });
});

// ==================== ADMIN ROUTES ====================
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  db.all("SELECT id, username, role, balance FROM users", [], (err, rows) => {
    res.json(rows);
  });
});

app.post('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { username, password, role } = req.body;
  const hashed = bcrypt.hashSync(password, 10);
  db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
    [username, hashed, role || 'user', 0], function(err) {
      if (err) return res.status(400).json({ error: "Error creating user" });
      res.json({ id: this.lastID });
    });
});

app.put('/api/admin/users/:id/balance', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { balance } = req.body;
  db.run("UPDATE users SET balance = ? WHERE id = ?", [balance, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: "Failed" });
    res.json({ message: "Balance updated" });
  });
});

// Products
app.get('/api/products', (req, res) => {
  db.all("SELECT * FROM products", [], (err, rows) => res.json(rows));
});

app.post('/api/admin/products', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, price } = req.body;
  db.run("INSERT INTO products (name, price) VALUES (?, ?)", [name, price], function(err) {
    res.json({ id: this.lastID });
  });
});

app.put('/api/admin/products/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, price } = req.body;
  db.run("UPDATE products SET name = ?, price = ? WHERE id = ?", [name, price, req.params.id], (err) => {
    res.json({ message: "Updated" });
  });
});

app.delete('/api/admin/products/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  db.run("DELETE FROM products WHERE id = ?", [req.params.id], (err) => {
    res.json({ message: "Deleted" });
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Zerox backend running on port ${PORT}`);
});