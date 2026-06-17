const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zerox-super-secret-key-CHANGE-THIS-IN-PRODUCTION'; // ← Change this!

app.use(helmet());
app.use(cors({ origin: '*' })); // TODO: Lock to your domain in prod
app.use(express.json());

// DB
const db = new sqlite3.Database('./zerox.db', (err) => {
  if (err) console.error('DB Error:', err);
  else console.log('✅ Connected to SQLite');
});

db.serialize(() => {
  // Tables
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    balance INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_id INTEGER,
    product_name TEXT,
    amount REAL,
    quantity INTEGER DEFAULT 1,
    key_code TEXT,
    date TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active',
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_code TEXT UNIQUE NOT NULL,
    product_id INTEGER,
    user_id INTEGER,
    hwid TEXT,
    expires_at TEXT,
    status TEXT DEFAULT 'active'
  )`);

  // Seed data (only if empty)
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (row.count === 0) {
      const hashedAdmin = bcrypt.hashSync('admin123', 10);
      const hashedUser = bcrypt.hashSync('demo', 10);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['admin', hashedAdmin, 'admin', 9999]);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['smockfaced', hashedUser, 'user', 0]);
    }
  });

  db.get("SELECT COUNT(*) as count FROM products", (err, row) => {
    if (row.count === 0) {
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Day", 2.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["Rogue Company Week", 7.50]);
      db.run("INSERT INTO products (name, price) VALUES (?, ?)", ["HWID Spoofer Month", 10]);
    }
  });
});

// Auth middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

// ==================== AUTH ====================
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Missing fields" });

  const hashed = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
    [username, hashed, 'user', 0], function(err) {
      if (err) return res.status(400).json({ error: "Username already exists" });
      res.json({ message: "User created", id: this.lastID });
    });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, role: user.role, username: user.username, balance: user.balance });
  });
});

// ==================== USER ====================
app.get('/api/me', authenticateToken, (req, res) => {
  db.get("SELECT id, username, role, balance FROM users WHERE id = ?", [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  });
});

app.post('/api/buy-credits', authenticateToken, (req, res) => {
  const amount = 250;
  db.run("UPDATE users SET balance = balance + ? WHERE id = ?", [amount, req.user.id], function(err) {
    if (err) return res.status(500).json({ error: "Failed" });
    db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], (_, row) => {
      res.json({ message: "Credits added", balance: row.balance });
    });
  });
});

app.get('/api/products', (_, res) => {
  db.all("SELECT * FROM products", [], (err, rows) => res.json(rows));
});

// Generate keys (new endpoint)
app.post('/api/generate-keys', authenticateToken, (req, res) => {
  const { productId, quantity = 1 } = req.body;

  db.get("SELECT * FROM products WHERE id = ?", [productId], (err, product) => {
    if (err || !product) return res.status(404).json({ error: "Product not found" });

    db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], (err, user) => {
      const totalCost = product.price * quantity;
      if (user.balance < totalCost) return res.status(400).json({ error: "Insufficient balance" });

      // Deduct balance
      db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [totalCost, req.user.id]);

      const generatedKeys = [];
      for (let i = 0; i < quantity; i++) {
        const keyCode = 'ZX-' + Math.random().toString(36).substring(2, 10).toUpperCase() + '-' + 
                       Math.random().toString(36).substring(2, 10).toUpperCase();
        
        generatedKeys.push(keyCode);
        
        db.run("INSERT INTO keys (key_code, product_id, user_id, expires_at) VALUES (?, ?, ?, date('now', '+30 days'))", 
          [keyCode, productId, req.user.id]);
        
        db.run("INSERT INTO purchases (user_id, product_id, product_name, amount, quantity, key_code, status) VALUES (?, ?, ?, ?, ?, ?, 'active')",
          [req.user.id, productId, product.name, totalCost, quantity, keyCode]);
      }

      res.json({ message: "Keys generated", keys: generatedKeys, totalCost });
    });
  });
});

// Key status check
app.post('/api/check-key', (req, res) => {
  const { key } = req.body;
  db.get("SELECT * FROM keys WHERE key_code = ?", [key], (err, keyData) => {
    if (err || !keyData) return res.status(404).json({ valid: false, message: "Invalid key" });
    res.json({ valid: true, key: keyData });
  });
});

// ==================== ADMIN ====================
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  db.all("SELECT id, username, role, balance, created_at FROM users", [], (err, rows) => res.json(rows));
});

app.post('/api/admin/users', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { username, password, role } = req.body;
  const hashed = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", 
    [username, hashed, role || 'user', 0], function(err) {
      if (err) return res.status(400).json({ error: "Error" });
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

// Products admin
app.post('/api/admin/products', authenticateToken, (req, res) => {
  if (req.user.role !== 'admin') return res.sendStatus(403);
  const { name, price } = req.body;
  db.run("INSERT INTO products (name, price) VALUES (?, ?)", [name, price], function(err) {
    res.json({ id: this.lastID });
  });
});

app.put('/api/admin/products/:id', authenticateToken, (req, res) => { /* same as before */ });
app.delete('/api/admin/products/:id', authenticateToken, (req, res) => { /* same as before */ });

app.listen(PORT, () => console.log(`🚀 Zerox backend running on http://localhost:${PORT}`));
