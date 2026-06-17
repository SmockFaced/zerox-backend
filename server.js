const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const helmet = require('helmet');
const fetch = require('node-fetch'); // Add this dependency

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'zerox-super-secret-key-CHANGE-THIS-IN-PRODUCTION';

const KEYAUTH_SELLER_KEY = process.env.KEYAUTH_SELLER_KEY || 'YOUR_SELLER_KEY_HERE'; // ← Set in .env
const KEYAUTH_APP_NAME = process.env.KEYAUTH_APP_NAME || 'Zerox'; // Your KeyAuth app name

app.use(helmet());
app.use(cors({ origin: '*' }));
app.use(express.json());

// DB setup (users + purchases only now)
const db = new sqlite3.Database('./zerox.db', (err) => {
  if (err) console.error('DB Error:', err);
  else console.log('✅ Connected to SQLite');
});

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    balance INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    product_name TEXT,
    amount REAL,
    quantity INTEGER DEFAULT 1,
    key_code TEXT,
    date TEXT DEFAULT CURRENT_TIMESTAMP,
    status TEXT DEFAULT 'active'
  )`);

  // Seed admin + demo user
  db.get("SELECT COUNT(*) as count FROM users", (err, row) => {
    if (row.count === 0) {
      const hashedAdmin = bcrypt.hashSync('admin123', 10);
      const hashedUser = bcrypt.hashSync('demo', 10);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['admin', hashedAdmin, 'admin', 9999]);
      db.run("INSERT INTO users (username, password, role, balance) VALUES (?, ?, ?, ?)", ['smockfaced', hashedUser, 'user', 0]);
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

// ==================== KeyAuth Helper ====================
async function callKeyAuth(type, extraParams = '') {
  const url = `https://keyauth.win/api/seller/?sellerkey=${KEYAUTH_SELLER_KEY}&type=${type}${extraParams}`;
  const response = await fetch(url);
  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch {
    return { success: false, message: text };
  }
}

// ==================== AUTH ====================
app.post('/api/register', async (req, res) => { /* unchanged */ });

app.post('/api/login', (req, res) => { /* unchanged */ });

// ==================== USER ====================
app.get('/api/me', authenticateToken, (req, res) => { /* unchanged */ });

app.post('/api/buy-credits', authenticateToken, (req, res) => { /* unchanged */ });

app.get('/api/products', (_, res) => { /* unchanged */ });

// Generate Keys via KeyAuth
app.post('/api/generate-keys', authenticateToken, async (req, res) => {
  const { productId, quantity = 1 } = req.body;

  db.get("SELECT * FROM products WHERE id = ?", [productId], async (err, product) => {
    if (err || !product) return res.status(404).json({ error: "Product not found" });

    db.get("SELECT balance FROM users WHERE id = ?", [req.user.id], async (err, user) => {
      const totalCost = product.price * quantity;
      if ((user?.balance || 0) < totalCost) return res.status(400).json({ error: "Insufficient balance" });

      // Deduct balance
      db.run("UPDATE users SET balance = balance - ? WHERE id = ?", [totalCost, req.user.id]);

      const generatedKeys = [];
      for (let i = 0; i < quantity; i++) {
        // Create license via KeyAuth
        const expiryDays = product.name.includes("Month") ? 30 : product.name.includes("Week") ? 7 : 1;
        const result = await callKeyAuth('add', `&expiry=${expiryDays}&format=1&amount=1&level=1&note=Zerox-${product.name}`);

        let keyCode = "ERROR";
        if (result.success && result.key) {
          keyCode = result.key;
        } else if (result.message) {
          console.error("KeyAuth error:", result.message);
        }

        generatedKeys.push(keyCode);

        // Record purchase
        db.run(`INSERT INTO purchases 
          (user_id, product_name, amount, quantity, key_code, status) 
          VALUES (?, ?, ?, ?, ?, 'active')`,
          [req.user.id, product.name, totalCost, quantity, keyCode]);
      }

      res.json({ 
        message: "Keys generated successfully via KeyAuth", 
        keys: generatedKeys, 
        totalCost 
      });
    });
  });
});

// Key Status Check via KeyAuth (or local if needed)
app.post('/api/check-key', async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: "Key required" });

  const result = await callKeyAuth('info', `&key=${key}`);
  res.json(result.success ? { valid: true, data: result } : { valid: false, message: result.message });
});

// ==================== ADMIN ROUTES (unchanged except products) ====================
/* Keep your existing admin routes for users, balance, products CRUD */

// Add product (if needed)
app.post('/api/admin/products', authenticateToken, (req, res) => { /* unchanged */ });

app.listen(PORT, () => console.log(`🚀 Zerox + KeyAuth backend running on http://localhost:${PORT}`));
