// server.js
// Single-file Express + SQLite backend for Material Management System
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'supersecret';
const NODE_ENV = process.env.NODE_ENV || 'development';
const DB_FILE = path.join(__dirname, 'database.sqlite');
const UPLOAD_DIR = path.join(__dirname, 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// Open or create DB
const db = new sqlite3.Database(DB_FILE);

function runSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}

function allSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, (err, rows) => {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

function getSql(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, (err, row) => {
      if (err) return reject(err);
      resolve(row);
    });
  });
}

// Initialize DB schema and seed data if missing
async function initDb() {
  db.serialize(async () => {
    try {
      // Users
      await runSql(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        email TEXT UNIQUE,
        password_hash TEXT,
        role TEXT,
        siteId TEXT
      )`);

      // Materials
      await runSql(`CREATE TABLE IF NOT EXISTS materials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code TEXT,
        name TEXT,
        category TEXT,
        unit TEXT,
        description TEXT
      )`);

      // Indents
      await runSql(`CREATE TABLE IF NOT EXISTS indents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        material_id INTEGER,
        quantity INTEGER,
        siteId TEXT,
        status TEXT,
        createdBy INTEGER,
        approvedBy INTEGER,
        receivedQty INTEGER DEFAULT 0,
        damagedQty INTEGER DEFAULT 0,
        createdAt TEXT DEFAULT (datetime('now'))
      )`);

      // Orders
      await runSql(`CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indent_id INTEGER,
        vendor_name TEXT,
        vendor_contact TEXT,
        status TEXT,
        createdAt TEXT DEFAULT (datetime('now'))
      )`);

      // Notifications
      await runSql(`CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT,
        userId INTEGER,
        isRead INTEGER DEFAULT 0,
        createdAt TEXT DEFAULT (datetime('now'))
      )`);

      // Receipts
      await runSql(`CREATE TABLE IF NOT EXISTS receipts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        indent_id INTEGER,
        file_url TEXT,
        uploadedBy INTEGER,
        createdAt TEXT DEFAULT (datetime('now'))
      )`);

      // Seed users if none
      const users = await allSql(`SELECT * FROM users LIMIT 1`);
      if (!users || users.length === 0) {
        console.log('Seeding users & materials...');
        const passwordPlain = 'password123';
        const saltRounds = 10;
        const hashEngineer = bcrypt.hashSync(passwordPlain, saltRounds);
        const hashPurchase = bcrypt.hashSync(passwordPlain, saltRounds);
        const hashDirector = bcrypt.hashSync(passwordPlain, saltRounds);

        await runSql(
          `INSERT INTO users (username,email,password_hash,role,siteId) VALUES (?, ?, ?, ?, ?)`,
          ['engineer1', 'engineer1@company.com', hashEngineer, 'Site Engineer', 'site-chembur']
        );
        await runSql(
          `INSERT INTO users (username,email,password_hash,role,siteId) VALUES (?, ?, ?, ?, ?)`,
          ['purchase1', 'purchase1@company.com', hashPurchase, 'Purchase Team', 'head-office']
        );
        await runSql(
          `INSERT INTO users (username,email,password_hash,role,siteId) VALUES (?, ?, ?, ?, ?)`,
          ['director1', 'director1@company.com', hashDirector, 'Director', 'head-office']
        );

        // Seed 20 materials
        const materials = [
          ['CEM001','Portland Cement','Cement','Bags','High quality Portland cement'],
          ['STL001','Steel Rebar','Steel','Tons','High tensile steel bars'],
          ['BRK001','Red Clay Bricks','Bricks','Pieces','Standard red clay bricks'],
          ['SND001','River Sand','Aggregates','MT','Washed river sand'],
          ['GRV001','Gravel','Aggregates','MT','Coarse gravel'],
          ['PLY001','Plywood','Wood','Sheets','Marine plywood 12mm'],
          ['TIL001','Ceramic Tiles','Tiles','Boxes','Floor tiles 600x600'],
          ['GLS001','Glass Pane','Glass','Sqft','Clear glass 6mm'],
          ['WTR001','PVC Pipes','Plumbing','Meters','PVC pipe 3-inch'],
          ['ELC001','Wires','Electrical','Rolls','Copper wire 2.5mm2'],
          ['PAI001','Paint','Finishes','Liters','Interior emulsion'],
          ['INS001','Insulation','Thermal','Rolls','Glass wool insulation'],
          ['NUT001','Bolts & Nuts','Fixings','Boxes','Mild steel bolts & nuts'],
          ['SHP001','Shuttering Plywood','Wood','Sheets','18mm shuttering'],
          ['GLU001','Adhesive','Chemical','Kg','Construction adhesive'],
          ['FIT001','Door Fittings','Hardware','Sets','Hinges, handles, locks'],
          ['WND001','Window Frame','Joinery','Pieces','Aluminum window frame'],
          ['RCT001','Concrete Mix','Concrete','CubicMeters','Ready mix concrete'],
          ['MSH001','Mesh Wire','Steel','Rolls','Welded mesh'],
          ['FNR001','Furniture','Misc','Pieces','Office furniture set']
        ];

        for (const m of materials) {
          await runSql(
            `INSERT INTO materials (code, name, category, unit, description) VALUES (?, ?, ?, ?, ?)`,
            m
          );
        }
      }
      console.log('DB ready.');
    } catch (err) {
      console.error('DB init error', err);
    }
  });
}

// Initialize DB
initDb();

// Express app
const app = express();

// CORS Configuration - CRITICAL FOR VERCEL
app.use(cors({
  origin: [
    'http://localhost:3000',
    'https://material-management-mobile.vercel.app',
    'https://*.vercel.app'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(bodyParser.json({ limit: '10mb' }));

// Helper: standard JSON success / fail wrappers
function ok(res, data) {
  return res.json({ success: true, data });
}

function fail(res, status = 400, error = 'Bad Request') {
  return res.status(status).json({ success: false, error });
}

// JWT middleware
function authMiddleware(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return fail(res, 401, 'Authorization header missing');

  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') {
    return fail(res, 401, 'Invalid Authorization header');
  }

  const token = parts[1];  // correct token extraction
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return fail(res, 401, 'Invalid or expired token');
  }
}

// Role check helper
function requireRole(roles) {
  return (req, res, next) => {
    const role = req.user && req.user.role;
    if (!role || !roles.includes(role)) return fail(res, 403, 'Forbidden: insufficient role');
    next();
  };
}

// Auth routes
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!password || (!username && !email)) return fail(res, 400, 'username/email and password required');

    const user = await getSql(
      `SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1`,
      [username || '', email || '']
    );

    if (!user) return fail(res, 401, 'Invalid credentials');

    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return fail(res, 401, 'Invalid credentials');

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, siteId: user.siteId },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    return ok(res, {
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        siteId: user.siteId
      }
    });
  } catch (err) {
    console.error('login error', err);
    return fail(res, 500, 'Server error');
  }
});

app.post('/api/auth/logout', (req, res) => {
  return ok(res, { message: 'Logged out' });
});

// Auth verify endpoint - MISSING FROM ORIGINAL
app.get('/api/auth/verify', authMiddleware, async (req, res) => {
  try {
    const user = await getSql(`SELECT * FROM users WHERE id = ?`, [req.user.id]);
    if (!user) return fail(res, 404, 'User not found');

    return ok(res, {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
      siteId: user.siteId
    });
  } catch (err) {
    return fail(res, 500, 'Server error');
  }
});

// Materials
app.get('/api/materials', authMiddleware, async (req, res) => {
  try {
    const rows = await allSql(`SELECT * FROM materials ORDER BY name`);
    return ok(res, rows);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Materials search endpoint - MISSING FROM ORIGINAL
app.get('/api/materials/search', authMiddleware, async (req, res) => {
  try {
    const { q } = req.query;
    if (!q) return ok(res, []);

    const rows = await allSql(
      `SELECT * FROM materials WHERE name LIKE ? OR description LIKE ? ORDER BY name LIMIT 20`,
      [`%${q}%`, `%${q}%`]
    );
    return ok(res, rows);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Sites endpoint - MISSING FROM ORIGINAL
app.get('/api/sites', authMiddleware, async (req, res) => {
  try {
    const sites = [
      { id: 'site-chembur', name: 'Chembur Site' },
      { id: 'site-bandra', name: 'Bandra Site' },
      { id: 'site-mumbai', name: 'Mumbai Central Site' }
    ];
    return ok(res, sites);
  } catch (err) {
    return fail(res, 500, 'Server error');
  }
});

// Indents
app.post('/api/indents', authMiddleware, requireRole(['Site Engineer']), async (req, res) => {
  try {
    const { material_id, quantity, siteId } = req.body;
    if (!material_id || !quantity) return fail(res, 400, 'material_id and quantity required');

    const status = 'Pending';
    const r = await runSql(
      `INSERT INTO indents (material_id, quantity, siteId, status, createdBy) VALUES (?, ?, ?, ?, ?)`,
      [material_id, quantity, siteId || req.user.siteId, status, req.user.id]
    );

    const indent = await getSql(`SELECT * FROM indents WHERE id = ?`, [r.lastID]);
    
    await runSql(`INSERT INTO notifications (message, userId) VALUES (?, ?)`, [`New indent #${r.lastID} created`, null]);
    
    return ok(res, indent);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

app.get('/api/indents', authMiddleware, async (req, res) => {
  try {
    const role = req.user.role;
    if (role === 'Site Engineer') {
      const rows = await allSql(`SELECT i.*, m.name as material_name FROM indents i LEFT JOIN materials m ON m.id=i.material_id WHERE i.siteId = ? ORDER BY i.createdAt DESC`, [req.user.siteId]);
      return ok(res, rows);
    } else {
      const rows = await allSql(`SELECT i.*, m.name as material_name FROM indents i LEFT JOIN materials m ON m.id=i.material_id ORDER BY i.createdAt DESC`);
      return ok(res, rows);
    }
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

app.patch('/api/indents/:id/approve', authMiddleware, requireRole(['Purchase Team','Director']), async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const indent = await getSql(`SELECT * FROM indents WHERE id = ?`, [id]);
    if (!indent) return fail(res, 404, 'Indent not found');

    let newStatus = indent.status;
    if (req.user.role === 'Purchase Team') {
      newStatus = 'Approved by Purchase';
    } else if (req.user.role === 'Director') {
      if (indent.status === 'Approved by Purchase') newStatus = 'Approved by Director';
      else newStatus = 'Approved by Director';
    }

    await runSql(`UPDATE indents SET status = ?, approvedBy = ? WHERE id = ?`, [newStatus, req.user.id, id]);
    
    await runSql(`INSERT INTO notifications (message, userId) VALUES (?, ?)`, [`Indent #${id} approved by ${req.user.role}`, null]);
    
    const updated = await getSql(`SELECT * FROM indents WHERE id = ?`, [id]);
    return ok(res, updated);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

app.patch('/api/indents/:id/receive', authMiddleware, requireRole(['Site Engineer']), async (req, res) => {
  try {
    const id = parseInt(req.params.id);
    const { receivedQty } = req.body;
    if (typeof receivedQty !== 'number') return fail(res, 400, 'receivedQty (number) required');

    const indent = await getSql(`SELECT * FROM indents WHERE id = ?`, [id]);
    if (!indent) return fail(res, 404, 'Indent not found');

    const newReceived = (indent.receivedQty || 0) + receivedQty;
    let newStatus = indent.status;
    if (newReceived >= indent.quantity) newStatus = 'Completed';
    else newStatus = 'Partially Received';

    await runSql(`UPDATE indents SET receivedQty = ?, status = ? WHERE id = ?`, [newReceived, newStatus, id]);
    await runSql(`INSERT INTO notifications (message, userId) VALUES (?, ?)`, [`Indent #${id} received ${receivedQty}`, null]);

    const updated = await getSql(`SELECT * FROM indents WHERE id = ?`, [id]);
    return ok(res, updated);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Dashboard stats endpoint - MISSING FROM ORIGINAL  
app.get('/api/reports/dashboard', authMiddleware, async (req, res) => {
  try {
    const { siteId } = req.query;
    
    let whereClause = '';
    let params = [];
    if (siteId && req.user.role === 'Site Engineer') {
      whereClause = 'WHERE siteId = ?';
      params = [siteId];
    }
    
    const totalIndents = await getSql(`SELECT COUNT(*) as count FROM indents ${whereClause}`, params);
    const pendingApproval = await getSql(`SELECT COUNT(*) as count FROM indents ${whereClause ? whereClause + ' AND' : 'WHERE'} status = 'Pending'`, siteId ? [...params] : []);
    const approvedIndents = await getSql(`SELECT COUNT(*) as count FROM indents ${whereClause ? whereClause + ' AND' : 'WHERE'} status LIKE '%Approved%'`, siteId ? [...params] : []);
    
    return ok(res, {
      totalIndents: totalIndents.count || 0,
      pendingApproval: pendingApproval.count || 0,
      approvedIndents: approvedIndents.count || 0,
      thisMonthIndents: 0,
      recentIndents: [],
      chartData: [],
      statusDistribution: []
    });
  } catch (err) {
    return fail(res, 500, 'Server error');
  }
});

// Orders
app.post('/api/orders', authMiddleware, requireRole(['Purchase Team']), async (req, res) => {
  try {
    const { indent_id, vendor_name, vendor_contact } = req.body;
    if (!indent_id || !vendor_name) return fail(res, 400, 'indent_id and vendor_name required');

    const r = await runSql(
      `INSERT INTO orders (indent_id, vendor_name, vendor_contact, status) VALUES (?, ?, ?, ?)`,
      [indent_id, vendor_name, vendor_contact || null, 'Placed']
    );

    await runSql(`INSERT INTO notifications (message, userId) VALUES (?, ?)`, [`Order #${r.lastID} created for indent #${indent_id}`, null]);

    const order = await getSql(`SELECT * FROM orders WHERE id = ?`, [r.lastID]);
    return ok(res, order);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

app.get('/api/orders', authMiddleware, requireRole(['Purchase Team','Director']), async (req, res) => {
  try {
    const rows = await allSql(`SELECT * FROM orders ORDER BY createdAt DESC`);
    return ok(res, rows);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Reports
app.get('/api/reports/monthly', authMiddleware, requireRole(['Purchase Team','Director']), async (req, res) => {
  try {
    const totalIndentsRow = await getSql(`SELECT COUNT(*) as total FROM indents`);
    const completedRow = await getSql(`SELECT COUNT(*) as completed FROM indents WHERE status = 'Completed'`);
    const pendingRow = await getSql(`SELECT COUNT(*) as pending FROM indents WHERE status = 'Pending'`);
    const damagedRow = await getSql(`SELECT COUNT(*) as damaged FROM indents WHERE status = 'Damaged' OR damagedQty > 0`);
    const perSiteRows = await allSql(`SELECT siteId, COUNT(*) as total FROM indents GROUP BY siteId`);

    const result = {
      totalIndents: totalIndentsRow.total || 0,
      completed: completedRow.completed || 0,
      pending: pendingRow.pending || 0,
      damaged: damagedRow.damaged || 0,
      perSite: perSiteRows
    };
    return ok(res, result);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

app.get('/api/reports/export', authMiddleware, requireRole(['Purchase Team','Director']), async (req, res) => {
  try {
    const indents = await allSql(`SELECT i.*, m.name as material_name FROM indents i LEFT JOIN materials m ON m.id=i.material_id ORDER BY i.createdAt DESC`);
    return ok(res, indents);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Notifications
app.get('/api/notifications', authMiddleware, async (req, res) => {
  try {
    const rows = await allSql(`SELECT * FROM notifications ORDER BY createdAt DESC LIMIT 100`);
    return ok(res, rows);
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Upload
app.post('/api/upload', authMiddleware, async (req, res) => {
  try {
    const { base64, indent_id } = req.body;
    if (!base64) return fail(res, 400, 'base64 required');

    const matches = base64.match(/^data:(.+);base64,(.+)$/);
let ext = 'jpg';
let data;
if (matches) {
  const mime = matches[1];
  data = matches[2];
  if (mime.includes('png')) ext = 'png';
  else if (mime.includes('jpeg')) ext = 'jpg';
} else {
  data = base64;
}

    const filename = `receipt-${Date.now()}-${Math.random().toString(36).slice(2)}.${ext}`;
    const filepath = path.join(UPLOAD_DIR, filename);
    fs.writeFileSync(filepath, Buffer.from(data, 'base64'));

    if (indent_id) {
      await runSql(`INSERT INTO receipts (indent_id, file_url, uploadedBy) VALUES (?, ?, ?)`, [indent_id, `/uploads/${filename}`, req.user.id]);
    }

    const fileUrl = `${req.protocol}://${req.get('host')}/uploads/${filename}`;
    return ok(res, { url: fileUrl });
  } catch (err) {
    console.error(err);
    return fail(res, 500, 'Server error');
  }
});

// Serve uploaded files
app.use('/uploads', express.static(UPLOAD_DIR));

// Health
app.get('/health', (req, res) => {
  return ok(res, { status: 'healthy', service: 'Mock Material Management API', timestamp: new Date().toISOString() });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Mock API (SQLite) running on port ${PORT}`);
});
