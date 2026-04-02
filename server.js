const express = require('express');
const path = require('path');
const nodemailer = require('nodemailer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'gutcheck-dev-secret';

// --------------- Middleware ---------------
app.use(cors());

// Skip JSON parsing for Stripe webhook (needs raw body for signature verification)
app.use((req, res, next) => {
  if (req.originalUrl === '/api/stripe-webhook') return next();
  express.json()(req, res, next);
});
app.use(express.urlencoded({ extended: true }));

// Serve static files (HTML, CSS, JS, images) from project root
app.use(express.static(path.join(__dirname), {
  extensions: ['html'] // allows /contact to serve contact.html
}));

// --------------- Database ---------------
const db = new Database(process.env.DB_PATH || 'gutcheck.db');
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    plan TEXT DEFAULT 'free',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS squad_sessions (
    id TEXT PRIMARY KEY,
    creator_id INTEGER NOT NULL,
    video_url TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS squad_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    verdict TEXT,
    confidence REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (session_id) REFERENCES squad_sessions(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS analytics_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event TEXT NOT NULL,
    page TEXT,
    referrer TEXT,
    user_agent TEXT,
    session_id TEXT,
    user_id INTEGER,
    meta TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS user_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    video_url TEXT,
    video_name TEXT,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    score INTEGER,
    emotions TEXT,
    duration INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS squad_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    shared_by INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES user_scans(id),
    FOREIGN KEY (shared_by) REFERENCES users(id),
    FOREIGN KEY (session_id) REFERENCES squad_sessions(id)
  );
  CREATE TABLE IF NOT EXISTS friend_verdicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    share_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (share_id) REFERENCES squad_shares(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS friend_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT UNIQUE NOT NULL,
    used_by INTEGER,
    used_at DATETIME,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (used_by) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS code_tracker (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    month TEXT NOT NULL,
    codes_generated INTEGER DEFAULT 0,
    UNIQUE(user_id, month),
    FOREIGN KEY (user_id) REFERENCES users(id)
  );
`);

// --------------- Auth helpers ---------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
}

// --------------- Video upload ---------------
const upload = multer({
  dest: 'uploads/',
  limits: { fileSize: 100 * 1024 * 1024 }, // 100 MB
  fileFilter(req, file, cb) {
    if (file.mimetype.startsWith('video/')) cb(null, true);
    else cb(new Error('Only video files are allowed'));
  }
});

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// =============================================
//  API ROUTES
// =============================================

// --------------- Auth ---------------
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const passwordHash = await bcrypt.hash(password, 10);
    const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    const result = stmt.run(email, passwordHash);

    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: result.lastInsertRowid, email, plan: 'free' } });
  } catch (err) {
    if (err.message?.includes('UNIQUE')) return res.status(409).json({ error: 'Email already registered' });
    console.error('Register error:', err);
    res.status(500).json({ error: 'Registration failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email, plan: user.plan } });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed' });
  }
});

// --------------- Contact ---------------
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ error: 'All fields required' });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD
      }
    });

    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: 'joseph.morin@gmail.com',
      replyTo: email,
      subject: `GutCheck Contact: ${subject}`,
      text: `Name: ${name}\nEmail: ${email}\n\n${message}`,
      html: `
        <h3>New contact form submission from GutCheck</h3>
        <p><strong>Name:</strong> ${name}</p>
        <p><strong>Email:</strong> ${email}</p>
        <p><strong>Subject:</strong> ${subject}</p>
        <p><strong>Message:</strong></p>
        <p>${message.replace(/\n/g, '<br>')}</p>
      `
    });

    res.json({ success: true });
  } catch (err) {
    console.error('Contact form error:', err);
    res.status(500).json({ error: 'Failed to send message' });
  }
});

// --------------- Stripe Checkout ---------------
app.post('/api/create-checkout-session', async (req, res) => {
  try {
    const { priceId, plan } = req.body;

    const session = await stripe.checkout.sessions.create({
      mode: 'subscription',
      payment_method_types: ['card'],
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${req.headers.origin || 'https://gutcheck.you'}/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${req.headers.origin || 'https://gutcheck.you'}/upgrade`,
      metadata: { plan, product: 'gutcheck_premium' }
    });

    res.json({ id: session.id });
  } catch (err) {
    console.error('Stripe error:', err);
    res.status(500).json({ error: err.message });
  }
});

// --------------- Stripe Webhook ---------------
app.post('/api/stripe-webhook', express.raw({ type: 'application/json' }), (req, res) => {
  const sig = req.headers['stripe-signature'];
  const endpointSecret = process.env.STRIPE_WEBHOOK_SECRET;

  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, endpointSecret);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const customerEmail = session.customer_details?.email;
      const plan = session.metadata?.plan || 'premium';
      if (customerEmail) {
        db.prepare('UPDATE users SET plan = ? WHERE email = ?').run(plan, customerEmail);
      }
      break;
    }
    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      const customerId = subscription.customer;
      // Downgrade user on cancellation — would need customer email lookup in production
      console.log('Subscription cancelled for customer:', customerId);
      break;
    }
  }

  res.json({ received: true });
});

// --------------- SquadCheck ---------------
app.post('/api/squadcheck/create', authenticateToken, (req, res) => {
  const { videoUrl } = req.body;
  const sessionId = require('crypto').randomUUID();

  db.prepare('INSERT INTO squad_sessions (id, creator_id, video_url) VALUES (?, ?, ?)')
    .run(sessionId, req.user.id, videoUrl || null);

  res.json({ sessionId, shareLink: `/squadcheck?session=${sessionId}` });
});

app.post('/api/squadcheck/:sessionId/respond', authenticateToken, (req, res) => {
  const { sessionId } = req.params;
  const { verdict, confidence } = req.body;

  const session = db.prepare('SELECT * FROM squad_sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });

  db.prepare('INSERT INTO squad_responses (session_id, user_id, verdict, confidence) VALUES (?, ?, ?, ?)')
    .run(sessionId, req.user.id, verdict, confidence);

  res.json({ success: true });
});

app.get('/api/squadcheck/:sessionId/results', authenticateToken, (req, res) => {
  const { sessionId } = req.params;

  const session = db.prepare('SELECT * FROM squad_sessions WHERE id = ?').get(sessionId);
  if (!session) return res.status(404).json({ error: 'Session not found' });

  const responses = db.prepare('SELECT sr.*, u.email FROM squad_responses sr JOIN users u ON sr.user_id = u.id WHERE sr.session_id = ?').all(sessionId);

  res.json({ session, responses });
});

// --------------- Video Upload ---------------
app.post('/api/upload', authenticateToken, upload.single('video'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No video file provided' });
  res.json({ url: `/uploads/${req.file.filename}`, originalName: req.file.originalname });
});

// --------------- Analytics ---------------
app.post('/api/analytics/event', (req, res) => {
  const { event, page, referrer, sessionId, meta } = req.body;
  if (!event) return res.status(400).json({ error: 'Event name required' });

  db.prepare(
    'INSERT INTO analytics_events (event, page, referrer, user_agent, session_id, meta) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(event, page || null, referrer || null, req.headers['user-agent'] || null, sessionId || null, meta ? JSON.stringify(meta) : null);

  res.json({ success: true });
});

app.get('/api/analytics/dashboard', authenticateToken, (req, res) => {
  const days = parseInt(req.query.days) || 30;
  const since = new Date(Date.now() - days * 86400000).toISOString();

  const totalEvents = db.prepare('SELECT COUNT(*) as count FROM analytics_events WHERE created_at >= ?').get(since);
  const uniqueSessions = db.prepare('SELECT COUNT(DISTINCT session_id) as count FROM analytics_events WHERE created_at >= ?').get(since);
  const topPages = db.prepare('SELECT page, COUNT(*) as views FROM analytics_events WHERE page IS NOT NULL AND created_at >= ? GROUP BY page ORDER BY views DESC LIMIT 10').all(since);
  const topEvents = db.prepare('SELECT event, COUNT(*) as count FROM analytics_events WHERE created_at >= ? GROUP BY event ORDER BY count DESC LIMIT 10').all(since);
  const dailyCounts = db.prepare("SELECT DATE(created_at) as date, COUNT(*) as count FROM analytics_events WHERE created_at >= ? GROUP BY DATE(created_at) ORDER BY date").all(since);
  const totalUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const planBreakdown = db.prepare('SELECT plan, COUNT(*) as count FROM users GROUP BY plan').all();

  res.json({ totalEvents: totalEvents.count, uniqueSessions: uniqueSessions.count, topPages, topEvents, dailyCounts, totalUsers: totalUsers.count, planBreakdown });
});

// --------------- Premium Dashboard ---------------
app.get('/api/dashboard/stats', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const weekAgo = new Date(Date.now() - 7 * 86400000).toISOString();

  const totalScans = db.prepare('SELECT COUNT(*) as count FROM user_scans WHERE user_id = ?').get(userId);
  const weekScans = db.prepare('SELECT COUNT(*) as count FROM user_scans WHERE user_id = ? AND created_at >= ?').get(userId, weekAgo);
  const uncertainScans = db.prepare("SELECT COUNT(*) as count FROM user_scans WHERE user_id = ? AND verdict = 'uncertain'").get(userId);
  const squadShares = db.prepare('SELECT COUNT(*) as count FROM squad_shares WHERE shared_by = ?').get(userId);

  res.json({
    totalScans: totalScans.count,
    weekScans: weekScans.count,
    uncertainScans: uncertainScans.count,
    squadShares: squadShares.count
  });
});

app.get('/api/dashboard/scans', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const limit = parseInt(req.query.limit) || 20;
  const offset = parseInt(req.query.offset) || 0;

  const scans = db.prepare(
    'SELECT * FROM user_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?'
  ).all(userId, limit, offset);

  const total = db.prepare('SELECT COUNT(*) as count FROM user_scans WHERE user_id = ?').get(userId);

  res.json({ scans, total: total.count });
});

app.post('/api/dashboard/scans', authenticateToken, (req, res) => {
  const { videoUrl, videoName, verdict, confidence, score, emotions, duration } = req.body;
  if (!verdict || confidence == null) return res.status(400).json({ error: 'Verdict and confidence required' });

  const result = db.prepare(
    'INSERT INTO user_scans (user_id, video_url, video_name, verdict, confidence, score, emotions, duration) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, videoUrl || null, videoName || null, verdict, confidence, score || null, emotions ? JSON.stringify(emotions) : null, duration || null);

  res.json({ id: result.lastInsertRowid });
});

app.get('/api/dashboard/squad-results', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const shares = db.prepare(`
    SELECT ss.*, us.video_name, us.verdict as original_verdict, us.confidence as original_confidence, us.score as original_score
    FROM squad_shares ss
    JOIN user_scans us ON ss.scan_id = us.id
    WHERE ss.shared_by = ?
    ORDER BY ss.created_at DESC LIMIT 20
  `).all(userId);

  const results = shares.map(share => {
    const verdicts = db.prepare(`
      SELECT fv.*, u.email FROM friend_verdicts fv
      JOIN users u ON fv.user_id = u.id
      WHERE fv.share_id = ?
    `).all(share.id);

    return { ...share, friendVerdicts: verdicts };
  });

  res.json({ results });
});

app.get('/api/dashboard/squad-impact', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const friendsProtected = db.prepare(
    'SELECT COUNT(DISTINCT fv.user_id) as count FROM friend_verdicts fv JOIN squad_shares ss ON fv.share_id = ss.id WHERE ss.shared_by = ?'
  ).get(userId);

  const sharesSent = db.prepare('SELECT COUNT(*) as count FROM squad_shares WHERE shared_by = ?').get(userId);

  const conversions = db.prepare('SELECT COUNT(*) as count FROM friend_codes WHERE user_id = ? AND used_by IS NOT NULL').get(userId);

  res.json({
    friendsProtected: friendsProtected.count,
    sharesSent: sharesSent.count,
    conversions: conversions.count
  });
});

app.get('/api/dashboard/invite-codes', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const currentMonth = new Date().toISOString().slice(0, 7);

  const codes = db.prepare('SELECT * FROM friend_codes WHERE user_id = ? ORDER BY created_at DESC').all(userId);
  const tracker = db.prepare('SELECT codes_generated FROM code_tracker WHERE user_id = ? AND month = ?').get(userId, currentMonth);

  res.json({
    codes,
    monthlyUsed: tracker ? tracker.codes_generated : 0,
    monthlyLimit: 5,
    currentMonth
  });
});

app.post('/api/dashboard/invite-codes', authenticateToken, (req, res) => {
  const userId = req.user.id;
  const currentMonth = new Date().toISOString().slice(0, 7);

  const tracker = db.prepare('SELECT codes_generated FROM code_tracker WHERE user_id = ? AND month = ?').get(userId, currentMonth);
  const used = tracker ? tracker.codes_generated : 0;

  if (used >= 5) return res.status(429).json({ error: 'Monthly invite code limit reached (5/month)' });

  const code = 'GUTCHECK' + Math.random().toString(36).substring(2, 6).toUpperCase();

  db.prepare('INSERT INTO friend_codes (user_id, code) VALUES (?, ?)').run(userId, code);
  db.prepare('INSERT INTO code_tracker (user_id, month, codes_generated) VALUES (?, ?, 1) ON CONFLICT(user_id, month) DO UPDATE SET codes_generated = codes_generated + 1')
    .run(userId, currentMonth);

  res.json({ code, monthlyUsed: used + 1, monthlyLimit: 5 });
});

app.post('/api/dashboard/redeem-code', authenticateToken, (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code required' });

  const invite = db.prepare('SELECT * FROM friend_codes WHERE code = ? AND used_by IS NULL').get(code);
  if (!invite) return res.status(404).json({ error: 'Invalid or already used code' });
  if (invite.user_id === req.user.id) return res.status(400).json({ error: 'Cannot redeem your own code' });

  db.prepare('UPDATE friend_codes SET used_by = ?, used_at = CURRENT_TIMESTAMP WHERE id = ?').run(req.user.id, invite.id);

  res.json({ success: true, message: 'Code redeemed successfully' });
});

app.get('/api/dashboard/activity', authenticateToken, (req, res) => {
  const userId = req.user.id;

  const scans = db.prepare(
    'SELECT id, video_name, verdict, confidence, score, created_at FROM user_scans WHERE user_id = ? ORDER BY created_at DESC LIMIT 10'
  ).all(userId);

  res.json({ activity: scans });
});

app.get('/api/dashboard/account', authenticateToken, (req, res) => {
  const user = db.prepare('SELECT id, email, plan, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(user);
});

app.put('/api/dashboard/account', authenticateToken, async (req, res) => {
  const { email, currentPassword, newPassword } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);

  if (email && email !== user.email) {
    const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (existing) return res.status(409).json({ error: 'Email already in use' });
    db.prepare('UPDATE users SET email = ? WHERE id = ?').run(email, req.user.id);
  }

  if (newPassword) {
    if (!currentPassword) return res.status(400).json({ error: 'Current password required' });
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hash, req.user.id);
  }

  const updated = db.prepare('SELECT id, email, plan, created_at FROM users WHERE id = ?').get(req.user.id);
  res.json(updated);
});

app.post('/api/dashboard/cancel-subscription', authenticateToken, (req, res) => {
  db.prepare("UPDATE users SET plan = 'free' WHERE id = ?").run(req.user.id);
  res.json({ success: true, message: 'Subscription cancelled. You now have a free plan.' });
});

// --------------- HTML fallback ---------------
// Catch-all: serve index.html for any unmatched route (SPA-style fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --------------- Start server ---------------
app.listen(PORT, () => {
  console.log(`GutCheck server running on port ${PORT}`);
});
