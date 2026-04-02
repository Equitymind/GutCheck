const express = require('express');
const path = require('path');
const nodemailer = require('nodemailer');
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const Database = require('better-sqlite3');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || 'gutcheck-dev-secret';

// --------------- Middleware ---------------
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

// --------------- HTML fallback ---------------
// Catch-all: serve index.html for any unmatched route (SPA-style fallback)
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// --------------- Start server ---------------
app.listen(PORT, () => {
  console.log(`GutCheck server running on port ${PORT}`);
});
