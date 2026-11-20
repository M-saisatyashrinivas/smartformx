import express from 'express';
import dotenv from 'dotenv';
import session from 'express-session';
import pool from './config/db.js';
import passport from './config/passport.js';
import authRoutes from './routes/auth.js';
import adminRoutes from './routes/admin.js';
import formRoutes from './routes/forms.js';
import whitelistRoutes from './routes/whitelist.js';
import submissionRoutes from './routes/submissions.js';

dotenv.config();

const app = express();

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

app.use(session({
  secret: 'formify-secret-key',
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// Automatically initialize database tables and seed Owner account on startup
const initDB = async () => {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS Users (
        UserID SERIAL PRIMARY KEY,
        Email VARCHAR(255) UNIQUE NOT NULL,
        Role VARCHAR(50) NOT NULL,
        CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS Forms (
        FormID SERIAL PRIMARY KEY,
        AdminID INT REFERENCES Users(UserID),
        FormTitle VARCHAR(255) NOT NULL,
        FormStructure JSONB NOT NULL,
        RequireWhitelist BOOLEAN DEFAULT FALSE,
        ExpiresAt TIMESTAMP,
        IsLive BOOLEAN DEFAULT TRUE,
        CreatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      CREATE TABLE IF NOT EXISTS Whitelists (
        WhitelistID SERIAL PRIMARY KEY,
        FormID INT REFERENCES Forms(FormID) ON DELETE CASCADE,
        StudentEmail VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS Blacklists (
        BlacklistID SERIAL PRIMARY KEY,
        FormID INT REFERENCES Forms(FormID) ON DELETE CASCADE,
        StudentEmail VARCHAR(255) NOT NULL
      );
      CREATE TABLE IF NOT EXISTS Submissions (
        SubmissionID SERIAL PRIMARY KEY,
        FormID INT REFERENCES Forms(FormID) ON DELETE CASCADE,
        StudentEmail VARCHAR(255) NOT NULL,
        ResponseData JSONB NOT NULL,
        SubmittedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE (FormID, StudentEmail)
      );
      INSERT INTO Users (Email, Role) 
      VALUES ('saisatyasrinivassatya@gmail.com', 'Owner') 
      ON CONFLICT (Email) DO UPDATE SET Role = 'Owner';
    `);
    console.log('Database verified and Owner configured: saisatyasrinivassatya@gmail.com');
  } catch (err) {
    console.error('Database initialization note:', err.message);
  }
};
initDB();

// Protect owner, admin, and responses pages dynamically based on database roles
app.get('/owner.html', async (req, res, next) => {
  if (!req.isAuthenticated() || !req.user || !req.user.emails || !req.user.emails[0]) {
    return res.redirect('/');
  }
  const sessionEmail = req.user.emails[0].value;
  try {
    const { rows } = await pool.query('SELECT role FROM Users WHERE Email = $1', [sessionEmail]);
    if (rows.length === 0 || rows[0].role !== 'Owner') {
      return res.redirect('/');
    }
    if (req.query.email !== sessionEmail) {
      return res.redirect(`/owner.html?email=${encodeURIComponent(sessionEmail)}`);
    }
    next();
  } catch (err) {
    res.redirect('/');
  }
});

app.get('/admin.html', async (req, res, next) => {
  if (!req.isAuthenticated() || !req.user || !req.user.emails || !req.user.emails[0]) {
    return res.redirect('/');
  }
  const sessionEmail = req.user.emails[0].value;
  try {
    const { rows } = await pool.query('SELECT role FROM Users WHERE Email = $1', [sessionEmail]);
    if (rows.length === 0 || (rows[0].role !== 'Admin' && rows[0].role !== 'Owner')) {
      return res.redirect('/');
    }
    if (req.query.email !== sessionEmail) {
      return res.redirect(`/admin.html?email=${encodeURIComponent(sessionEmail)}`);
    }
    next();
  } catch (err) {
    res.redirect('/');
  }
});

app.get('/responses.html', async (req, res, next) => {
  if (!req.isAuthenticated() || !req.user || !req.user.emails || !req.user.emails[0]) {
    return res.redirect('/');
  }
  next();
});

app.use(express.static('public'));

// Fast Access / Direct Login route (bypasses Google OAuth if keys are not ready)
app.get('/auth/quick-access', async (req, res) => {
  const email = req.query.email || 'saisatyasrinivassatya@gmail.com';
  try {
    const { rows } = await pool.query('SELECT * FROM Users WHERE Email = $1', [email]);
    const userRole = (rows.length > 0 && rows[0].role) ? rows[0].role : 'Owner';
    const user = {
      id: (rows.length > 0 && rows[0].userid) ? rows[0].userid : 1,
      emails: [{ value: email }],
      displayName: email.split('@')[0]
    };
    req.login(user, (err) => {
      if (err) return res.redirect('/');
      if (userRole === 'Owner') {
        return res.redirect(`/owner.html?email=${encodeURIComponent(email)}`);
      } else {
        return res.redirect(`/admin.html?email=${encodeURIComponent(email)}`);
      }
    });
  } catch (err) {
    console.error('Quick access error:', err);
    res.redirect('/');
  }
});

app.get('/auth/google',
  (req, res, next) => {
    const formId = req.query.formId;
    passport.authenticate('google', { 
      scope: ['profile', 'email'],
      state: formId
    })(req, res, next);
  }
);

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  async (req, res) => {
    const email = req.user.emails[0].value;
    const formId = req.query.state;
    
    if (formId) {
      return res.redirect(`/form.html?id=${formId}&email=${email}`);
    }
    
    const { rows } = await pool.query('SELECT * FROM Users WHERE Email = $1', [email]);
    
    if (rows.length === 0) {
      return res.send('<script>alert("Access denied. Contact owner."); window.location.href="/";</script>');
    }
    
    if (rows[0].role === 'Owner') {
      res.redirect('/owner.html?email=' + email);
    } else {
      res.redirect('/admin.html?email=' + email);
    }
  }
);

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/forms', formRoutes);
app.use('/api/whitelist', whitelistRoutes);
app.use('/api/submissions', submissionRoutes);

app.get('/', (req, res) => {
  res.sendFile('index.html', { root: 'public' });
});

const HOST = '0.0.0.0';
const PORT = process.env.PORT || 3000;

app.listen(PORT, HOST, () => {
  console.log(`Server running on http://${HOST}:${PORT}`);
});
