require('dotenv').config({ path: require('path').join(__dirname, '.env') });
const express      = require('express');
const path         = require('path');
const https        = require('node:https');
const fs           = require('node:fs');
const { Pool }     = require('pg');
const bcrypt       = require('bcryptjs');
const jwt          = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const crypto       = require('node:crypto');
const os           = require('node:os');

const JWT_SECRET = process.env.JWT_SECRET || 'insurancecontentai-change-this-secret';
const IS_SERVERLESS = !!(process.env.NETLIFY || process.env.AWS_LAMBDA_FUNCTION_NAME);

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '20mb' }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

// ─── TEAM PASSWORD GATE ───────────────────────────────────────────────────────
// When APP_PASSWORD is set (e.g. on Netlify), every /api, /auth and /admin call
// needs an unlock cookie, so strangers can't spend your AI credit.
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const GATE_SECRET  = JWT_SECRET + ':' + APP_PASSWORD; // changing the password logs everyone out
const sha = s => crypto.createHash('sha256').update(String(s)).digest();

function gateUnlocked(req) {
  if (!APP_PASSWORD) return true;
  try { jwt.verify(req.cookies?.gate || '', GATE_SECRET); return true; } catch { return false; }
}

app.post('/api/unlock', async (req, res) => {
  if (!APP_PASSWORD) return res.json({ ok: true });
  const ok = crypto.timingSafeEqual(sha(req.body?.password || ''), sha(APP_PASSWORD));
  if (!ok) {
    await new Promise(r => setTimeout(r, 1000)); // slow down guessing
    return res.status(403).json({ error: 'Wrong password' });
  }
  const token = jwt.sign({ gate: true }, GATE_SECRET, { expiresIn: '30d' });
  res.cookie('gate', token, {
    httpOnly: true, sameSite: 'lax', secure: req.secure || req.headers['x-forwarded-proto'] === 'https',
    maxAge: 30 * 24 * 3600 * 1000,
  });
  res.json({ ok: true });
});

app.use(['/api', '/auth', '/admin'], (req, res, next) => {
  if (req.path === '/unlock' || req.path === '/config' || gateUnlocked(req)) return next();
  res.status(401).json({ error: 'Locked — enter the team password', locked: true });
});

// ─── DATABASE ─────────────────────────────────────────────────────────────────
let pool = null;
if (process.env.DATABASE_URL) {
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('railway') || process.env.DATABASE_URL.includes('render')
      ? { rejectUnauthorized: false } : false
  });
  (async () => {
    try {
      await pool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id          SERIAL PRIMARY KEY,
          email       TEXT UNIQUE NOT NULL,
          password    TEXT NOT NULL,
          name        TEXT NOT NULL,
          created_at  TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS projects (
          id          SERIAL PRIMARY KEY,
          user_id     INTEGER REFERENCES users(id) ON DELETE CASCADE,
          data        JSONB NOT NULL,
          created_at  TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE TABLE IF NOT EXISTS dna (
          id          SERIAL PRIMARY KEY,
          user_id     INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
          data        JSONB NOT NULL,
          updated_at  TIMESTAMPTZ DEFAULT NOW()
        );
      `);
      console.log('✅ Database ready');
    } catch (err) { console.error('DB init error:', err.message); }
  })();
} else {
  console.log('⚠️  No DATABASE_URL — running without DB (auth disabled)');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  if (!pool) return next(); // no DB = auth disabled (local dev without DB)
  const token = req.cookies?.token || req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Not authenticated' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ─── APP CONFIG ───────────────────────────────────────────────────────────────
app.get('/api/config', (req, res) => {
  res.json({
    allowRegistration: process.env.ALLOW_REGISTRATION === 'true',
    authEnabled: !!pool,
    gateEnabled: !!APP_PASSWORD,
    unlocked: gateUnlocked(req)
  });
});

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/auth/register', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not configured' });
  if (process.env.ALLOW_REGISTRATION !== 'true')
    return res.status(403).json({ error: 'Registration is currently closed. Contact your admin.' });
  const { email, password, name } = req.body;
  if (!email || !password || !name)
    return res.status(400).json({ error: 'Name, email and password are required' });
  if (password.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO users (email, password, name) VALUES ($1,$2,$3) RETURNING id,email,name',
      [email.toLowerCase().trim(), hash, name.trim()]
    );
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, name: rows[0].name }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ user: rows[0] });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Email already registered' });
    res.status(500).json({ error: err.message });
  }
});

app.post('/auth/login', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not configured' });
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  try {
    const { rows } = await pool.query('SELECT * FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!rows.length || !(await bcrypt.compare(password, rows[0].password)))
      return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: rows[0].id, email: rows[0].email, name: rows[0].name }, JWT_SECRET, { expiresIn: '30d' });
    res.cookie('token', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 30 * 24 * 60 * 60 * 1000 });
    res.json({ user: { id: rows[0].id, email: rows[0].email, name: rows[0].name } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/auth/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

app.get('/auth/me', requireAuth, (req, res) => {
  if (!req.user) return res.json({ user: null, authEnabled: false });
  res.json({ user: req.user, authEnabled: true });
});

// ─── USER DATA ROUTES ─────────────────────────────────────────────────────────
app.get('/api/user/projects', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.json({ projects: [] });
  try {
    const { rows } = await pool.query(
      'SELECT id, data, created_at FROM projects WHERE user_id=$1 ORDER BY created_at DESC',
      [req.user.id]
    );
    res.json({ projects: rows.map(r => ({ ...r.data, _dbId: r.id, _createdAt: r.created_at })) });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/user/projects', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.json({ id: null });
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'data required' });
    const { rows } = await pool.query(
      'INSERT INTO projects (user_id, data) VALUES ($1,$2) RETURNING id, created_at',
      [req.user.id, JSON.stringify(data)]
    );
    res.json({ id: rows[0].id, createdAt: rows[0].created_at });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/user/projects/:id', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.json({ ok: true });
  try {
    await pool.query('DELETE FROM projects WHERE id=$1 AND user_id=$2', [req.params.id, req.user.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/user/dna', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.json({ dna: null });
  try {
    const { rows } = await pool.query('SELECT data FROM dna WHERE user_id=$1', [req.user.id]);
    res.json({ dna: rows[0]?.data || null });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/user/dna', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.json({ ok: true });
  try {
    const { data } = req.body;
    if (!data) return res.status(400).json({ error: 'data required' });
    await pool.query(`
      INSERT INTO dna (user_id, data, updated_at) VALUES ($1,$2,NOW())
      ON CONFLICT (user_id) DO UPDATE SET data=$2, updated_at=NOW()
    `, [req.user.id, JSON.stringify(data)]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── CHANGE PASSWORD ──────────────────────────────────────────────────────────
app.post('/auth/change-password', requireAuth, async (req, res) => {
  if (!pool || !req.user) return res.status(503).json({ error: 'Auth not available' });
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Both fields required' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'New password must be at least 6 characters' });
  try {
    const { rows } = await pool.query('SELECT password FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(404).json({ error: 'User not found' });
    const valid = await bcrypt.compare(currentPassword, rows[0].password);
    if (!valid) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, req.user.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ADMIN RESET PASSWORD ─────────────────────────────────────────────────────
app.post('/admin/reset-password', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not configured' });
  const adminSecret = process.env.ADMIN_SECRET;
  if (!adminSecret) return res.status(503).json({ error: 'ADMIN_SECRET not configured in environment' });
  const { secret, email, newPassword } = req.body;
  if (!secret || !email || !newPassword) return res.status(400).json({ error: 'secret, email and newPassword required' });
  if (secret !== adminSecret) return res.status(403).json({ error: 'Invalid admin secret' });
  if (newPassword.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  try {
    const { rows } = await pool.query('SELECT id, email, name FROM users WHERE email=$1', [email.toLowerCase().trim()]);
    if (!rows.length) return res.status(404).json({ error: 'No user found with that email' });
    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, rows[0].id]);
    res.json({ ok: true, message: `Password reset for ${rows[0].name} (${rows[0].email})` });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── ADMIN LIST USERS ─────────────────────────────────────────────────────────
app.get('/admin/users', async (req, res) => {
  if (!pool) return res.status(503).json({ error: 'Database not configured' });
  const adminSecret = process.env.ADMIN_SECRET;
  if (!adminSecret) return res.status(503).json({ error: 'ADMIN_SECRET not configured' });
  const secret = req.query.secret;
  if (secret !== adminSecret) return res.status(403).json({ error: 'Invalid admin secret' });
  try {
    const { rows } = await pool.query('SELECT id, name, email, created_at FROM users ORDER BY created_at DESC');
    res.json({ users: rows });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Temp image folder for Instagram (needs a publicly accessible URL)
// (serverless hosts have a read-only app folder, so fall back to the OS temp dir)
const tempImagesDir = IS_SERVERLESS
  ? path.join(os.tmpdir(), 'temp-images')
  : path.join(__dirname, 'public', 'temp-images');
if (!fs.existsSync(tempImagesDir)) fs.mkdirSync(tempImagesDir, { recursive: true });

// ── Auto-detect provider from available API keys ───────────────────
// Priority: DEEPSEEK → OPENAI → ANTHROPIC
// Or set AI_PROVIDER explicitly in .env (deepseek / openai / anthropic)
function detectProvider() {
  const explicit = (process.env.AI_PROVIDER || '').toLowerCase();
  if (explicit) return explicit;
  if (process.env.DEEPSEEK_API_KEY)  return 'deepseek';
  if (process.env.OPENAI_API_KEY)    return 'openai';
  if (process.env.ANTHROPIC_API_KEY) return 'anthropic';
  return null;
}

const PROVIDER = detectProvider();
let client, MODEL, isOpenAICompat;

if (PROVIDER === 'openai') {
  const { OpenAI } = require('openai');
  if (!process.env.OPENAI_API_KEY) {
    console.error('\n❌  OPENAI_API_KEY not found in .env\n'); process.exit(1);
  }
  client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
  MODEL  = 'gpt-4o-mini';
  isOpenAICompat = true;
  console.log('🤖 Provider: OpenAI  |  Model: gpt-4o-mini');

} else if (PROVIDER === 'deepseek') {
  const { OpenAI } = require('openai');
  if (!process.env.DEEPSEEK_API_KEY) {
    console.error('\n❌  DEEPSEEK_API_KEY not found in .env\n'); process.exit(1);
  }
  client = new OpenAI({ apiKey: process.env.DEEPSEEK_API_KEY, baseURL: 'https://api.deepseek.com' });
  MODEL  = 'deepseek-chat';
  isOpenAICompat = true;
  console.log('🤖 Provider: DeepSeek  |  Model: deepseek-chat');

} else if (PROVIDER === 'anthropic') {
  const Anthropic = require('@anthropic-ai/sdk');
  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('\n❌  ANTHROPIC_API_KEY not found in .env\n'); process.exit(1);
  }
  client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  MODEL  = 'claude-haiku-4-5-20251001';
  isOpenAICompat = false;
  console.log('🤖 Provider: Anthropic  |  Model: claude-haiku-4-5');

} else {
  console.error('\n❌  No API key found in .env!');
  console.error('    Add one of: ANTHROPIC_API_KEY, OPENAI_API_KEY, or DEEPSEEK_API_KEY\n');
  process.exit(1);
}

// Language display names
const LANG_NAMES = {
  en: 'English',
  zh: 'Simplified Chinese (简体中文)',
  my: 'Bahasa Malaysia (Malay)',
  ta: 'Tamil (தமிழ்)',
};

// ── Streaming helper (works for all 3 providers) ───────────────────
async function streamResponse(res, system, prompt) {
  res.setHeader('Content-Type',      'text/event-stream');
  res.setHeader('Cache-Control',     'no-cache');
  res.setHeader('Connection',        'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  res.flushHeaders();

  const send = (obj) => res.write(`data: ${JSON.stringify(obj)}\n\n`);

  try {
    if (isOpenAICompat) {
      // OpenAI or DeepSeek
      const stream = await client.chat.completions.create({
        model:      MODEL,
        max_tokens: 4096,
        messages: [
          { role: 'system', content: system },
          { role: 'user',   content: prompt },
        ],
        stream: true,
      });
      for await (const chunk of stream) {
        const text = chunk.choices[0]?.delta?.content || '';
        if (text) send({ type: 'text', text });
      }
    } else {
      // Anthropic
      const stream = client.messages.stream({
        model:      MODEL,
        max_tokens: 4096,
        system,
        messages: [{ role: 'user', content: prompt }],
      });
      stream.on('text', (text) => send({ type: 'text', text }));
      await stream.finalMessage();
    }
    send({ type: 'done' });
  } catch (err) {
    send({ type: 'error', message: err.message });
  }
  res.end();
}

// ── STYLE DNA — Scrape public profile via Jina AI ─────────────────
app.post('/api/scrape-profile', async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'URL required' });
  try {
    const jinaUrl  = `https://r.jina.ai/${url}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    const r = await fetch(jinaUrl, {
      headers: { 'Accept': 'text/plain', 'X-Return-Format': 'text' },
      signal: controller.signal,
    });
    clearTimeout(timer);
    if (!r.ok) return res.status(400).json({ error: `Could not fetch page (${r.status}). It may require login.` });
    const raw = await r.text();
    if (/sign.?in|log.?in|join now|create account|authwall/i.test(raw.slice(0, 1000))) {
      return res.status(403).json({ error: 'This page requires login. Please paste your posts manually.' });
    }
    const lines = raw.split('\n').map(l => l.trim())
      .filter(l => l.length > 40)
      .filter(l => !/^https?:\/\//i.test(l))
      .slice(0, 120);
    res.json({ content: lines.join('\n\n'), lineCount: lines.length });
  } catch (err) {
    const msg = err.name === 'AbortError' ? 'Request timed out — paste posts manually.' : err.message;
    res.status(500).json({ error: msg });
  }
});

// ── STYLE DNA — Analyze writing style ─────────────────────────────
app.post('/api/analyze-style', async (req, res) => {
  const { facebookPosts, linkedinPosts, name } = req.body;
  const allPosts = [];
  if (facebookPosts?.trim()) allPosts.push(`=== FACEBOOK POSTS ===\n${facebookPosts.trim()}`);
  if (linkedinPosts?.trim()) allPosts.push(`=== LINKEDIN POSTS ===\n${linkedinPosts.trim()}`);
  if (!allPosts.length) return res.status(400).json({ error: 'No posts provided' });

  await streamResponse(
    res,
    `You are an elite ghostwriter and writing style analyst. Your job is to study someone's actual social media posts and extract every detail of their unique voice — so precisely that future AI-generated content is indistinguishable from their real writing. Be specific with real examples from the posts, not generic descriptions.`,
    `Study every single post below written by ${name || 'this insurance advisor'} and produce a detailed Writing Style DNA profile. Pull REAL examples and quotes from the posts to illustrate each point.

${allPosts.join('\n\n')}

---
Return in this exact markdown format, filling every field with SPECIFIC observations and ACTUAL examples from the posts above:

## 🧬 Writing Style DNA — ${name || 'Agent Profile'}

### 🎙️ Tone & Voice
- **Overall Tone:** (e.g. warm and conversational / authoritative / motivational)
- **Energy Level:** (e.g. calm and reassuring / high-energy / thoughtful)
- **Personality:** (e.g. relatable friend / trusted expert / storyteller)
- **Real example of tone:** (quote a line that best shows their voice)

### 📐 Sentence & Structure
- **Sentence Length:** (e.g. short punchy sentences under 10 words / medium / mix)
- **Paragraph Style:** (e.g. 1-sentence paragraphs / 2–3 lines / long blocks)
- **Line breaks:** (e.g. uses lots of white space / dense paragraphs)
- **Formatting Habits:** (e.g. uses bold, lists, numbers, dashes)

### 😊 Emoji Usage
- **Frequency:** (Heavy 5+/post / Moderate 2–4 / Minimal 0–1)
- **Placement:** (e.g. start of line, mid-sentence, end of post)
- **Commonly used emojis:** (list the actual emojis they use most)

### #️⃣ Hashtag Style
- **Count per post:** (e.g. 3–5 / 6–10 / none)
- **Placement:** (end of post / inline within text)
- **Language of hashtags:** (English / Malay / mix)
- **Common hashtag themes:** (list examples)

### 🪝 Hook Patterns (how posts OPEN)
- **Primary hook style:** (question / bold statement / personal story / surprising fact)
- **Signature openers:** (list 2–3 real opening lines from their posts)

### 📣 CTA & Closing Style
- **CTA type:** (soft question / direct call / reflection prompt / no CTA)
- **Signature closing phrases:** (quote actual endings from their posts)

### 📖 Vocabulary & Language
- **Language mix:** (e.g. pure English / pure Malay / Manglish / mix)
- **Formality:** (casual slang / semi-formal / professional)
- **Recurring words/phrases they love:** (list real examples)
- **Words/phrases they NEVER use:** (based on observation)

### 📏 Post Length & Format
- **Typical length:** (short <80w / medium 80–200w / long 200w+)
- **Format preference:** (flowing prose / bullet lists / numbered points / hybrid)

### ✨ Signature Style Markers
- **What makes their writing instantly recognisable:**
- **Recurring themes or values:**
- **Their unique storytelling approach:**

### 🎯 AI Replication Instructions
When writing content in this person's style:
- DO: (list 5 specific things to always do)
- AVOID: (list 5 specific things to never do)
- Sample opening line in their style:
- Sample closing line in their style:

---
*Style DNA captured from ${allPosts.length > 1 ? 'Facebook + LinkedIn' : 'social media'} posts by ${name || 'this agent'}.*`
  );
});

// ── STEP 1 — 7-Day Content Calendar ───────────────────────────────
app.post('/api/calendar', async (req, res) => {
  const name         = (req.body.agentName || '').trim() || 'an insurance advisor';
  const lang         = LANG_NAMES[req.body.language] || 'English';
  const styleProfile = (req.body.styleProfile || '').trim();
  const langNote     = `CRITICAL REQUIREMENT: You MUST write ALL content — including every table header, content theme, hook, key message, CTA, and any other text — ENTIRELY in ${lang}. Do not use any other language.`;
  const styleNote    = styleProfile
    ? `\n\nWRITING STYLE: Use the following Style DNA profile to shape the tone, hooks, and CTAs in the calendar:\n${styleProfile}`
    : '';

  await streamResponse(
    res,
    `You are an expert insurance content strategist and social media manager. You always use proper markdown table formatting. ${langNote}`,
    `${langNote}

Create a 7-day social media content calendar for ${name}.

Format as a clean markdown table with EXACTLY these columns (translate the column headers to ${lang}):
| Day | Content Theme | Post Topic / Hook | Key Message | Post Format | CTA |

Content Theme options (write in ${lang}): Education, Myth-Busting, Emotional Storytelling, Tips

Topics must cover a mix of:
• Financial security for children
• Medical protection
• Future planning (retirement, education fund)
• Common insurance misconceptions
• Real-life emotional angles (family, protection, peace of mind)

Post Format: each row must say either "Static Post" or "Reel" (write in ${lang})
Audience: Young Parents/Families AND Working Professionals planning for financial security
Tone: Warm, professional, reassuring — NO hard selling
${styleNote}

Generate the complete 7-day calendar table now. ${langNote}`
  );
});

// ── STEP 2 — Draft Social Media Post ──────────────────────────────
app.post('/api/post', async (req, res) => {
  const { calendarContent, dayNumber, agentName, language, styleProfile } = req.body;
  const name       = (agentName || '').trim() || 'an insurance advisor';
  const lang       = LANG_NAMES[language] || 'English';
  const langNote   = `CRITICAL REQUIREMENT: Write the ENTIRE post — every word, sentence, emoji caption, and hashtag description — in ${lang} only.`;
  const styleNote  = (styleProfile || '').trim()
    ? `\n\n════ STYLE DNA — HIGHEST PRIORITY ════
You are ghostwriting for ${name}. You MUST write this post so it sounds EXACTLY like them — not like a generic AI post.
Follow the "AI Replication Instructions" in the Style DNA below. Use their actual vocabulary, sentence rhythm, emoji patterns, hook style, and closing phrases.
A reader who knows ${name} personally should not be able to tell the difference.

${styleProfile}
════════════════════════════════════`
    : '';

  await streamResponse(
    res,
    `You are an expert social media copywriter specializing in insurance and financial advisory content. ${langNote}`,
    `${langNote}

Using the 7-day content calendar below, write a complete ready-to-publish social media post for Day ${dayNumber}.

CALENDAR:
${calendarContent}

Structure the post using these 3 sections IN ORDER, but DO NOT include any section headers or labels (no "HOOK", "VALUE", "CALL-TO-ACTION", or any translated equivalents) — write it as one seamless flowing post:

1. HOOK (do not print this label): A surprising or thought-provoking opening that stops the scroll. 1–2 sentences max.

2. VALUE (do not print this label): An educational insight, myth-busting explanation, or emotional story tied to Day ${dayNumber}'s topic. 3–5 short paragraphs.

3. CALL-TO-ACTION (do not print this label): A soft CTA — a reflective question, invite to comment, or prompt to save/share.

End with one engaging question on its own line to spark comments.
Add relevant emoji throughout. Add 6–8 hashtags at the end.
IMPORTANT: Output only the post content — no section headers, no labels, no structural markers.

Written for: ${name}
Tone: Professional, empathetic — NOT salesy
Audience: Young parents and working adults who care about family protection
${styleNote}
${langNote}`
  );
});

// ── STEP 3a — Image Prompt (always English) ───────────────────────
app.post('/api/image-prompt', async (req, res) => {
  const { postCaption } = req.body;
  // Image prompts are always generated in English for best AI image tool compatibility

  await streamResponse(
    res,
    'You are an expert AI image prompt engineer specializing in lifestyle, family, and professional photography for social media in Southeast Asia.',
    `Based on the insurance post caption below, generate ONE detailed image generation prompt in English.

POST CAPTION:
${postCaption}

The prompt must include:
• People: Southeast Asian appearance — warm medium skin tones, dark hair, East/Southeast Asian facial features; authentic, natural-looking faces
• Setting: Malaysian or Southeast Asian environment — modern Malaysian home, city café, suburban neighbourhood, hospital, office, or outdoor park in a tropical setting
• Clothing: appropriate Malaysian everyday attire — e.g. modest traditional or smart casual wear, business attire; culturally appropriate
• Emotional mood: warm, calm, hopeful, confident, reassuring
• Visual style: photorealistic lifestyle photography OR soft cinematic
• Color palette: warm soft tones, gentle blues, natural light — nothing cold or clinical
• Composition: framing, depth of field, subject placement
• Platform: optimized for Instagram/Facebook square or portrait (1:1 or 4:5 ratio)

Requirements:
✓ Human-centric — real-looking Southeast Asian people, genuine emotions
✓ Family-friendly and brand-safe
✓ Culturally authentic — looks like it was shot in Malaysia
✗ DO NOT mention any specific ethnicity, race, or nationality of people
✗ NO Western or non-Asian faces
✗ NO fear-based, dark, dramatic, or negative imagery
✗ NO text overlays in the image

Output ONLY the image prompt text in English — no title, no explanation.
Ready to paste into Midjourney, DALL·E 3, Gemini Imagen, or Dreamina.`
  );
});

// ── STEP 3b — Video Script (always English) ──────────────────────
app.post('/api/video-script', async (req, res) => {
  const { postCaption, agentName } = req.body;
  const name = (agentName || '').trim() || 'an insurance advisor';
  // Video scripts are always generated in English

  await streamResponse(
    res,
    'You are an expert short-form video script writer for insurance agents and financial advisors in Malaysia. Write all scripts in English.',
    `Based on the post caption below, write a first-person talking-head video script in English for Instagram Reels / TikTok / YouTube Shorts.

IMPORTANT — Asian context: The speaker is a Malaysian insurance advisor (${name}). The audience is everyday Malaysians — families, young working adults, couples. Use relatable Malaysian life references (e.g. school fees, ageing parents, kampung, EPF, hospital bills) where natural. Keep language simple and warm.

POST CAPTION:
${postCaption}

Format with these clearly labelled sections:

⏱️ OPENING HOOK — 0 to 3 seconds
[ON-SCREEN TEXT: what appears on screen]
SPOKEN: the actual words spoken aloud here

📹 CORE MESSAGE — 4 to 50 seconds
SPOKEN: first spoken sentence
[B-ROLL: optional visual cue]
SPOKEN: next spoken sentence [PAUSE]
SPOKEN: continue spoken content

🎯 CLOSE + SOFT CTA — last 5 to 10 seconds
SPOKEN: closing words and soft call to action

Rules:
• EVERY line of spoken dialogue must start with SPOKEN:
• Stage directions go inside [square brackets] on their own line
• First person ("I", "you") throughout
• Speaker: ${name}
• 30–60 seconds when spoken aloud
• Tone: warm, confident, empathetic advisor
• Write entirely in English`
  );
});

// ── Dreamina AI video drama script ─────────────────────────────────
app.post('/api/dreamina-script', async (req, res) => {
  const { postCaption, agentName } = req.body;
  const name = (agentName || '').trim() || 'an insurance advisor';

  await streamResponse(
    res,
    'You are an expert cinematic video scriptwriter specialising in short-form AI-generated drama videos for Malaysian social media. Write all scripts in English.',
    `Based on the insurance post caption below, write a cinematic drama video script for AI video generation using Dreamina / CapCut AI.

POST CAPTION:
${postCaption}

═══════════════════════════════════════
STEP 1 — DEFINE CHARACTERS & SETTING
═══════════════════════════════════════
Before writing scenes, define the following and keep them IDENTICAL in every scene:

CHARACTER PROFILES:
• List 1–3 characters. For each:
  - Malaysian name, age, ethnicity (Malay / Chinese / Indian — choose ONE that fits the story)
  - Physical: dark black hair, Southeast Asian skin tone, facial features; specific build
  - Attire: exact Malaysian clothing with colours and accessories — e.g. baju kurung, batik shirt, casual t-shirt with jeans, office wear (must not change between scenes)
  - No Western or non-Asian appearance

ENVIRONMENT:
• Distinctly Malaysian/Southeast Asian location — e.g. modern Malaysian terraced house interior, Malaysian city café with local signage, government hospital corridor, suburban pasar malam, office in KL
• Time of day and lighting (e.g. late afternoon, warm golden tropical light through windows)
• Key Malaysian props / recurring visual elements (e.g. framed family photo, songkok on shelf, thermos of teh tarik, Malaysian ringgit notes, school report card)

═══════════════════════════════════════
STEP 2 — WRITE 3–5 SCENES
═══════════════════════════════════════
Each scene must follow this exact structure:

SCENE [N] — [SCENE TITLE] ([duration, e.g. 0–4s])
[VISUAL: what the camera sees — reference characters by name, use their defined attire and setting]
[CAMERA: movement, e.g. slow zoom in, wide shot, close-up on hands]
[MOOD: atmosphere and colour grade, e.g. warm amber tones, soft bokeh background]
[ACTION: exactly what each character is doing, with specific body language]
[DIALOGUE: "one short spoken line if needed — emotionally resonant"]
[TEXT ON SCREEN: overlay text if needed]

Consistency rules:
• Characters wear EXACTLY the same clothes in every scene — never change attire
• Same location and lighting style throughout unless a scene explicitly transitions
• Reference characters by name in every scene, not as "the man" or "she"
• Props introduced in Scene 1 must reappear where relevant in later scenes
• All characters must look authentically Malaysian/Southeast Asian in every scene description
• Total video: 30–60 seconds
• Tone: emotional, warm, cinematic — everyday Malaysian family story
• End with a moment of relief or hope that ties back to insurance/financial protection
• Write entirely in English`
  );
});

// ── Translate existing content ─────────────────────────────────────
app.post('/api/translate', async (req, res) => {
  const { content, language } = req.body;
  const lang = LANG_NAMES[language] || 'English';

  await streamResponse(
    res,
    'You are a professional translator specializing in insurance and financial content for social media. You translate accurately while preserving all formatting.',
    `Translate the following content to ${lang}.

STRICT RULES — follow exactly:
1. Preserve ALL markdown formatting: table pipes |, separator rows ---, bold **, headers #, bullet points -, etc.
2. If content is a markdown table, keep the EXACT same table structure with same number of rows and columns
3. Translate ALL text to ${lang} including table headers, cell content, post body, hooks, and CTAs
4. Keep all emoji exactly as-is
5. For hashtags: translate or adapt them to natural ${lang} equivalents
6. Do NOT add any introduction, explanation, or preamble
7. Output ONLY the translated content — nothing else

CONTENT TO TRANSLATE:
${content}`
  );
});

// ── Enhance prompt with Malaysian/Asian context if humans are involved
function enhanceImagePrompt(prompt) {
  const humanKeywords = [
    'person', 'people', 'man', 'woman', 'men', 'women', 'family', 'couple',
    'agent', 'customer', 'client', 'advisor', 'professional', 'businessman',
    'businesswoman', 'employee', 'staff', 'team', 'group', 'individual',
    'father', 'mother', 'parent', 'child', 'senior', 'elderly', 'adult',
    'he ', 'she ', 'his ', 'her ', 'him ', 'they ', 'their ',
    'face', 'portrait', 'smile', 'smiling', 'sitting', 'standing',
    'orang', 'lelaki', 'perempuan', 'wanita', 'pria',
  ];
  const lower = prompt.toLowerCase();
  const hasHuman = humanKeywords.some(kw => lower.includes(kw));
  if (!hasHuman) return prompt;
  return prompt + ', East Asian and Southeast Asian appearance, modern urban Malaysian setting, photorealistic';
}

// ── Which image/video providers are configured? ───────────────────
app.get('/api/image-providers', (_req, res) => {
  res.json({
    dalle:    !!process.env.OPENAI_API_KEY,
    seedream: !!process.env.SEEDREAM_API_KEY,
    gemini:   !!process.env.GEMINI_API_KEY,
    heygen:   !!process.env.HEYGEN_API_KEY,
  });
});

// ── Generate Image ────────────────────────────────────────────────
// provider param: 'dalle' | 'seedream' | 'gemini'
// If omitted, auto-detects from available keys (dalle → seedream → gemini)
app.post('/api/generate-image', async (req, res) => {
  const { imagePrompt, referenceImages, provider } = req.body;
  // referenceImages: [{data, mimeType}, ...] or legacy single fields
  const refImgs = Array.isArray(referenceImages) && referenceImages.length ? referenceImages : [];
  const enhancedPrompt = enhanceImagePrompt(imagePrompt);

  const useProvider = provider || (
    process.env.OPENAI_API_KEY   ? 'dalle'    :
    process.env.SEEDREAM_API_KEY ? 'seedream' :
    process.env.GEMINI_API_KEY   ? 'gemini'   : null
  );

  // ── GPT Image 2 ──────────────────────────────────────────────────
  if (useProvider === 'dalle') {
    if (!process.env.OPENAI_API_KEY) return res.status(400).json({ error: 'OPENAI_API_KEY not set in .env' });
    try {
      const { OpenAI, toFile } = require('openai');
      const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
      let response;
      if (refImgs.length) {
        // Use images.edit with reference images
        const imageFiles = await Promise.all(refImgs.map((img, i) =>
          toFile(Buffer.from(img.data, 'base64'), `ref${i}.png`, { type: img.mimeType || 'image/png' })
        ));
        response = await openai.images.edit({
          model:   'gpt-image-2',
          image:   imageFiles.length === 1 ? imageFiles[0] : imageFiles,
          prompt:  enhancedPrompt,
          n:       1,
          size:    '1024x1024',
        });
      } else {
        response = await openai.images.generate({
          model:   'gpt-image-2',
          prompt:  enhancedPrompt,
          n:       1,
          size:    '1024x1024',
          quality: 'high',
        });
      }
      return res.json({ imageData: response.data[0].b64_json, mimeType: 'image/png', source: 'gpt-image-2' });
    } catch (err) {
      return res.status(500).json({ error: `GPT Image 2 error: ${err.message}` });
    }
  }

  // ── SeedDream / Dreamina ──────────────────────────────────────────
  if (useProvider === 'seedream') {
    if (!process.env.SEEDREAM_API_KEY) return res.status(400).json({ error: 'SEEDREAM_API_KEY not set in .env' });
    try {
      const baseUrl = (process.env.SEEDREAM_BASE_URL || 'https://api.laozhang.ai').replace(/\/$/, '');
      const model   = process.env.SEEDREAM_MODEL || 'seedream-4-0-250828';
      const parsed  = new URL(baseUrl);

      const payload = {
        model,
        prompt:          enhancedPrompt,
        n:               1,
        response_format: 'url',
        size:            '1K',
        watermark:       false,
      };
      if (refImgs.length) {
        // SeedDream supports one reference image — use the first
        payload.image = `data:${refImgs[0].mimeType || 'image/jpeg'};base64,${refImgs[0].data}`;
      }
      const body = JSON.stringify(payload);

      const result = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: parsed.hostname,
          path:     '/v1/images/generations',
          method:   'POST',
          headers:  { 'Content-Type': 'application/json', 'Authorization': `Bearer ${process.env.SEEDREAM_API_KEY}`, 'Content-Length': Buffer.byteLength(body) },
        }, (r) => {
          let data = '';
          r.on('data', c => { data += c; });
          r.on('end', () => {
            try {
              const json = JSON.parse(data);
              if (json.error) reject(new Error(json.error.message || JSON.stringify(json.error)));
              else resolve(json);
            } catch { reject(new Error('SeedDream parse error: ' + data.slice(0, 300))); }
          });
        });
        req.on('error', reject);
        req.write(body);
        req.end();
      });

      const imageUrl = result.data?.[0]?.url;
      if (!imageUrl) throw new Error('SeedDream did not return an image URL. Check your API key and model name.');

      const imgParsed = new URL(imageUrl);
      const imageBase64 = await new Promise((resolve, reject) => {
        https.get({ hostname: imgParsed.hostname, path: imgParsed.pathname + (imgParsed.search || ''), headers: { 'User-Agent': 'InsuranceApp/1.0' } }, (r) => {
          const chunks = [];
          r.on('data', c => chunks.push(c));
          r.on('end', () => resolve(Buffer.concat(chunks).toString('base64')));
        }).on('error', reject);
      });

      return res.json({ imageData: imageBase64, mimeType: 'image/jpeg', source: 'seedream' });
    } catch (err) {
      return res.status(500).json({ error: `SeedDream error: ${err.message}` });
    }
  }

  // ── Gemini (gemini-2.0-flash-exp, image generation via v1beta) ───
  if (useProvider === 'gemini') {
    if (!process.env.GEMINI_API_KEY) return res.status(400).json({ error: 'GEMINI_API_KEY not set in .env' });
    try {
      const model   = process.env.GEMINI_IMAGE_MODEL || 'gemini-2.0-flash-exp';
      const apiKey  = process.env.GEMINI_API_KEY;
      const parts = [{ text: enhancedPrompt }];
      refImgs.forEach(img => {
        parts.push({ inlineData: { mimeType: img.mimeType || 'image/jpeg', data: img.data } });
      });
      const gemBody = JSON.stringify({
        contents: [{ parts }],
        generationConfig: { responseModalities: ['IMAGE', 'TEXT'] },
      });
      const gemResult = await new Promise((resolve, reject) => {
        const req = https.request({
          hostname: 'generativelanguage.googleapis.com',
          path:     `/v1beta/models/${model}:generateContent?key=${apiKey}`,
          method:   'POST',
          headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(gemBody) },
        }, (r) => {
          let data = '';
          r.on('data', c => { data += c; });
          r.on('end', () => {
            try { resolve(JSON.parse(data)); }
            catch { reject(new Error('Gemini parse error: ' + data.slice(0, 300))); }
          });
        });
        req.on('error', reject);
        req.write(gemBody);
        req.end();
      });

      if (gemResult.error) throw new Error(gemResult.error.message || JSON.stringify(gemResult.error));
      const resParts = gemResult.candidates?.[0]?.content?.parts || [];
      const imgPart  = resParts.find(p => p.inlineData?.mimeType?.startsWith('image/'));
      if (!imgPart) throw new Error('Gemini did not return an image. This model requires billing to be enabled on your Google account.');

      return res.json({ imageData: imgPart.inlineData.data, mimeType: imgPart.inlineData.mimeType, source: 'gemini' });
    } catch (err) {
      return res.status(500).json({ error: `Gemini error: ${err.message}` });
    }
  }

  res.status(400).json({
    error: 'No image API key found. Add OPENAI_API_KEY, SEEDREAM_API_KEY, or GEMINI_API_KEY to your .env file.',
  });
});

// ── Social Media Helpers ──────────────────────────────────────────

// Reusable HTTPS request → resolves with parsed JSON
function httpsReq(options, body) {
  return new Promise((resolve, reject) => {
    const req = https.request(options, (r) => {
      let data = '';
      r.on('data', c => { data += c; });
      r.on('end', () => {
        try { resolve(JSON.parse(data)); }
        catch { resolve({ _raw: data, _status: r.statusCode }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Which platforms are configured?
app.get('/api/social-status', (_req, res) => {
  res.json({
    facebook:  !!(process.env.FACEBOOK_PAGE_ID && process.env.FACEBOOK_PAGE_ACCESS_TOKEN),
    instagram: !!(process.env.INSTAGRAM_USER_ID && process.env.INSTAGRAM_ACCESS_TOKEN),
    linkedin:  !!(process.env.LINKEDIN_ACCESS_TOKEN && process.env.LINKEDIN_AUTHOR),
  });
});

// ── POST to Facebook ──────────────────────────────────────────────
app.post('/api/post-facebook', async (req, res) => {
  const { text, imageData, mimeType } = req.body;
  const pageId = process.env.FACEBOOK_PAGE_ID;
  const token  = process.env.FACEBOOK_PAGE_ACCESS_TOKEN;
  if (!pageId || !token) {
    return res.status(400).json({ error: 'Facebook not configured. Add FACEBOOK_PAGE_ID and FACEBOOK_PAGE_ACCESS_TOKEN to .env' });
  }
  try {
    if (imageData) {
      // Photo post via multipart/form-data — no public URL needed
      const imgBuf   = Buffer.from(imageData, 'base64');
      const ext      = (mimeType || 'image/jpeg').split('/')[1] || 'jpg';
      const boundary = 'fb' + Date.now().toString(16);
      const body = Buffer.concat([
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="access_token"\r\n\r\n${token}\r\n`),
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="caption"\r\n\r\n${text}\r\n`),
        Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="source"; filename="image.${ext}"\r\nContent-Type: ${mimeType || 'image/jpeg'}\r\n\r\n`),
        imgBuf,
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]);
      const result = await httpsReq({
        hostname: 'graph.facebook.com',
        path:     `/v19.0/${pageId}/photos`,
        method:   'POST',
        headers:  { 'Content-Type': `multipart/form-data; boundary=${boundary}`, 'Content-Length': body.length },
      }, body);
      if (result.error) throw new Error(result.error.message || JSON.stringify(result.error));
      return res.json({ success: true, postId: result.id });
    } else {
      // Text-only post
      const body = JSON.stringify({ message: text, access_token: token });
      const result = await httpsReq({
        hostname: 'graph.facebook.com',
        path:     `/v19.0/${pageId}/feed`,
        method:   'POST',
        headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) },
      }, Buffer.from(body));
      if (result.error) throw new Error(result.error.message || JSON.stringify(result.error));
      return res.json({ success: true, postId: result.id });
    }
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── POST to Instagram ─────────────────────────────────────────────
app.post('/api/post-instagram', async (req, res) => {
  const { text, imageData, mimeType } = req.body;
  const userId = process.env.INSTAGRAM_USER_ID;
  const token  = process.env.INSTAGRAM_ACCESS_TOKEN;
  if (!userId || !token) {
    return res.status(400).json({ error: 'Instagram not configured. Add INSTAGRAM_USER_ID and INSTAGRAM_ACCESS_TOKEN to .env' });
  }
  if (!imageData) {
    return res.status(400).json({ error: 'Instagram requires an image. Generate an AI image in Step 3 first.' });
  }
  const ext      = (mimeType || 'image/png').split('/')[1] || 'png';
  const filename = Date.now().toString(36) + Math.random().toString(36).slice(2) + '.' + ext;
  const filePath = path.join(tempImagesDir, filename);
  const siteUrl  = (process.env.SITE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
  const imageUrl = `${siteUrl}/temp-images/${filename}`;
  try {
    fs.writeFileSync(filePath, Buffer.from(imageData, 'base64'));
    // Step 1: Create media container
    const cBody = JSON.stringify({ image_url: imageUrl, caption: text, access_token: token });
    const container = await httpsReq({
      hostname: 'graph.facebook.com',
      path:     `/v19.0/${userId}/media`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(cBody) },
    }, Buffer.from(cBody));
    if (container.error) throw new Error(container.error.message || JSON.stringify(container.error));
    // Step 2: Publish
    const pBody = JSON.stringify({ creation_id: container.id, access_token: token });
    const publish = await httpsReq({
      hostname: 'graph.facebook.com',
      path:     `/v19.0/${userId}/media_publish`,
      method:   'POST',
      headers:  { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(pBody) },
    }, Buffer.from(pBody));
    if (publish.error) throw new Error(publish.error.message || JSON.stringify(publish.error));
    return res.json({ success: true, postId: publish.id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  } finally {
    try { fs.unlinkSync(filePath); } catch {}
  }
});

// ── POST to LinkedIn ──────────────────────────────────────────────
app.post('/api/post-linkedin', async (req, res) => {
  const { text, imageData, mimeType } = req.body;
  const token  = process.env.LINKEDIN_ACCESS_TOKEN;
  const author = process.env.LINKEDIN_AUTHOR;
  if (!token || !author) {
    return res.status(400).json({ error: 'LinkedIn not configured. Add LINKEDIN_ACCESS_TOKEN and LINKEDIN_AUTHOR to .env' });
  }
  try {
    let mediaAsset = null;
    if (imageData) {
      // Step 1: Register upload
      const rBody = JSON.stringify({
        registerUploadRequest: {
          recipes:              ['urn:li:digitalmediaRecipe:feedshare-image'],
          owner:                author,
          serviceRelationships: [{ relationshipType: 'OWNER', identifier: 'urn:li:userGeneratedContent' }],
        },
      });
      const registered = await httpsReq({
        hostname: 'api.linkedin.com',
        path:     '/v2/assets?action=registerUpload',
        method:   'POST',
        headers:  { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(rBody), 'X-Restli-Protocol-Version': '2.0.0' },
      }, Buffer.from(rBody));
      if (registered.message) throw new Error(registered.message);
      const uploadUrl = registered.value?.uploadMechanism?.['com.linkedin.digitalmedia.uploading.MediaUploadHttpRequest']?.uploadUrl;
      mediaAsset      = registered.value?.asset;
      // Step 2: Upload binary
      const imgBuf = Buffer.from(imageData, 'base64');
      const up     = new URL(uploadUrl);
      await httpsReq({
        hostname: up.hostname,
        path:     up.pathname + (up.search || ''),
        method:   'PUT',
        headers:  { 'Authorization': `Bearer ${token}`, 'Content-Type': mimeType || 'image/png', 'Content-Length': imgBuf.length },
      }, imgBuf);
    }
    // Step 3: Create post
    const shareContent = mediaAsset
      ? { shareCommentary: { text }, shareMediaCategory: 'IMAGE', media: [{ status: 'READY', media: mediaAsset }] }
      : { shareCommentary: { text }, shareMediaCategory: 'NONE' };
    const postBody = JSON.stringify({
      author,
      lifecycleState:  'PUBLISHED',
      specificContent: { 'com.linkedin.ugc.ShareContent': shareContent },
      visibility:      { 'com.linkedin.ugc.MemberNetworkVisibility': 'PUBLIC' },
    });
    const result = await httpsReq({
      hostname: 'api.linkedin.com',
      path:     '/v2/ugcPosts',
      method:   'POST',
      headers:  { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(postBody), 'X-Restli-Protocol-Version': '2.0.0', 'X-Restli-Method': 'CREATE' },
    }, Buffer.from(postBody));
    if (result.message) throw new Error(result.message);
    res.json({ success: true, postId: result.id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── HeyGen ───────────────────────────────────────────────────────
function heygenReq(path, method, bodyObj) {
  const key  = process.env.HEYGEN_API_KEY;
  const body = bodyObj ? Buffer.from(JSON.stringify(bodyObj)) : null;
  const headers = { 'X-Api-Key': key, 'Accept': 'application/json' };
  if (body) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = body.length; }

  return new Promise((resolve, reject) => {
    const req = https.request({ hostname: 'api.heygen.com', path, method, headers }, (r) => {
      const chunks = [];
      r.on('data', c => chunks.push(c));
      r.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        try { resolve(JSON.parse(raw)); }
        catch { reject(new Error(`HeyGen parse error (${r.statusCode}): ${raw.slice(0, 300)}`)); }
      });
    });
    req.setTimeout(25000, () => { req.destroy(); reject(new Error('HeyGen request timed out after 25s')); });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

app.get('/api/heygen-avatars', async (_req, res) => {
  if (!process.env.HEYGEN_API_KEY) return res.status(400).json({ error: 'HEYGEN_API_KEY not set in .env' });
  try {
    const result = await heygenReq('/v2/avatars', 'GET');
    const count = result.data?.avatars?.length ?? 'unknown';
    console.log(`[HeyGen] avatars response: ${count} avatars, code=${result.code ?? result.error ?? 'ok'}`);
    res.json(result);
  } catch (err) {
    console.error('[HeyGen] avatars error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/heygen-voices', async (_req, res) => {
  if (!process.env.HEYGEN_API_KEY) return res.status(400).json({ error: 'HEYGEN_API_KEY not set in .env' });
  try {
    const result = await heygenReq('/v2/voices', 'GET');
    const count = result.data?.voices?.length ?? 'unknown';
    console.log(`[HeyGen] voices response: ${count} voices, code=${result.code ?? result.error ?? 'ok'}`);
    res.json(result);
  } catch (err) {
    console.error('[HeyGen] voices error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/heygen-generate', async (req, res) => {
  if (!process.env.HEYGEN_API_KEY) return res.status(400).json({ error: 'HEYGEN_API_KEY not set in .env' });
  const { script, avatarId, voiceId } = req.body;
  if (!script || !avatarId || !voiceId) return res.status(400).json({ error: 'script, avatarId and voiceId are required' });
  try {
    const result = await heygenReq('/v2/video/generate', 'POST', {
      video_inputs: [{
        character: { type: 'avatar', avatar_id: avatarId, avatar_style: 'normal' },
        voice:     { type: 'text',   input_text: script,   voice_id:   voiceId  },
      }],
      dimension: { width: 1280, height: 720 },
    });
    if (result.error) throw new Error(result.error.message || JSON.stringify(result.error));
    res.json({ videoId: result.data?.video_id });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/heygen-video-status/:videoId', async (req, res) => {
  if (!process.env.HEYGEN_API_KEY) return res.status(400).json({ error: 'HEYGEN_API_KEY not set in .env' });
  try {
    const result = await heygenReq(`/v1/video_status.get?video_id=${req.params.videoId}`, 'GET');
    res.json(result);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ── Start ──────────────────────────────────────────────────────────
module.exports = app; // used by netlify/functions/api.js

if (require.main === module) app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════╗
║   🤖  AI Insurance Content Creator  ✅        ║
╠══════════════════════════════════════════════╣
║   Open in browser:                           ║
║   👉  http://localhost:${PORT}                   ║
╚══════════════════════════════════════════════╝
`);
});
