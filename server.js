const fs = require('fs');
const path = require('path');
const http = require('http');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const chokidar = require('chokidar');
const Fuse = require('fuse.js');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'markdown-search-secret';
const DOCS_DIR = path.join(__dirname, 'docs');
const UPLOAD_LOG = path.join(__dirname, 'uploads.json');

const initialUsers = [
  { username: 'admin', role: 'admin', password: 'admin_123!' },
  { username: 'manager', role: 'editor', password: 'manager_123!' },
  { username: 'guest', role: 'viewer', password: 'guest_123!' },
];

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

if (!fs.existsSync(DOCS_DIR)) {
  fs.mkdirSync(DOCS_DIR, { recursive: true });
}

if (!fs.existsSync(UPLOAD_LOG)) {
  fs.writeFileSync(UPLOAD_LOG, '[]', 'utf-8');
}

let fuseIndex = null;
let searchableLines = [];

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512');
  return { salt, hash: derived.toString('hex') };
}

function verifyPassword(password, userRecord) {
  const derived = crypto.pbkdf2Sync(password, userRecord.salt, 100000, 64, 'sha512');
  const existing = Buffer.from(userRecord.hash, 'hex');
  if (derived.length !== existing.length) {
    return false;
  }
  return crypto.timingSafeEqual(derived, existing);
}

const users = new Map();
initialUsers.forEach(({ username, role, password }) => {
  const { salt, hash } = hashPassword(password);
  users.set(username.toLowerCase(), { username, role, salt, hash });
});

const fuseOptions = {
  includeScore: true,
  ignoreLocation: true,
  keys: ['text'],
  threshold: 0.4,
};

function loadUploadLog() {
  try {
    const data = fs.readFileSync(UPLOAD_LOG, 'utf-8');
    return JSON.parse(data);
  } catch (error) {
    console.error('Failed to read upload log, resetting.', error);
    fs.writeFileSync(UPLOAD_LOG, '[]', 'utf-8');
    return [];
  }
}

function appendUploadLog(entry) {
  const log = loadUploadLog();
  log.push(entry);
  fs.writeFileSync(UPLOAD_LOG, JSON.stringify(log, null, 2));
}

function buildIndex() {
  const files = fs.readdirSync(DOCS_DIR).filter((file) => file.endsWith('.md'));
  const newIndex = [];

  files.forEach((filename) => {
    const filePath = path.join(DOCS_DIR, filename);
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split(/\r?\n/);
    lines.forEach((line, idx) => {
      if (!line.trim()) {
        return;
      }
      newIndex.push({
        filename,
        lineNumber: idx + 1,
        text: line,
      });
    });
  });

  fuseIndex = newIndex.length ? new Fuse(newIndex, fuseOptions) : null;
  searchableLines = newIndex;
  io.emit('index_updated');
}

function buildRegexFromWildcard(pattern) {
  const placeholder = pattern
    .replace(/\\\*/g, '___ESCAPED_STAR___')
    .replace(/\\\?/g, '___ESCAPED_Q___')
    .replace(/\*/g, '___WILDCARD_STAR___')
    .replace(/\?/g, '___WILDCARD_Q___');

  const escaped = placeholder.replace(/([.+^${}()\[\]\\])/g, '\\$1');

  const restored = escaped
    .replace(/___WILDCARD_STAR___/g, '.*')
    .replace(/___WILDCARD_Q___/g, '.')
    .replace(/___ESCAPED_STAR___/g, '\\*')
    .replace(/___ESCAPED_Q___/g, '\\?');

  return new RegExp(restored, 'i');
}

function buildRegex(pattern, mode) {
  if (mode === 'regex') {
    return new RegExp(pattern, 'i');
  }
  if (mode === 'wildcard') {
    return buildRegexFromWildcard(pattern);
  }
  return null;
}

function sanitizeFilename(filename) {
  const base = path.basename(filename);
  if (!base.endsWith('.md')) {
    return null;
  }
  return base;
}

function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) {
    return res.status(401).json({ message: 'Missing authorization token.' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

function authorize(roles = []) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(500).json({ message: 'User is not authenticated.' });
    }
    if (roles.length === 0 || roles.includes(req.user.role)) {
      return next();
    }
    return res.status(403).json({ message: 'Insufficient permissions.' });
  };
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => {
    cb(null, DOCS_DIR);
  },
  filename: (_req, file, cb) => {
    const safeName = sanitizeFilename(file.originalname);
    if (!safeName) {
      return cb(new Error('Only .md files are allowed.'));
    }
    cb(null, safeName);
  },
});

const upload = multer({
  storage,
  fileFilter: (_req, file, cb) => {
    if (!file.originalname.endsWith('.md')) {
      return cb(new Error('Only .md files are allowed.'));
    }
    cb(null, true);
  },
});

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) {
    return next(new Error('Authentication required for live updates.'));
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.data.user = payload;
    return next();
  } catch (error) {
    return next(new Error('Authentication failed.'));
  }
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password are required.' });
  }
  const record = users.get(String(username).toLowerCase());
  if (!record || !verifyPassword(password, record)) {
    return res.status(401).json({ message: 'Invalid username or password.' });
  }

  const payload = { user: record.username, role: record.role };
  const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });

  res.json({ token, user: payload });
});

app.get('/session', authenticate, (req, res) => {
  res.json({ user: req.user });
});

app.get('/search-doc', authenticate, (req, res) => {
  const { keywords = '', mode = 'and' } = req.query;
  const trimmed = keywords.trim();

  if (!trimmed) {
    return res.status(400).json({ message: 'At least one keyword is required.' });
  }

  const allowedModes = ['and', 'regex', 'wildcard'];
  if (!allowedModes.includes(mode)) {
    return res.status(400).json({ message: 'Unsupported search mode.' });
  }

  if (!searchableLines.length) {
    return res.json({ results: [] });
  }

  const matchesMap = new Map();

  if (mode === 'regex' || mode === 'wildcard') {
    let regex;
    try {
      regex = buildRegex(trimmed, mode);
    } catch (error) {
      return res.status(400).json({ message: 'Invalid search pattern.' });
    }

    searchableLines.forEach((item) => {
      const testRegex = new RegExp(regex.source, regex.flags);
      if (!testRegex.test(item.text)) {
        return;
      }
      if (!matchesMap.has(item.filename)) {
        matchesMap.set(item.filename, []);
      }
      matchesMap.get(item.filename).push({
        lineNumber: item.lineNumber,
        line: item.text,
      });
    });

    const response = Array.from(matchesMap.entries()).map(([filename, matches]) => ({
      filename,
      matches,
    }));

    const highlightRegex = new RegExp(regex.source, regex.flags.includes('g') ? regex.flags : `${regex.flags}g`);

    return res.json({
      results: response,
      mode,
      pattern: highlightRegex.source,
      flags: highlightRegex.flags,
    });
  }

  const keywordList = trimmed
    .split(',')
    .map((kw) => kw.trim())
    .filter(Boolean);

  if (!keywordList.length) {
    return res.status(400).json({ message: 'At least one keyword is required.' });
  }

  if (!fuseIndex) {
    return res.json({ results: [] });
  }

  const searchTerm = keywordList.join(' ');
  const fuseResults = fuseIndex.search(searchTerm);

  const lowerKeywords = keywordList.map((kw) => kw.toLowerCase());

  fuseResults.forEach(({ item }) => {
    const textLower = item.text.toLowerCase();
    const hasAllKeywords = lowerKeywords.every((kw) => textLower.includes(kw));
    if (!hasAllKeywords) {
      return;
    }
    if (!matchesMap.has(item.filename)) {
      matchesMap.set(item.filename, []);
    }
    matchesMap.get(item.filename).push({
      lineNumber: item.lineNumber,
      line: item.text,
    });
  });

  const response = Array.from(matchesMap.entries()).map(([filename, matches]) => ({
    filename,
    matches,
  }));

  res.json({ results: response, mode: 'and', keywords: keywordList });
});

app.post('/upload-doc', authenticate, authorize(['editor', 'admin']), (req, res) => {
  upload.single('file')(req, res, (err) => {
    if (err) {
      return res.status(400).json({ message: err.message });
    }
    if (!req.file) {
      return res.status(400).json({ message: 'No file uploaded.' });
    }

    const logEntry = {
      filename: req.file.filename,
      user: req.user.user,
      role: req.user.role,
      uploadedAt: new Date().toISOString(),
    };

    appendUploadLog(logEntry);
    buildIndex();
    io.emit('file_changed', { event: 'uploaded', filename: req.file.filename, user: req.user });

    res.json({ message: 'File uploaded successfully.', entry: logEntry });
  });
});

app.put('/edit-doc/:filename', authenticate, authorize(['editor', 'admin']), (req, res) => {
  const safeName = sanitizeFilename(req.params.filename);
  if (!safeName) {
    return res.status(400).json({ message: 'Invalid filename.' });
  }
  const filePath = path.join(DOCS_DIR, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'File not found.' });
  }

  const { content } = req.body || {};
  if (typeof content !== 'string') {
    return res.status(400).json({ message: 'File content is required.' });
  }

  try {
    fs.writeFileSync(filePath, content, 'utf-8');
    buildIndex();
    io.emit('file_changed', { event: 'edited', filename: safeName, user: req.user });
    res.json({ message: 'File saved successfully.' });
  } catch (error) {
    console.error('Failed to edit file', error);
    res.status(500).json({ message: 'Unable to save file.' });
  }
});

app.get('/download-doc/:filename', authenticate, (req, res) => {
  const safeName = sanitizeFilename(req.params.filename);
  if (!safeName) {
    return res.status(400).json({ message: 'Invalid filename.' });
  }
  const filePath = path.join(DOCS_DIR, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'File not found.' });
  }
  res.download(filePath);
});

app.get('/preview-doc/:filename', authenticate, (req, res) => {
  const safeName = sanitizeFilename(req.params.filename);
  if (!safeName) {
    return res.status(400).json({ message: 'Invalid filename.' });
  }

  const filePath = path.join(DOCS_DIR, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'File not found.' });
  }

  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lineCount = content === '' ? 0 : content.split(/\r?\n/).length;
    res.json({
      filename: safeName,
      content,
      lineCount,
      size: Buffer.byteLength(content, 'utf-8'),
    });
  } catch (error) {
    console.error('Failed to preview file', error);
    res.status(500).json({ message: 'Unable to read file.' });
  }
});

app.delete('/delete-doc/:filename', authenticate, authorize(['admin']), (req, res) => {
  const safeName = sanitizeFilename(req.params.filename);
  if (!safeName) {
    return res.status(400).json({ message: 'Invalid filename.' });
  }
  const filePath = path.join(DOCS_DIR, safeName);
  if (!fs.existsSync(filePath)) {
    return res.status(404).json({ message: 'File not found.' });
  }
  fs.unlinkSync(filePath);
  buildIndex();
  io.emit('file_changed', { event: 'deleted', filename: safeName, user: req.user });
  res.json({ message: 'File deleted successfully.' });
});

app.get('/upload-history', authenticate, authorize(['admin']), (_req, res) => {
  const log = loadUploadLog();
  log.sort((a, b) => new Date(b.uploadedAt) - new Date(a.uploadedAt));
  res.json({ history: log });
});

app.post('/force-reindex', authenticate, authorize(['admin']), (_req, res) => {
  buildIndex();
  res.json({ message: 'Index rebuilt successfully.' });
});

buildIndex();

const watcher = chokidar.watch(path.join(DOCS_DIR, '**/*.md'), {
  ignoreInitial: true,
});

watcher
  .on('add', (filePath) => {
    buildIndex();
    io.emit('file_changed', {
      event: 'added',
      filename: path.basename(filePath),
    });
  })
  .on('change', (filePath) => {
    buildIndex();
    io.emit('file_changed', {
      event: 'changed',
      filename: path.basename(filePath),
    });
  })
  .on('unlink', (filePath) => {
    buildIndex();
    io.emit('file_changed', {
      event: 'removed',
      filename: path.basename(filePath),
    });
  });

io.on('connection', (socket) => {
  socket.emit('index_ready');
});

server.listen(PORT, () => {
  console.log(`Markdown search server running on port ${PORT}`);
});
