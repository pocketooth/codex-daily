const fs = require('fs');
const path = require('path');
const http = require('http');
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
  io.emit('index_updated');
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

app.get('/get-token', (req, res) => {
  const { user, role } = req.query;
  const allowedRoles = ['viewer', 'editor', 'admin'];
  if (!user || !role) {
    return res.status(400).json({ message: 'User and role are required.' });
  }
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ message: 'Invalid role requested.' });
  }
  const token = jwt.sign({ user, role }, JWT_SECRET, { expiresIn: '8h' });
  res.json({ token });
});

app.get('/search-doc', authenticate, (req, res) => {
  const { keywords = '' } = req.query;
  const keywordList = keywords
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

  const matchesMap = new Map();
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

  res.json({ results: response });
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
