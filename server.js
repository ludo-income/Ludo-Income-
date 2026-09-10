const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = Number(process.env.PORT) || 10000;
const ROOT = __dirname;
const ADMIN = path.join(ROOT, 'admin.html');
const HOME = path.join(ROOT, 'index.html');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.webp': 'image/webp'
};

function sendFile(res, file, headOnly = false) {
  fs.readFile(file, (err, data) => {
    if (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Server Error');
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-store'
    });
    if (headOnly) return res.end();
    res.end(data);
  });
}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Method Not Allowed');
  }

  let pathname;
  try { pathname = new URL(req.url || '/', 'http://localhost').pathname; }
  catch { res.writeHead(400); return res.end('Bad Request'); }

  // Explicit admin routes. /admin, /admin/, and /admin/index.html all open the admin panel.
  if (pathname === '/admin' || pathname === '/admin/' || pathname === '/admin/index.html') {
    if (!fs.existsSync(ADMIN)) {
      res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Admin panel file not found');
    }
    return sendFile(res, ADMIN, req.method === 'HEAD');
  }

  // Serve other static files safely.
  const relative = decodeURIComponent(pathname).replace(/^\/+/, '');
  const file = path.resolve(ROOT, relative || 'index.html');
  if (file !== ROOT && !file.startsWith(ROOT + path.sep)) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end('Bad Request');
  }

  if (fs.existsSync(file) && fs.statSync(file).isFile()) {
    return sendFile(res, file, req.method === 'HEAD');
  }

  // Home fallback only for unknown non-file routes.
  return sendFile(res, HOME, req.method === 'HEAD');
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`Ludo Income running on port ${PORT}`);
  console.log(`Admin panel: /admin`);
});
