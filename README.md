# Ludo Income Render FINAL Flat

Everything needed for Render is at the repository root. No public/ or admin/ folder is required.

Render:
- Root Directory: empty
- Build Command: npm install
- Start Command: npm start

Routes:
- / -> index.html
- /admin -> admin.html
- /admin/ -> admin.html
- /health -> health JSON

Environment:
JWT_SECRET
ADMIN_EMAIL
ADMIN_PASSWORD

Important: this demo stores settings in data/db.json in the earlier version; this final flat version keeps the app code self-contained. For production persistence, use an external database.
