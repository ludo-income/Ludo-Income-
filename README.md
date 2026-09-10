# Ludo Income — Render Fixed

This ZIP is intentionally flat at the repository root.

## Render
Root Directory: leave empty
Build Command: npm install
Start Command: npm start

## URLs
Main: /
Admin: /admin
Health: /health

## Environment Variables
JWT_SECRET = a long random secret
ADMIN_EMAIL = your admin email
ADMIN_PASSWORD = your initial admin password

## Important
Do not commit .env or secrets to GitHub.

The admin settings and password hash are stored in data/db.json. Render's local filesystem is not a durable database for production; use a persistent external database for permanent data.
