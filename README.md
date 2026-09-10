# Ludo Income - Render Ready

## Deploy
- Root Directory: empty
- Build Command: `npm install`
- Start Command: `npm start`
- Environment variables: `JWT_SECRET`, `ADMIN_EMAIL`, `ADMIN_PASSWORD`

Default demo login if variables are unchanged:
- Email: admin@example.com
- Password: ChangeThisPassword123!

## URLs
- `/` main page
- `/admin` admin panel

The admin panel controls the main page through backend APIs. Settings and matches are stored in `data/db.json`. On Render, the default filesystem is ephemeral; for durable production data, connect a database and move credentials/settings there.
