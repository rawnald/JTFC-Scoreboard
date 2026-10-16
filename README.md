# JTFC Combat Scoreboard
Cloudflare Pages (static UI + Pages Functions) with a D1 database. Tailwind + Material Design styling.

- `/` public dashboard · `/admin.html` password-protected data entry
- `functions/api/[[route]].js` API · `schema.sql` database · `wrangler.toml` config

## Deploy
1. Push this folder to a GitHub repo.
2. Cloudflare dashboard → Storage & Databases → D1 → create `jtfc-scoreboard`. Copy its ID into `wrangler.toml`.
3. Run the schema: D1 → Console, paste `schema.sql` (or `npx wrangler d1 execute jtfc-scoreboard --remote --file=schema.sql`).
4. Workers & Pages → Create → Pages → Connect to Git → pick the repo. Build command: none. Output directory: `public`.
5. Project → Settings → Bindings → add D1 binding named `DB` → your database.
6. Project → Settings → Variables and Secrets → add secrets `ADMIN_PASSWORD` and `SESSION_SECRET` (long random string).
7. Redeploy. Open `/admin.html`, sign in, add data.
