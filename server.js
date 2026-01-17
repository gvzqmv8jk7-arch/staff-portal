
const path = require("path");
const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const helmet = require("helmet");
const http = require("http");
const { Server } = require("socket.io");
const SQLiteStore = require("connect-sqlite3")(session);

const { initDb, getDb, ROLES } = require("./db");

const BUILD_ID = "2026-01-13-full-fix6-core-working";

const app = express();
const server = http.createServer(app);
const io = new Server(server);

app.use(helmet({ contentSecurityPolicy: false })); // CDN-friendly (Quill/Tailwind)
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use("/public", express.static(path.join(__dirname, "public")));

const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite" }),
  secret: "change-me-to-a-long-random-secret",
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: "lax" },
});
app.use(sessionMiddleware);
io.engine.use(sessionMiddleware);

function requireAuth(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}

async function requireAppAccess(appKey, req, res, next) {
  const user = req.session.user;
  if (user?.role === "CEO") return next(); // CEO super-admin

  const db = getDb();
  const allowed = await db.get(
    "SELECT 1 FROM app_permissions WHERE app_key = ? AND role = ?",
    [appKey, user.role]
  );
  if (!allowed) return res.status(403).send("Access denied.");
  next();
}

function escapeHtml(str) {
  return String(str ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function render(res, viewName, data = {}) {
  const layout = fs.readFileSync(path.join(__dirname, "views", "layout.html"), "utf8");
  const view = fs.readFileSync(path.join(__dirname, "views", viewName), "utf8");

  const safeTitle = data.title || "Staff Portal";
  const userDisplay = escapeHtml(data.user?.display_name || "");
  const userRole = escapeHtml(data.user?.role || "");

  const layoutFilled = layout
    .replaceAll("{{TITLE}}", escapeHtml(safeTitle))
    .replaceAll("{{USER_DISPLAY}}", userDisplay)
    .replaceAll("{{USER_ROLE}}", userRole)
    .replaceAll("{{BUILD}}", escapeHtml(BUILD_ID));

  const contentFilled = view.replace(/\{\{(\w+)\}\}/g, (_, k) => (data[k] ?? ""));

  res.send(layoutFilled.replace("{{CONTENT}}", contentFilled));
}

app.get("/__build", (req, res) => res.json({ build: BUILD_ID }));

app.get("/", (req, res) => (req.session.user ? res.redirect("/dashboard") : res.redirect("/login")));

app.get("/login", (req, res) => render(res, "login.html", { title: "Login", error: "" }));

app.post("/login", async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "").trim();
  const db = getDb();

  const user = await db.get("SELECT * FROM users WHERE username = ?", [username]);
  if (!user || user.is_active !== 1) return render(res, "login.html", { title: "Login", error: "Invalid username or password." });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return render(res, "login.html", { title: "Login", error: "Invalid username or password." });

  req.session.user = { id: user.id, username: user.username, display_name: user.display_name, role: user.role };
  res.redirect("/dashboard");
});

app.post("/logout", (req, res) => {
  req.session.destroy(() => res.redirect("/login"));
});

/** Dashboard (filtered apps) **/
app.get("/dashboard", requireAuth, async (req, res) => {
  const user = req.session.user;
  const db = getDb();

  const apps = await db.all(
    `SELECT a.key, a.name, a.description, a.href, a.badge
     FROM apps a
     JOIN app_permissions p ON p.app_key = a.key
     WHERE a.is_enabled = 1 AND p.role = ?
     ORDER BY a.sort_order ASC, a.name ASC`,
    [user.role]
  );

  const APPS_HTML = apps.length
    ? apps.map(a => `
      <a href="${a.href}" class="group rounded-3xl bg-white/5 ring-1 ring-white/10 p-5 shadow-xl hover:bg-white/10 transition">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="text-lg font-semibold tracking-tight">${a.name}</div>
            <div class="text-sm text-slate-300 mt-1">${a.description}</div>
          </div>
          <div class="text-xs rounded-full bg-white/10 ring-1 ring-white/10 px-3 py-1">${a.badge || ""}</div>
        </div>
        <div class="mt-4 text-xs text-slate-400 group-hover:text-slate-300 transition">Open →</div>
      </a>
    `).join("")
    : `<div class="rounded-3xl bg-white/5 ring-1 ring-white/10 p-6 text-slate-300">No apps assigned to your role. Ask an admin to grant permissions.</div>`;

  render(res, "dashboard.html", { title: "Dashboard", user, APPS_HTML });
});


/** Word-like Editor **/
app.get("/editor", requireAuth, (req, res, next) => requireAppAccess("editor", req, res, next), async (req, res) => {
  const user = req.session.user;
  const db = getDb();

  let doc = await db.get("SELECT * FROM editor_docs WHERE user_id = ? ORDER BY id DESC LIMIT 1", [user.id]);
  if (!doc) {
    await db.run("INSERT INTO editor_docs (user_id, title, content_html) VALUES (?, ?, ?)", [user.id, "My Document", "<p>Start writing…</p>"]);
    doc = await db.get("SELECT * FROM editor_docs WHERE user_id = ? ORDER BY id DESC LIMIT 1", [user.id]);
  }

  render(res, "editor.html", {
    title: "Editor",
    user,
    DOC_ID: String(doc.id),
    DOC_TITLE: escapeHtml(doc.title),
    DOC_HTML: doc.content_html,
    DOC_UPDATED: doc.updated_at,
  });
});

app.post("/editor/save", requireAuth, (req, res, next) => requireAppAccess("editor", req, res, next), async (req, res) => {
  const user = req.session.user;
  const db = getDb();
  const docId = String(req.body.docId || "").trim();
  const title = String(req.body.title || "Untitled").trim();
  const html = String(req.body.html ?? "");

  const existing = await db.get("SELECT 1 FROM editor_docs WHERE id = ? AND user_id = ?", [docId, user.id]);
  if (!existing) return res.status(403).json({ ok: false, error: "Not allowed." });

  await db.run(
    "UPDATE editor_docs SET title = ?, content_html = ?, updated_at = datetime('now') WHERE id = ? AND user_id = ?",
    [title, html, docId, user.id]
  );
  res.json({ ok: true });
});

/** Staff Directory **/
/** Staff Directory **/
app.get("/directory", requireAuth, (req, res, next) => requireAppAccess("directory", req, res, next), async (req, res) => {
  const user = req.session.user;
  const db = getDb();
  const q = String(req.query.q || "").trim();
  let users;
  if (q) {
    users = await db.all(
      "SELECT id, display_name, username, role, is_active FROM users WHERE display_name LIKE ? OR username LIKE ? OR role LIKE ? ORDER BY display_name ASC LIMIT 300",
      [`%${q}%`, `%${q}%`, `%${q}%`]
    );
  } else {
    users = await db.all("SELECT id, display_name, username, role, is_active FROM users ORDER BY display_name ASC LIMIT 300");
  }

  const cards = users.map(u => `
    <div class="rounded-3xl bg-white/5 ring-1 ring-white/10 p-5 shadow-xl flex items-center justify-between gap-4">
      <div>
        <div class="font-semibold text-lg tracking-tight">${escapeHtml(u.display_name)} <span class="text-xs text-slate-400">@${escapeHtml(u.username)}</span></div>
        <div class="text-sm text-slate-300 mt-1">${escapeHtml(u.role)} • <span class="${u.is_active ? "text-emerald-200" : "text-rose-200"}">${u.is_active ? "Active" : "Inactive"}</span></div>
      </div>
      <div class="text-xs rounded-full bg-slate-950/40 ring-1 ring-white/10 px-3 py-1.5 font-mono">ID ${u.id}</div>
    </div>
  `).join("");

  render(res, "directory.html", { title: "Directory", user, QUERY: escapeHtml(q), USER_CARDS: cards || '<div class="rounded-3xl bg-slate-950/40 ring-1 ring-white/10 p-6 text-slate-300">No results.</div>' });
});

/** Team Chat page (rooms are role-locked) **/
/** Team Chat page (rooms are role-locked) **/
app.get("/chat", requireAuth, (req, res, next) => requireAppAccess("chat", req, res, next), async (req, res) => {
  const user = req.session.user;
  const db = getDb();

  const rooms = await db.all(
    `SELECT r.id, r.name
     FROM chat_rooms r
     JOIN chat_room_roles rr ON rr.room_id = r.id
     WHERE rr.role = ?
     ORDER BY r.sort_order ASC, r.name ASC`,
    [user.role]
  );

  const roomOptions = rooms.map(r => `<option value="${escapeHtml(r.id)}">${escapeHtml(r.name)}</option>`).join("");
  const roomList = rooms.map(r => `<div class="flex items-center justify-between gap-2 rounded-2xl bg-white/5 ring-1 ring-white/10 px-3 py-2"><div class="text-sm">${escapeHtml(r.name)}</div><div class="text-xs text-slate-400 font-mono">${escapeHtml(r.id)}</div></div>`).join("");
  const firstRoom = rooms[0]?.id || "";

  render(res, "chat.html", { title: "Chat", user, ROOM_OPTIONS: roomOptions, ROOM_LIST: roomList, FIRST_ROOM: escapeHtml(firstRoom) });
});

/** Admin panel (CEO always allowed; IT Manager via permission) **/
app.get("/admin", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const user = req.session.user;
  const db = getDb();

  const users = await db.all("SELECT id, username, display_name, role, is_active, created_at FROM users ORDER BY created_at DESC LIMIT 800");
  const apps = await db.all("SELECT key, name, description, href, badge, is_enabled, sort_order FROM apps ORDER BY sort_order ASC, name ASC");
  const perms = await db.all("SELECT app_key, role FROM app_permissions");
  const rooms = await db.all("SELECT id, name, sort_order FROM chat_rooms ORDER BY sort_order ASC, name ASC");
  const roomRoles = await db.all("SELECT room_id, role FROM chat_room_roles");

  render(res, "admin.html", {
    title: "Admin",
    user,
    USERS_JSON: JSON.stringify(users),
    APPS_JSON: JSON.stringify(apps),
    PERMS_JSON: JSON.stringify(perms),
    ROLES_JSON: JSON.stringify(ROLES),
    ROOMS_JSON: JSON.stringify(rooms),
    ROOMROLES_JSON: JSON.stringify(roomRoles),
  });
});

app.post("/admin/users/create", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const username = String(req.body.username || "").trim().toLowerCase();
  const display_name = String(req.body.display_name || "").trim();
  const role = String(req.body.role || "").trim();
  const password = String(req.body.password || "").trim();

  if (!username || !display_name || !role || !password) return res.status(400).json({ ok: false, error: "Missing fields." });
  if (!ROLES.includes(role)) return res.status(400).json({ ok: false, error: "Invalid role." });
  if (!/^[a-z0-9._-]{3,32}$/.test(username)) return res.status(400).json({ ok: false, error: "Username must be 3-32 chars: a-z 0-9 . _ -" });

  const hash = await bcrypt.hash(password, 12);
  try {
    await db.run("INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)", [username, hash, display_name, role]);
  } catch (e) {
    return res.status(400).json({ ok: false, error: "Username already exists." });
  }
  res.json({ ok: true });
});

app.post("/admin/users/update", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const id = String(req.body.id || "").trim();
  const display_name = String(req.body.display_name || "").trim();
  const role = String(req.body.role || "").trim();

  if (!id || !display_name || !role) return res.status(400).json({ ok: false, error: "Missing fields." });
  if (!ROLES.includes(role)) return res.status(400).json({ ok: false, error: "Invalid role." });

  await db.run("UPDATE users SET display_name = ?, role = ? WHERE id = ?", [display_name, role, id]);
  res.json({ ok: true });
});

app.post("/admin/users/toggle", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const id = String(req.body.id || "").trim();
  const is_active = Number(req.body.is_active) ? 1 : 0;
  if (!id) return res.status(400).json({ ok: false, error: "Missing id." });
  if (req.session.user && String(req.session.user.id) === String(id) && is_active === 0) {
    return res.status(400).json({ ok: false, error: "You can't deactivate your own account while logged in." });
  }
  await db.run("UPDATE users SET is_active = ? WHERE id = ?", [is_active, id]);
  res.json({ ok: true });
});

app.post("/admin/users/reset_password", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const id = String(req.body.id || "").trim();
  const password = String(req.body.password || "").trim();
  if (!id || !password) return res.status(400).json({ ok: false, error: "Missing fields." });

  const hash = await bcrypt.hash(password, 12);
  await db.run("UPDATE users SET password_hash = ? WHERE id = ?", [hash, id]);
  res.json({ ok: true });
});

app.post("/admin/apps/update", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const key = String(req.body.key || "").trim();
  const is_enabled = Number(req.body.is_enabled) ? 1 : 0;
  const sort_order = Number(req.body.sort_order ?? 100);
  if (!key) return res.status(400).json({ ok: false, error: "Missing key." });
  await db.run("UPDATE apps SET is_enabled = ?, sort_order = ? WHERE key = ?", [is_enabled, sort_order, key]);
  res.json({ ok: true });
});

app.post("/admin/perms/set", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const app_key = String(req.body.app_key || "").trim();
  const role = String(req.body.role || "").trim();
  const allowed = Number(req.body.allowed) ? 1 : 0;
  if (!app_key || !role) return res.status(400).json({ ok: false, error: "Missing fields." });
  if (!ROLES.includes(role)) return res.status(400).json({ ok: false, error: "Invalid role." });

  if (allowed) {
    await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", [app_key, role]);
  } else {
    await db.run("DELETE FROM app_permissions WHERE app_key = ? AND role = ?", [app_key, role]);
  }
  res.json({ ok: true });
});

/** Chat room role locks editor (admin) **/
app.post("/admin/chat/roomrole", requireAuth, (req, res, next) => requireAppAccess("admin", req, res, next), async (req, res) => {
  const db = getDb();
  const room_id = String(req.body.room_id || "").trim();
  const role = String(req.body.role || "").trim();
  const allowed = Number(req.body.allowed) ? 1 : 0;
  if (!room_id || !role) return res.status(400).json({ ok: false, error: "Missing fields." });
  if (!ROLES.includes(role)) return res.status(400).json({ ok: false, error: "Invalid role." });

  if (allowed) {
    await db.run("INSERT OR IGNORE INTO chat_room_roles (room_id, role) VALUES (?, ?)", [room_id, role]);
  } else {
    await db.run("DELETE FROM chat_room_roles WHERE room_id = ? AND role = ?", [room_id, role]);
  }
  res.json({ ok: true });
});

/** Friendly 404 last **/
app.use((req, res) => {
  res.status(404);
  render(res, "notfound.html", { title: "Not Found", user: req.session.user || null, PATH: req.path });
});

/** Socket.io (role-locked rooms) **/
io.on("connection", async (socket) => {
  const user = socket.request.session?.user;
  if (!user) return socket.disconnect(true);

  const db = getDb();
  const rooms = await db.all(
    `SELECT r.id, r.name
     FROM chat_rooms r
     JOIN chat_room_roles rr ON rr.room_id = r.id
     WHERE rr.role = ?
     ORDER BY r.sort_order ASC, r.name ASC`,
    [user.role]
  );

  socket.emit("rooms", rooms);

  socket.on("join", async (roomId) => {
    const allowed = await db.get(
      "SELECT 1 FROM chat_room_roles WHERE room_id = ? AND role = ?",
      [roomId, user.role]
    );
    if (!allowed) {
      socket.emit("system", { message: "You don't have access to that room." });
      return;
    }

    // leave all rooms first
    for (const r of rooms) socket.leave(r.id);
    socket.join(roomId);
    socket.emit("system", { message: "Joined " + roomId });
  });

  socket.on("message", async (payload) => {
    const roomId = String(payload?.roomId || "").trim();
    const text = String(payload?.text || "").trim();
    if (!roomId || !text) return;

    const allowed = await db.get(
      "SELECT 1 FROM chat_room_roles WHERE room_id = ? AND role = ?",
      [roomId, user.role]
    );
    if (!allowed) {
      socket.emit("system", { message: "Message blocked: no access to room." });
      return;
    }

    const msg = {
      roomId,
      text: text.slice(0, 2000),
      from: { display_name: user.display_name, username: user.username, role: user.role },
      at: new Date().toISOString(),
    };
    io.to(roomId).emit("message", msg);
  });
});

(async () => {
  await initDb();
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log("Running on http://localhost:" + PORT));
})();
