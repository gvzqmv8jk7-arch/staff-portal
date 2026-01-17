
// db.js
const sqlite3 = require("sqlite3").verbose();
const { open } = require("sqlite");
const bcrypt = require("bcrypt");

const ROLES = [
  "CEO",
  "Recruitment Team",
  "IT",
  "Radio Presenter",
  "HR Administrator",
  "HR Officer",
  "HR Manager",
  "Head of HR",
  "Finance Team",
  "IT Manager",
  "Safeguarding Officer"
];

let db;

async function initDb() {
  db = await open({
    filename: "./staff.db",
    driver: sqlite3.Database,
  });

  await db.exec(`
    PRAGMA journal_mode = WAL;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      display_name TEXT NOT NULL,
      role TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS apps (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      key TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      description TEXT NOT NULL,
      href TEXT NOT NULL,
      badge TEXT NOT NULL DEFAULT '',
      is_enabled INTEGER NOT NULL DEFAULT 1,
      sort_order INTEGER NOT NULL DEFAULT 100
    );

    CREATE TABLE IF NOT EXISTS app_permissions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      app_key TEXT NOT NULL,
      role TEXT NOT NULL,
      UNIQUE(app_key, role)
    );

    CREATE TABLE IF NOT EXISTS editor_docs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      content_html TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS chat_rooms (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      sort_order INTEGER NOT NULL DEFAULT 100
    );

    CREATE TABLE IF NOT EXISTS chat_room_roles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      room_id TEXT NOT NULL,
      role TEXT NOT NULL,
      UNIQUE(room_id, role)
    );
  `);

  // Seed users
  const existingUsers = await db.get("SELECT COUNT(*) AS c FROM users");
  if (existingUsers.c === 0) {
    const ceoHash = await bcrypt.hash("ceo123", 12);
    await db.run(
      "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
      ["ceo", ceoHash, "CEO", "CEO"]
    );

    const itMgrHash = await bcrypt.hash("it123", 12);
    await db.run(
      "INSERT INTO users (username, password_hash, display_name, role) VALUES (?, ?, ?, ?)",
      ["itmanager", itMgrHash, "IT Manager", "IT Manager"]
    );

    console.log("Seeded users (change passwords after first run):");
    console.log("  ceo / ceo123");
    console.log("  itmanager / it123");
  }

  // Seed apps
  const existingApps = await db.get("SELECT COUNT(*) AS c FROM apps");
  if (existingApps.c === 0) {
    const apps = [
      ["admin", "Admin Panel", "User management + app permissions.", "/admin", "Admin", 5],
      ["editor", "Word-like Editor", "Create and save formatted documents.", "/editor", "Docs", 10],
      ["chat", "Team Chat", "Role-based rooms + GC.", "/chat", "Live", 20],
      ["directory", "Staff Directory", "Search users by name, username, role.", "/directory", "People", 30],
    ];
    for (const a of apps) {
      await db.run(
        "INSERT INTO apps (key, name, description, href, badge, sort_order) VALUES (?, ?, ?, ?, ?, ?)",
        a
      );
    }
  }

  // Seed permissions
  const existingPerms = await db.get("SELECT COUNT(*) AS c FROM app_permissions");
  if (existingPerms.c === 0) {
    const apps = await db.all("SELECT key FROM apps WHERE is_enabled = 1");

    // CEO gets everything
    for (const a of apps) {
      await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", [a.key, "CEO"]);
    }

    // IT Manager gets admin
    await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", ["admin", "IT Manager"]);

    // Everyone gets editor + chat + directory by default
    for (const r of ROLES) {
      await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", ["editor", r]);
      await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", ["chat", r]);
      await db.run("INSERT OR IGNORE INTO app_permissions (app_key, role) VALUES (?, ?)", ["directory", r]);
    }
  }

  // Seed chat rooms + role locks
  const existingRooms = await db.get("SELECT COUNT(*) AS c FROM chat_rooms");
  if (existingRooms.c === 0) {
    const rooms = [
      ["gc", "GC (All Staff)", 10],
      ["leadership", "Leadership", 15],
      ["hr", "HR", 20],
      ["recruitment", "Recruitment", 30],
      ["it", "IT", 40],
      ["finance", "Finance", 50],
      ["radio", "Radio Presenters", 60],
      ["safeguarding", "Safeguarding", 70],
    ];
    for (const r of rooms) {
      await db.run("INSERT INTO chat_rooms (id, name, sort_order) VALUES (?, ?, ?)", r);
    }

    // GC: all roles
    for (const role of ROLES) {
      await db.run("INSERT OR IGNORE INTO chat_room_roles (room_id, role) VALUES (?, ?)", ["gc", role]);
    }

    const locks = [
["leadership", ["CEO", "Head of HR", "HR Manager", "IT Manager", "Finance Team"]],
      ["hr", ["HR Administrator", "HR Officer", "HR Manager", "Head of HR", "CEO"]],
      ["recruitment", ["Recruitment Team", "CEO"]],
      ["it", ["IT", "IT Manager", "CEO"]],
      ["finance", ["Finance Team", "CEO"]],
      ["radio", ["Radio Presenter", "CEO"]],
      ["safeguarding", ["Safeguarding Officer", "CEO", "Head of HR", "HR Manager"]],
    ];

    for (const [room, rr] of locks) {
      for (const role of rr) {
        await db.run("INSERT OR IGNORE INTO chat_room_roles (room_id, role) VALUES (?, ?)", [room, role]);
      }
    }
  }

  return db;
}

function getDb() {
  if (!db) throw new Error("DB not initialized. Call initDb() first.");
  return db;
}

module.exports = { initDb, getDb, ROLES };
