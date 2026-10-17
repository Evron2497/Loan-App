
require("dotenv").config();

const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const dbPath = process.env.DATABASE_PATH || "./data/okoa.sqlite";
const absoluteDbPath = path.resolve(dbPath);

if (!fs.existsSync(absoluteDbPath)) {
  console.error("Database not found:", absoluteDbPath);
  console.error("Run npm.cmd start once, then stop the server and try again.");
  process.exit(1);
}

async function main() {
  const db = new Database(absoluteDbPath);

  try {
    const adminCount = db
      .prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'")
      .get().n;

    if (adminCount > 0) {
      console.error("An administrator already exists.");
      console.error("No new administrator was created.");
      return;
    }

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });

    const ask = (question) =>
      new Promise((resolve) => rl.question(question, resolve));

    let name;
    let phone;

    try {
      name = (await ask("Admin full name: ")).trim();
      phone = (await ask("Admin Kenyan mobile (e.g. 0712345678): ")).trim();
    } finally {
      rl.close();
    }

    if (!name || !/^(\+?254|0)7\d{8}$/.test(phone)) {
      throw new Error("Enter a name and valid Kenyan mobile number.");
    }

    const username = "okoa_admin_" + crypto.randomBytes(3).toString("hex");
    const email = username + "@okoa.local";
    const password = "OC!" + crypto.randomBytes(18).toString("base64url") + "9a";
    const passwordHash = await bcrypt.hash(password, 12);

    db.prepare(`
      INSERT INTO users (name, email, phone, password_hash, role)
      VALUES (?, ?, ?, ?, 'admin')
    `).run(name, email, phone, passwordHash);

    console.log("\nADMIN ACCOUNT CREATED");
    console.log("Save these credentials securely; the password is shown only once.");
    console.log("Login email:", email);
    console.log("Password:", password);
    console.log("\nSign in using the exact login email above.");
    console.log("Do not share the password or commit it to source control.");
  } finally {
    db.close();
  }
}

main().catch((error) => {
  console.error("Admin creation failed:", error.message);
  process.exitCode = 1;
});
