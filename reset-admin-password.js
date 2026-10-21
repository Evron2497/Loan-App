
require("dotenv").config();

const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const readline = require("readline");

const dbPath = path.resolve(
  process.env.DATABASE_PATH || "./data/okoa.sqlite"
);

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const ask = (question) =>
  new Promise((resolve) => rl.question(question, resolve));

async function main() {
  const db = new Database(dbPath);

  try {
    const admins = db.prepare(
      "SELECT email, name FROM users WHERE role = 'admin'"
    ).all();

    if (admins.length === 0) {
      throw new Error("No admin account exists in this database.");
    }

    console.log("\nExisting administrator accounts:");
    admins.forEach((admin, index) => {
      console.log(`${index + 1}. ${admin.name} — ${admin.email}`);
    });

    const email = (await ask(
      "\nEnter the exact admin email to reset: "
    )).trim();

    const admin = db.prepare(
      "SELECT email FROM users WHERE email = ? AND role = 'admin'"
    ).get(email);

    if (!admin) {
      throw new Error("That email is not an administrator account.");
    }

    const password =
      "OC!" + crypto.randomBytes(24).toString("base64url");

    const passwordHash = await bcrypt.hash(password, 12);

    const result = db.prepare(
      "UPDATE users SET password_hash = ? WHERE email = ? AND role = 'admin'"
    ).run(passwordHash, email);

    if (result.changes !== 1) {
      throw new Error("Password was not updated.");
    }

    console.log("\nADMIN PASSWORD RESET SUCCESSFUL");
    console.log("Login email:", email);
    console.log("New password:", password);
    console.log("\nSave this password securely now.");
    console.log("It will not be displayed again.");

  } finally {
    db.close();
    rl.close();
  }
}

main().catch((error) => {
  console.error("\nReset failed:", error.message);
  process.exitCode = 1;
  rl.close();
});
