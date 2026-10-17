require("dotenv").config();
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const dbPath = process.env.DATABASE_PATH || "./data/okoa.sqlite";
if (!fs.existsSync(path.resolve(dbPath))) {
  console.error("Database not found. Run npm.cmd start once, stop the server, then run this script from the project folder.");
  process.exit(1);
}
(async () => {
  const db = new Database(dbPath);
  const adminCount = db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='admin'").get().n;
  if (adminCount) {
    console.error("An administrator already exists. For safety, this script will not create another admin or reveal/reset credentials. Use the existing admin account or implement a verified reset process.");
    db.close(); process.exit(1);
  }
  const rl = require("readline").createInterface({input:process.stdin,output:process.stdout});
  const ask = q => new Promise(resolve => rl.question(q,resolve));
  const name = (await ask("Admin full name: ")).trim();
  const phone = (await ask("Admin Kenyan mobile (e.g. 0712345678): ")).trim();
  rl.close();
  if (!name || !/^((\+?254)|0)7\d{8}$/.test(phone)) throw new Error("Enter a name and valid Kenyan mobile number.");
  const username = "okoa_admin_" + crypto.randomBytes(3).toString("hex");
  const email = username + "@okoa.local";
  const password = "OC!" + crypto.randomBytes(18).toString("base64url") + "9a";
  const hash = await bcrypt.hash(password,12);
  db.prepare("INSERT INTO users(name,email,phone,password_hash,role) VALUES(?,?,?,?,'admin')").run(name,email,phone,hash);
  db.close();
  console.log("\nADMIN ACCOUNT CREATED — save these credentials securely; the password is shown only once.\n");
  console.log("Username: " + username);
  console.log("Login email field: " + email);
  console.log("Password: " + password);
  console.log("\nSign in using the exact login email above. Do not share these credentials or commit them to source control.\n");
})().catch(e => { console.error(e.message); process.exit(1); });
