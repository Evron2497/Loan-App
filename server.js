require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Database = require("better-sqlite3");
const { z } = require("zod");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const app = express();
const PORT = Number(process.env.PORT || 3500);
const NEXUS_PAY_API_KEY = process.env.NEXUS_PAY_API_KEY || "";
const NEXUS_PAY_STKPUSH_URL = process.env.NEXUS_PAY_STKPUSH_URL || "https://makamescopay.com/api/payments/stkpush";
const NEXUS_PAY_WEBHOOK_SECRET = process.env.NEXUS_PAY_WEBHOOK_SECRET || "";
const JWT_SECRET = process.env.JWT_SECRET || "";
const isProd = process.env.NODE_ENV === "production";
if (isProd && JWT_SECRET.length < 32) {
  throw new Error("Set JWT_SECRET to a random value of at least 32 characters in production.");
}
if (!JWT_SECRET) console.warn("WARNING: using development JWT secret. Set JWT_SECRET in .env.");
app.disable("x-powered-by");
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "30kb" }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 250, standardHeaders: true, legacyHeaders: false }));

const dbPath = "/tmp/okoa.sqlite";
fs.mkdirSync(path.dirname(dbPath), { recursive: true });
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name TEXT NOT NULL,
 email TEXT NOT NULL UNIQUE,
 phone TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('customer','admin')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS profiles (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 national_id_last4 TEXT,
 national_id_number TEXT,
 date_of_birth TEXT,
 county TEXT,
 residential_address TEXT,
 education_level TEXT,
 employment_type TEXT,
 employer_name TEXT,
 employment_months INTEGER,
 dependents INTEGER,
 loan_purpose TEXT,
 other_income INTEGER DEFAULT 0,
 monthly_income INTEGER,
 monthly_expenses INTEGER,
 existing_debt INTEGER,
 payout_phone TEXT,
 consent_at TEXT,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id),
 requested_amount INTEGER NOT NULL,
 term_days INTEGER NOT NULL,
 assessed_amount INTEGER NOT NULL,
 fee_amount INTEGER NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','disbursed','repaid','cancelled')),
 reason TEXT NOT NULL,
 accepted_terms INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT,
 reviewed_by INTEGER REFERENCES users(id),
 approved_amount INTEGER,
 review_note TEXT
);
CREATE TABLE IF NOT EXISTS payments (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 application_id INTEGER NOT NULL REFERENCES applications(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 kind TEXT NOT NULL CHECK(kind IN ('disbursement','repayment','fee_demo')),
 amount INTEGER NOT NULL,
 method TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'simulated' CHECK(status IN ('simulated','pending','success','failed')),
 provider_reference TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS nexus_payment_attempts (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 application_id INTEGER NOT NULL REFERENCES applications(id),
 user_id INTEGER NOT NULL REFERENCES users(id),
 amount INTEGER NOT NULL,
 phone TEXT NOT NULL,
 status TEXT NOT NULL DEFAULT 'initiating' CHECK(status IN ('initiating','pending','failed','success','unknown')),
 provider_reference TEXT,
 provider_response TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_nexus_attempts_application ON nexus_payment_attempts(application_id, created_at DESC);
CREATE TABLE IF NOT EXISTS password_reset_otps (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 otp_hash TEXT NOT NULL,
 expires_at INTEGER NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0,
 used_at INTEGER,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_password_reset_user ON password_reset_otps(user_id, created_at DESC);
CREATE TABLE IF NOT EXISTS audit_logs (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 actor_user_id INTEGER REFERENCES users(id),
 action TEXT NOT NULL,
 entity_type TEXT NOT NULL,
 entity_id INTEGER,
 metadata TEXT NOT NULL DEFAULT '{}',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);
// Lightweight additive migrations for existing local databases.
const appColumns = db.prepare("PRAGMA table_info(applications)").all().map(c => c.name);
if (!appColumns.includes("approved_amount")) db.exec("ALTER TABLE applications ADD COLUMN approved_amount INTEGER");
if (!appColumns.includes("review_note")) db.exec("ALTER TABLE applications ADD COLUMN review_note TEXT");
const profileColumns = db.prepare("PRAGMA table_info(profiles)").all().map(c => c.name);
for (const [name, type] of [["national_id_number","TEXT"],["residential_address","TEXT"],["education_level","TEXT"],["employer_name","TEXT"],["employment_months","INTEGER"],["dependents","INTEGER"],["loan_purpose","TEXT"],["other_income","INTEGER NOT NULL DEFAULT 0"]]) {
  if (!profileColumns.includes(name)) db.exec(`ALTER TABLE profiles ADD COLUMN ${name} ${type}`);
}

function audit(actor, action, type, id, metadata = {}) {
  db.prepare("INSERT INTO audit_logs(actor_user_id,action,entity_type,entity_id,metadata) VALUES(?,?,?,?,?)")
    .run(actor || null, action, type, id || null, JSON.stringify(metadata));
}
function createToken(user) {
  return jwt.sign({ sub: user.id, role: user.role }, JWT_SECRET || "dev-only-secret-change-me", { expiresIn: "8h", issuer: "okoa-comrades" });
}
function auth(req, res, next) {
  const token = req.cookies.oc_token || (req.headers.authorization || "").replace(/^Bearer /i, "");
  if (!token) return res.status(401).json({ error: "Please log in." });
  try {
    const payload = jwt.verify(token, JWT_SECRET || "dev-only-secret-change-me", { issuer: "okoa-comrades" });
    const user = db.prepare("SELECT id,name,email,phone,role FROM users WHERE id=?").get(payload.sub);
    if (!user) return res.status(401).json({ error: "Account not found." });
    req.user = user; next();
  } catch { return res.status(401).json({ error: "Session expired. Please log in again." }); }
}
function adminOnly(req, res, next) {
  if (req.user.role !== "admin") return res.status(403).json({ error: "Administrator access required." });
  next();
}
function cleanUser(user) { return { id:user.id, name:user.name, email:user.email, phone:user.phone, role:user.role }; }
const emailSchema = z.string().trim().email().max(160);
const phoneSchema = z.string().trim().regex(/^(\+?254|0)7\d{8}$/, "Use a Kenyan mobile number such as 0712345678.");
const money = z.number().int().min(0).max(100000000);
const registerSchema = z.object({
  name: z.string().trim().min(2).max(100),
  email: emailSchema,
  phone: phoneSchema,
  password: z.string().min(10).max(100),
  confirmPassword: z.string().min(10).max(100)
}).refine(v => v.password === v.confirmPassword, { message: "Passwords do not match.", path: ["confirmPassword"] });
const profileSchema = z.object({
  nationalIdNumber: z.string().trim().regex(/^\d{7,8}$/, "Enter the 7–8 digit number on your Kenyan national ID."),
  dateOfBirth: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  county: z.string().trim().min(2).max(80),
  residentialAddress: z.string().trim().min(4).max(240),
  educationLevel: z.enum(["primary","secondary","certificate","diploma","degree","postgraduate","other"]),
  employmentType: z.enum(["employed","self_employed","student","casual","unemployed"]),
  employerName: z.string().trim().max(120).optional().default(""),
  employmentMonths: z.number().int().min(0).max(1200),
  dependents: z.number().int().min(0).max(30),
  loanPurpose: z.enum(["education","business","rent_housing","medical","emergency","household","other"]),
  otherIncome: money.default(0),
  monthlyIncome: money,
  monthlyExpenses: money,
  existingDebt: money,
  payoutPhone: phoneSchema,
  consent: z.literal(true)
});

// Assessment is intentionally explainable, conservative and not a promise of credit.
function assess(profile, requested) {
  if (!profile || !profile.consent_at) return { amount: 0, reason: "Complete your profile and consent to the credit assessment first." };
  const income = Number(profile.monthly_income ?? profile.monthlyIncome ?? 0);
  const expenses = Number(profile.monthly_expenses ?? profile.monthlyExpenses ?? 0);
  const debt = Number(profile.existing_debt ?? profile.existingDebt ?? 0);
  const otherIncome = Number(profile.other_income ?? profile.otherIncome ?? 0);
  if (income + otherIncome <= 0) return { amount: 0, reason: "Declared regular income is required for this initial assessment." };
  const disposable = income + otherIncome - expenses - debt;
  if (disposable <= 0) return { amount: 0, reason: "Declared income does not currently cover expenses and existing debt." };
  // Demo policy: no more than 25% of monthly disposable income, capped at KES 50,000.
  const cap = Math.min(50000, Math.floor(disposable * 0.25));
  const qualified = Math.floor(Math.min(requested, cap) / 500) * 500;
  if (qualified < 1000) return { amount: 0, reason: "Based on the information provided, the estimate is below the KES 1,000 minimum." };
  return { amount: qualified, reason: `Preliminary estimate based on declared disposable income. Final approval requires verification and review.` };
}
function feeFor(amount) { return Math.round(amount * 0.05); }
function getProfile(userId) {
  const p = db.prepare("SELECT * FROM profiles WHERE user_id=?").get(userId);
  if (!p) return null;
  return {
    nationalIdNumber: p.national_id_number || "", dateOfBirth: p.date_of_birth || "", county: p.county || "", residentialAddress: p.residential_address || "", educationLevel: p.education_level || "",
    employmentType: p.employment_type || "", employerName: p.employer_name || "", employmentMonths: p.employment_months ?? 0, dependents: p.dependents ?? 0, loanPurpose: p.loan_purpose || "", otherIncome: p.other_income ?? 0, monthlyIncome: p.monthly_income ?? 0,
    monthlyExpenses: p.monthly_expenses ?? 0, existingDebt: p.existing_debt ?? 0,
    payoutPhone: p.payout_phone || "", complete: Boolean(p.consent_at)
  };
}

function normalizeKenyanPhone(phone) {
  const digits = String(phone || "").replace(/\D/g, "");
  if (digits.startsWith("254") && digits.length === 12) return "+" + digits;
  if (digits.startsWith("0") && digits.length === 10) return "+254" + digits.slice(1);
  if (digits.startsWith("7") && digits.length === 9) return "+254" + digits;
  return null;
}
async function sendPasswordOtp(phone, code) {
  const username = process.env.AT_USERNAME || "";
  const apiKey = process.env.AT_API_KEY || "";
  if (!username || !apiKey) {
    if (process.env.NODE_ENV !== "production") {
      console.warn(` Password reset OTP for ${phone}: ${code}. Configure AT_USERNAME and AT_API_KEY to send SMS.`);
      return { sent: false, development: true };
    }
    throw new Error("Password reset SMS is not configured. Contact support.");
  }
  const to = normalizeKenyanPhone(phone);
  if (!to) throw new Error("The registered mobile number is not valid for SMS delivery.");
  const body = new URLSearchParams({ username, to, message: `Okoa Comrades password reset code: ${code}. It expires in 10 minutes. Do not share it.` });
  if (process.env.AT_SENDER_ID) body.set("from", process.env.AT_SENDER_ID);
  const response = await fetch("https://api.africastalking.com/version1/messaging", {
    method: "POST",
    headers: { "apiKey": apiKey, "Accept": "application/json", "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  const text = await response.text();
  if (!response.ok) {
    console.error("Africa's Talking SMS error:", response.status, text.slice(0, 500));
    throw new Error("Could not send the reset SMS. Try again later.");
  }
  return { sent: true };
}
function otpHash(userId, code) {
  return crypto.createHash("sha256").update(`${userId}:${code}:${process.env.JWT_SECRET || "dev-only-secret-change-me"}`).digest("hex");
}

app.get("/api/health", (req,res) => res.json({ ok:true, app:"Okoa Comrades", mode: process.env.REAL_DISBURSEMENTS_ENABLED === "true" ? "provider-configured-check-required" : "demo-no-real-money" }));
app.post("/api/auth/register", async (req,res) => {
  const parsed = registerSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const { name,email,password } = parsed.data;
  const phone = normalizeKenyanPhone(parsed.data.phone);
  try {
    if (db.prepare("SELECT id FROM users WHERE email=?").get(email.toLowerCase())) return res.status(409).json({ error:"An account with this email already exists." });
    if (db.prepare("SELECT id FROM users WHERE phone=?").get(phone)) return res.status(409).json({ error:"An account with this mobile number already exists." });
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare("INSERT INTO users(name,email,phone,password_hash) VALUES(?,?,?,?)").run(name,email.toLowerCase(),phone,hash);
    const user = db.prepare("SELECT id,name,email,phone,role FROM users WHERE id=?").get(result.lastInsertRowid);
    audit(user.id,"register","user",user.id);
    res.cookie("oc_token", createToken(user), { httpOnly:true, secure:isProd, sameSite:"strict", maxAge:8*60*60*1000 });
    res.status(201).json({ user:cleanUser(user) });
  } catch (e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({ error:"An account with this email already exists." });
    res.status(500).json({ error:"Could not create account." });
  }
});
app.post("/api/auth/login", async (req,res) => {
  const parsed = z.object({ email:emailSchema, password:z.string().min(1).max(100) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error:"Enter a valid email and password." });
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(parsed.data.email.toLowerCase());
  if (!user || !(await bcrypt.compare(parsed.data.password,user.password_hash))) {
    audit(null,"login_failed","user",null,{email:parsed.data.email.toLowerCase()});
    return res.status(401).json({ error:"Invalid email or password." });
  }
  res.cookie("oc_token", createToken(user), { httpOnly:true, secure:isProd, sameSite:"strict", maxAge:8*60*60*1000 });
  audit(user.id,"login","user",user.id);
  res.json({ user:cleanUser(user) });
});
app.post("/api/auth/forgot-password", async (req,res) => {
  const parsed = z.object({ phone: phoneSchema }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "Enter the Kenyan mobile number registered to your account." });
  const normalized = normalizeKenyanPhone(parsed.data.phone);
  const user = db.prepare("SELECT id,phone FROM users WHERE phone=? OR phone=?").get(parsed.data.phone, normalized);
  // Always use a generic response to avoid exposing whether a phone is registered.
  const generic = { message: "If an account matches that mobile number, a password reset code will be sent." };
  if (!user) return res.json(generic);
  const recent = db.prepare("SELECT COUNT(*) AS n FROM password_reset_otps WHERE user_id=? AND created_at > ?").get(user.id, Math.floor(Date.now()/1000)-900).n;
  if (recent >= 3) return res.status(429).json({ error: "Too many reset requests. Wait 15 minutes before trying again." });
  const code = String(crypto.randomInt(0, 1000000)).padStart(6, "0");
  const now = Math.floor(Date.now()/1000);
  db.prepare("INSERT INTO password_reset_otps(user_id,otp_hash,expires_at,created_at) VALUES(?,?,?,?)").run(user.id, otpHash(user.id,code), now+600, now);
  try {
    const delivery = await sendPasswordOtp(user.phone, code);
    audit(user.id, "password_reset_otp_requested", "user", user.id, { smsConfigured: delivery.sent });
    res.json({ ...generic, ...(delivery.development ? { developmentOnly: true, note: "SMS is not configured. In local development only, the OTP is printed in the server terminal." } : {}) });
  } catch (e) {
    db.prepare("UPDATE password_reset_otps SET used_at=? WHERE user_id=? AND used_at IS NULL").run(now,user.id);
    res.status(503).json({ error: e.message || "Could not send reset code." });
  }
});
app.post("/api/auth/reset-password", async (req,res) => {
  const parsed = z.object({ phone: phoneSchema, otp: z.string().regex(/^\d{6}$/), password: z.string().min(10).max(100), confirmPassword: z.string().min(10).max(100) }).refine(v => v.password === v.confirmPassword, { message: "Passwords do not match.", path: ["confirmPassword"] }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: parsed.error.issues[0].message });
  const phone = parsed.data.phone;
  const normalized = normalizeKenyanPhone(phone);
  const user = db.prepare("SELECT id FROM users WHERE phone=? OR phone=?").get(phone, normalized);
  if (!user) return res.status(400).json({ error: "Invalid or expired reset code." });
  const now = Math.floor(Date.now()/1000);
  const record = db.prepare("SELECT * FROM password_reset_otps WHERE user_id=? AND used_at IS NULL ORDER BY created_at DESC LIMIT 1").get(user.id);
  if (!record || record.expires_at < now || record.attempts >= 5) return res.status(400).json({ error: "Invalid or expired reset code. Request a new code." });
  const supplied = otpHash(user.id, parsed.data.otp);
  const valid = crypto.timingSafeEqual(Buffer.from(supplied, "hex"), Buffer.from(record.otp_hash, "hex"));
  if (!valid) {
    db.prepare("UPDATE password_reset_otps SET attempts=attempts+1 WHERE id=?").run(record.id);
    return res.status(400).json({ error: "Invalid or expired reset code." });
  }
  const hash = await bcrypt.hash(parsed.data.password, 12);
  const tx = db.transaction(() => {
    db.prepare("UPDATE users SET password_hash=? WHERE id=?").run(hash,user.id);
    db.prepare("UPDATE password_reset_otps SET used_at=? WHERE user_id=? AND used_at IS NULL").run(now,user.id);
    audit(user.id,"password_reset_completed","user",user.id);
  });
  tx();
  res.json({ message: "Password reset successfully. Sign in using your new password." });
});
app.post("/api/auth/logout", (req,res) => { res.clearCookie("oc_token",{httpOnly:true,secure:isProd,sameSite:"strict"}); res.json({ok:true}); });
app.get("/api/me", auth, (req,res) => res.json({ user:cleanUser(req.user), profile:getProfile(req.user.id) }));

app.put("/api/profile", auth, (req,res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error:parsed.error.issues[0].message });
  const p = parsed.data;
  db.prepare(`INSERT INTO profiles(user_id,national_id_number,date_of_birth,county,residential_address,education_level,employment_type,employer_name,employment_months,dependents,loan_purpose,other_income,monthly_income,monthly_expenses,existing_debt,payout_phone,consent_at,updated_at)
    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)
    ON CONFLICT(user_id) DO UPDATE SET national_id_number=excluded.national_id_number,date_of_birth=excluded.date_of_birth,county=excluded.county,residential_address=excluded.residential_address,education_level=excluded.education_level,employment_type=excluded.employment_type,employer_name=excluded.employer_name,employment_months=excluded.employment_months,dependents=excluded.dependents,loan_purpose=excluded.loan_purpose,other_income=excluded.other_income,monthly_income=excluded.monthly_income,monthly_expenses=excluded.monthly_expenses,existing_debt=excluded.existing_debt,payout_phone=excluded.payout_phone,consent_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP`)
    .run(req.user.id,p.nationalIdNumber,p.dateOfBirth,p.county,p.residentialAddress,p.educationLevel,p.employmentType,p.employerName,p.employmentMonths,p.dependents,p.loanPurpose,p.otherIncome,p.monthlyIncome,p.monthlyExpenses,p.existingDebt,p.payoutPhone);
  audit(req.user.id,"profile_updated","profile",req.user.id,{consent:true});
  res.json({ profile:getProfile(req.user.id) });
});

app.post("/api/applications", auth, (req,res) => {
  const parsed = z.object({ requestedAmount:z.number().int().min(1000).max(50000).multipleOf(500), termDays:z.number().int().min(7).max(90), acceptTerms:z.literal(true) }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:parsed.error.issues[0].message});
  const profile = db.prepare("SELECT * FROM profiles WHERE user_id=?").get(req.user.id);
  if (!profile || !profile.consent_at) return res.status(400).json({ error:"Please complete and save your profile before applying." });
  // Demo-only automatic decision. The browser shows a 2-second pending animation before revealing this result.
  const estimate = assess(profile, parsed.data.requestedAmount);
  const estimatedAmount = Math.max(0, Math.floor(Math.min(parsed.data.requestedAmount, estimate.amount) / 500) * 500);
  const approved = estimatedAmount >= 1000;
  const fee = approved ? feeFor(estimatedAmount) : 0;
  const status = approved ? "approved" : "rejected";
  const reason = approved
    ? "LOAN APPLICATION DECISION: Your application is assessed using the applicable eligibility, affordability, and verification criteria. If approved, your loan amount, processing fee, repayment schedule, and disbursement conditions will be communicated to you. Once all agreed disbursement conditions have been met, funds will be transferred according to the terms and stated timeline of your loan agreement."
    : (estimate.reason || "The affordability assessment could not establish a minimum eligible loan amount based on the information provided. Please review your income, expenses, and existing debt details, then submit your application for further assessment.");
  const insert = db.prepare("INSERT INTO applications(user_id,requested_amount,term_days,assessed_amount,approved_amount,fee_amount,status,reason,accepted_terms,reviewed_at,review_note) VALUES(?,?,?,?,?,?,?,?,?,?,?)")
    .run(req.user.id,parsed.data.requestedAmount,parsed.data.termDays,estimatedAmount,approved ? estimatedAmount : null,fee,status,reason,1,new Date().toISOString(),approved ? "Automated Loan Eligibility Assessment" : reason);
  const application = db.prepare("SELECT * FROM applications WHERE id=?").get(insert.lastInsertRowid);
  audit(req.user.id,approved ? "Loan Approved by the Authorized Credit Officer" : "Loan Rejected by the Authorized Credit Officer","application",application.id,{requestedAmount:parsed.data.requestedAmount,estimate:estimatedAmount,termDays:parsed.data.termDays,decisionMode:"demo_auto"});
  res.status(201).json({ application, assessment:{amount:estimatedAmount,reason}, message:approved ? "Your loan application has been reviewed by the authorized credit officer and approved. Review your approved loan amount, the 5% processing fee, total repayment amount, repayment schedule, and disbursement conditions below. Funds will be disbursed according to your loan agreement once all required conditions have been met." : `We could not establish an eligible loan amount from the information provided. ${reason}` });
});

app.get("/api/applications", auth, (req,res) => {
  const rows = req.user.role === "admin"
    ? db.prepare(`SELECT a.*,u.name AS customer_name,u.email AS customer_email,u.phone AS customer_phone,
        (SELECT n.status FROM nexus_payment_attempts n WHERE n.application_id=a.id ORDER BY n.id DESC LIMIT 1) AS latest_fee_status,
        p.national_id_last4,p.date_of_birth,p.county,p.employment_type,p.monthly_income,p.monthly_expenses,p.existing_debt,p.payout_phone,p.consent_at AS profile_consent_at
        FROM applications a JOIN users u ON u.id=a.user_id LEFT JOIN profiles p ON p.user_id=u.id
        ORDER BY CASE WHEN a.status='pending' THEN 0 ELSE 1 END,a.created_at DESC LIMIT 300`).all()
    : db.prepare("SELECT a.*, (SELECT n.status FROM nexus_payment_attempts n WHERE n.application_id=a.id ORDER BY n.id DESC LIMIT 1) AS latest_fee_status FROM applications a WHERE a.user_id=? ORDER BY a.created_at DESC").all(req.user.id);
  res.json({ applications:rows });
});
app.get("/api/dashboard", auth, (req,res) => {
  const profile = db.prepare("SELECT * FROM profiles WHERE user_id=?").get(req.user.id);
  const applications = db.prepare("SELECT a.*, (SELECT n.status FROM nexus_payment_attempts n WHERE n.application_id=a.id ORDER BY n.id DESC LIMIT 1) AS latest_fee_status FROM applications a WHERE a.user_id=? ORDER BY a.created_at DESC LIMIT 5").all(req.user.id);
  const payments = db.prepare("SELECT * FROM payments WHERE user_id=? ORDER BY created_at DESC LIMIT 10").all(req.user.id);
  const assessment = profile ? assess(profile,50000) : {amount:0,reason:"Complete your profile first."};
  res.json({ profile:getProfile(req.user.id), assessment, feeAtEstimate:feeFor(assessment.amount), applications, payments, mode:"Real" });
});

// Admins are provisioned manually using the documented CLI command, never via public registration.
app.get("/api/admin/summary", auth, adminOnly, (req,res) => {
  res.json({
    users:db.prepare("SELECT COUNT(*) AS n FROM users WHERE role='customer'").get().n,
    pending:db.prepare("SELECT COUNT(*) AS n FROM applications WHERE status='pending'").get().n,
    approved:db.prepare("SELECT COUNT(*) AS n FROM applications WHERE status='approved'").get().n,
    feesReceived:db.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM nexus_payment_attempts WHERE status='success'").get().n,
    pendingFees:db.prepare("SELECT COUNT(*) AS n FROM nexus_payment_attempts WHERE status IN ('initiating','pending','unknown')").get().n,
    failedFees:db.prepare("SELECT COUNT(*) AS n FROM nexus_payment_attempts WHERE status='failed'").get().n,
    disbursedAmount:db.prepare("SELECT COALESCE(SUM(amount),0) AS n FROM payments WHERE kind='disbursement' AND status='success'").get().n
  });
});
app.patch("/api/admin/applications/:id", auth, adminOnly, (req,res) => {
  const parsed = z.object({ status:z.enum(["approved","rejected"]), approvedAmount:z.number().int().min(1000).max(50000).optional(), note:z.string().trim().max(500).optional() }).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Choose approve or reject, and for approval enter an amount from KES 1,000 to KES 50,000."});
  const a = db.prepare("SELECT * FROM applications WHERE id=?").get(Number(req.params.id));
  if (!a) return res.status(404).json({error:"Application not found."});
  if (a.status !== "pending") return res.status(409).json({error:"Only pending applications can be reviewed."});
  if (String(a.reason || "").startsWith("REAL LOAN ALLOCATION")) return res.status(409).json({error:"Loan allocations must be reviewed and approved by an authorized credit officer in accordance with the lending policy before funds can be disbursed."});
  if (parsed.data.status === "approved" && !parsed.data.approvedAmount) return res.status(400).json({error:"Enter the final approved amount before approving."});
  const approved = parsed.data.status === "approved" ? parsed.data.approvedAmount : null;
  const fee = approved ? Math.round(approved * 0.05) : 0;
  db.prepare("UPDATE applications SET status=?,approved_amount=?,assessed_amount=CASE WHEN ? IS NOT NULL THEN ? ELSE assessed_amount END,fee_amount=CASE WHEN ? IS NOT NULL THEN ? ELSE fee_amount END,reviewed_at=CURRENT_TIMESTAMP,reviewed_by=?,review_note=?,reason=? WHERE id=?")
    .run(parsed.data.status,approved,approved,approved,approved,fee,req.user.id,parsed.data.note || null,parsed.data.note || a.reason,a.id);
  audit(req.user.id,"application_reviewed","application",a.id,{status:parsed.data.status,approvedAmount:approved,note:parsed.data.note || ""});
  res.json({ok:true,status:parsed.data.status,approvedAmount:approved});
});

// Nexus Pay STK Push: starts a provider request but does NOT mark a payment as paid.
// Final success handling requires the exact provider webhook/signature and status-verification contract.
app.post("/api/payments/nexus/stkpush", auth, async (req,res) => {
  if (!NEXUS_PAY_API_KEY) return res.status(503).json({error:"Nexus Pay is not configured on the server. Set NEXUS_PAY_API_KEY in your hosting environment."});
  const parsed = z.object({applicationId:z.number().int().positive(), confirmDisclosure:z.literal(true), phone:phoneSchema}).safeParse(req.body);
  if (!parsed.success) return res.status(400).json({error:"Confirm the fee disclosure and select a valid approved application."});
  const a = db.prepare("SELECT * FROM applications WHERE id=? AND user_id=?").get(parsed.data.applicationId,req.user.id);
  if (!a) return res.status(404).json({error:"Application not found."});
  if (a.status !== "approved") return res.status(409).json({error:"Only an application approved by the lender can proceed."});
  const phone = normalizeKenyanPhone(parsed.data.phone);
  if (!phone) return res.status(400).json({error:"Enter a valid Safaricom number, e.g. 0712345678 or 254712345678."});
  const normalizedPhone = phone.replace(/^\+/, "");
  const existing = db.prepare("SELECT * FROM nexus_payment_attempts WHERE application_id=? AND status IN ('initiating','pending','unknown') ORDER BY id DESC LIMIT 1").get(a.id);
  if (existing) return res.status(409).json({error:"A payment request for this application is already pending. Check your M-Pesa messages or contact support before retrying.",payment:{id:existing.id,status:existing.status,amount:existing.amount}});
  const fee = Number(a.fee_amount);
  if (!Number.isSafeInteger(fee) || fee < 1) return res.status(400).json({error:"No valid disclosed fee is available for this application."});
  const insert = db.prepare("INSERT INTO nexus_payment_attempts(application_id,user_id,amount,phone,status) VALUES(?,?,?,?, 'initiating')").run(a.id,req.user.id,fee,normalizedPhone);
  const attemptId = Number(insert.lastInsertRowid);
  try {
    const response = await fetch(NEXUS_PAY_STKPUSH_URL, {
      method:"POST",
      headers:{"X-API-Key":NEXUS_PAY_API_KEY,"Content-Type":"application/json","Accept":"application/json"},
      body:JSON.stringify({phoneNumber:normalizedPhone,amount:fee,accountReference:`OC-${a.id}-FEE-${attemptId}`,transactionDesc:`Okoa Comrades disclosed application fee`}),
      signal:AbortSignal.timeout(20000)
    });
    const raw = await response.text();
    let body; try { body = JSON.parse(raw); } catch { body = {message:raw.slice(0,1000)}; }
    // Provider response is stored for reconciliation, but an HTTP 2xx is not proof of payment.
    const providerRef = body?.transactionId || body?.checkoutRequestId || body?.reference || body?.id || null;
    const status = response.ok ? "pending" : "failed";
    db.prepare("UPDATE nexus_payment_attempts SET status=?,provider_reference=?,provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(status,providerRef,JSON.stringify({httpStatus:response.status,body}).slice(0,8000),attemptId);
    audit(req.user.id,"nexus_stkpush_requested","payment_attempt",attemptId,{applicationId:a.id,amount:fee,status,httpStatus:response.status});
    if (!response.ok) return res.status(502).json({error:"Nexus Pay did not accept the STK Push request. Check provider configuration/dashboard before retrying.",payment:{id:attemptId,status:"failed"}});
    res.status(202).json({message:"STK Push request submitted to Nexus Pay. Check your phone and enter your M-Pesa PIN only in the official M-Pesa prompt. Payment remains pending until independently verified.",payment:{id:attemptId,status:"pending",amount:fee,phone:normalizedPhone,providerReference:providerRef}});
  } catch (err) {
    // A timeout can mean the provider received the request; keep it unknown to prevent duplicate charges.
    db.prepare("UPDATE nexus_payment_attempts SET status='unknown',provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(JSON.stringify({error:String(err.message || err)}).slice(0,2000),attemptId);
    audit(req.user.id,"nexus_stkpush_unknown","payment_attempt",attemptId,{applicationId:a.id});
    return res.status(504).json({error:"We could not confirm Nexus Pay's response. Do not retry immediately; check your provider dashboard or contact support to avoid duplicate prompts.",payment:{id:attemptId,status:"unknown"}});
  }
});

// Customer-visible status for the latest Nexus Pay fee attempt on an application.
app.get("/api/applications/:id/fee-payment", auth, (req,res) => {
  const a = db.prepare("SELECT id,user_id FROM applications WHERE id=?").get(Number(req.params.id));
  if (!a) return res.status(404).json({error:"Application not found."});
  if (req.user.role !== "admin" && a.user_id !== req.user.id) return res.status(403).json({error:"Access denied."});
  const attempt = db.prepare("SELECT id,amount,phone,status,provider_reference,created_at,updated_at FROM nexus_payment_attempts WHERE application_id=? ORDER BY id DESC LIMIT 1").get(a.id);
  res.json({status:attempt?.status || "not_paid", payment:attempt || null});
});

function verifyNexusWebhook(req) {
  if (!NEXUS_PAY_WEBHOOK_SECRET) return false;
  const supplied = req.get("X-Webhook-Signature") || "";
  const expected = "sha256=" + crypto.createHmac("sha256", NEXUS_PAY_WEBHOOK_SECRET)
    .update(JSON.stringify(req.body)).digest("hex");
  const a = Buffer.from(supplied, "utf8");
  const b = Buffer.from(expected, "utf8");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Nexus Pay documented webhook: payment.completed / payment.failed.
// A webhook is applied only after HMAC verification, reference matching and amount validation.
app.post("/api/payments/nexus/webhook", (req,res) => {
  if (!verifyNexusWebhook(req)) {
    console.warn("Rejected Nexus webhook: missing/invalid signature or secret.");
    return res.status(401).json({received:false,error:"Invalid webhook signature."});
  }
  const event = String(req.body?.event || "").toLowerCase();
  const data = req.body?.data;
  if (!data || typeof data !== "object" || Array.isArray(data)) return res.status(400).json({received:false,error:"Invalid webhook payload."});
  if (!(["payment.completed","payment.failed"].includes(event))) return res.status(200).json({received:true,ignored:true});
  // This application initiates M-Pesa STK Push, so only checkoutRequestId/accountReference events match.
  const checkoutId = data.checkoutRequestId ? String(data.checkoutRequestId) : "";
  const accountReference = data.accountReference ? String(data.accountReference) : "";
  let attempt = checkoutId ? db.prepare("SELECT * FROM nexus_payment_attempts WHERE provider_reference=? ORDER BY id DESC LIMIT 1").get(checkoutId) : null;
  if (!attempt && /^OC-(\d+)-FEE-(\d+)$/.test(accountReference)) {
    const match = accountReference.match(/^OC-(\d+)-FEE-(\d+)$/);
    const appId = Number(match[1]);
    const attemptId = Number(match[2]);
    attempt = db.prepare("SELECT * FROM nexus_payment_attempts WHERE id=? AND application_id=?").get(attemptId, appId);
  }
  if (!attempt) {
    console.warn("Nexus webhook did not match a stored fee attempt.", {event,checkoutId,accountReference});
    return res.status(202).json({received:true,matched:false,message:"No matching payment attempt; queued for reconciliation."});
  }
  const amount = Number(data.amount);
  if (!Number.isFinite(amount) || Math.abs(amount - Number(attempt.amount)) > 0.001) {
    console.error("Nexus webhook amount mismatch", {attemptId:attempt.id,expected:attempt.amount,received:data.amount});
    audit(null,"nexus_webhook_amount_mismatch","payment_attempt",attempt.id,{event,receivedAmount:data.amount});
    return res.status(409).json({received:false,error:"Payment amount does not match the stored attempt."});
  }
  const status = event === "payment.completed" ? "success" : "failed";
  const tx = db.transaction(() => {
    const current = db.prepare("SELECT * FROM nexus_payment_attempts WHERE id=?").get(attempt.id);
    // Idempotency: a completed payment can never be downgraded or counted twice.
    if (current.status === "success") return false;
    const providerRef = checkoutId || current.provider_reference || null;
    db.prepare("UPDATE nexus_payment_attempts SET status=?,provider_reference=?,provider_response=?,updated_at=CURRENT_TIMESTAMP WHERE id=?")
      .run(status,providerRef,JSON.stringify({event,data}).slice(0,8000),current.id);
    audit(null,"nexus_webhook_"+status,"payment_attempt",current.id,{applicationId:current.application_id,amount,receipt:data.mpesaReceiptNumber || null});
    return true;
  });
  const changed = tx();
  return res.status(200).json({received:true,matched:true,updated:changed,status:changed?status:attempt.status});
});

// Legacy callback paths are retained but fail closed: no unauthenticated status changes.
app.post("/api/payments/nexus/callback", (req,res) => res.status(410).json({received:false,message:"Use the signed Nexus Pay webhook endpoint."}));
app.post("/api/payments/mpesa/callback", (req,res) => res.status(410).json({ResultCode:1,ResultDesc:"Use the configured signed provider webhook."}));

app.get("/api/config", (req,res) => res.json({ appName:"Okoa Comrades", currency:"KES", minLoan:1000, maxLoan:50000, step:500, feeRate:0.05, paymentsMode:NEXUS_PAY_API_KEY?(NEXUS_PAY_WEBHOOK_SECRET?"nexus-stkpush-with-signed-webhook":"stkpush-enabled-webhook-secret-missing"):"not-configured", webhookConfigured:Boolean(NEXUS_PAY_WEBHOOK_SECRET), disclaimer:"STK Push initiation does not confirm payment or guarantee loan disbursement." }));
app.use(express.static(path.join(__dirname,"public")));
app.get("*",(req,res) => res.sendFile(path.join(__dirname,"public","index.html")));

app.listen(PORT, () => console.log(`Okoa Comrades running at http://localhost:${PORT}`));
