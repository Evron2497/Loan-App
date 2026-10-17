# Okoa Comrades — full-stack starter

Responsive Kenyan KES lending workflow starter with Express API, SQLite persistence, customer registration with password confirmation, login, SMS OTP password reset, profile capture, server-calculated preliminary affordability estimates, administrator-reviewed applications, application tracking, signed Nexus Pay webhook processing and payment status reporting.

> **Not production lending software.** This starter does not move money, verify identity or provide a real credit decision. Payment state changes only through the signed Nexus Pay webhook; the legacy M-Pesa callback path is disabled. Never request an advance payment to “unlock” a loan. Before a real launch, obtain Kenyan legal/compliance advice and confirm CBK licensing/authorization, data protection, consumer-credit disclosures and payment-provider requirements.

## Requirements
- Node.js 20+
- npm

## Run locally
```bash
cp .env.example .env
# Edit .env and set JWT_SECRET to a long random secret
npm install
npm start
```
Open http://localhost:3000. SQLite DB is created at `data/okoa.sqlite`.

Windows PowerShell:
```powershell
Copy-Item .env.example .env
npm install
npm start
```

## Create an administrator
Run the server once to initialize the database, stop it, then run:
```bash
node scripts/create-admin.js
```
The script creates a unique administrator login and a cryptographically random password, prints them once, and refuses to create a second admin. Save the credentials securely. Use the generated `@okoa.local` login email in the sign-in email field. Public registration cannot create admins. The starter stores login identity in the email field; the unique username is included in that generated login email.

## Demo loan policy
- Requested amount: KES 1,000–50,000 in KES 500 increments.
- Indicative fee: 5% of the assessed amount.
- Demonstration assessment: disposable income = monthly income − monthly expenses − monthly existing debt payments; estimated cap = 25% of disposable income, capped at KES 50,000. Estimate rounds down to KES 500 increments and is never an approval.
- Applications with a positive estimate are sent to the administrator review queue as pending. The estimate is not an approval. An authorized administrator must enter a final approved amount; applications with no preliminary amount are recorded as rejected. The default estimate uses customer-declared figures only and is not external identity or income verification.
- A customer sees the withdrawal summary only after an authorized admin approval. The withdrawal modal can request a Nexus Pay STK Push if `NEXUS_PAY_API_KEY` is configured. A provider HTTP response is stored as pending, never as proof of payment. Signed webhook events update fee attempt status after signature, reference and amount checks. Real loan disbursement remains unimplemented.
- The interface never records simulated payouts as real disbursements. The six-second wait is a UI minimum, not proof that a credit check took six seconds or that an application was approved.

This affordability rule is an illustrative software default, not a validated lending model or a statement of regulatory compliance. Change it only after documented credit policy, validation, fairness review and legal/compliance review.

## Password reset OTP by SMS
- Registration requires the password and confirmation to match.
- Forgot password uses the registered Kenyan mobile number and a 6-digit, 10-minute OTP. OTPs are stored as hashes, expire, and are limited to five attempts; reset requests are rate-limited per account.
- Configure Africa's Talking SMS in `.env` using `AT_USERNAME`, `AT_API_KEY`, and optionally `AT_SENDER_ID`. In local development only, if SMS is not configured, the OTP is printed to the server terminal for testing. Production fails closed when SMS credentials are absent. Never use the development OTP mode in production.

## Nexus Pay STK Push integration status
The server can submit an STK Push request to `https://makamescopay.com/api/payments/stkpush` using `X-API-Key` and the documented homepage payload fields (`phoneNumber`, `amount`, `accountReference`, `transactionDesc`). Configure these environment variables on your host (for example Render) without putting the secret in frontend files:

```env
NEXUS_PAY_API_KEY=your_secret_key_here
NEXUS_PAY_STKPUSH_URL=https://makamescopay.com/api/payments/stkpush
```

The app only permits withdrawal UI for applications approved by an authorized admin decision. A successful HTTP response is treated as **pending**, not paid. The signed webhook endpoint updates payment state only after HMAC verification, attempt/reference matching and amount checks. A timeout is recorded as unknown to reduce duplicate-charge risk. No real loan disbursement is implemented.

Before production:
1. Confirm the API endpoint, payload, response fields, callback signature/authentication, status-query endpoint and idempotency support with Nexus Pay's current documentation/support.
2. Implement authenticated callback validation and independent transaction reconciliation before recording `success`.
3. Implement a separately authorized, audited B2C payout workflow only after payment and loan-contract checks; never infer payout success from STK Push success.
4. Test using a provider-approved test environment and verify amounts, phone numbers, duplicate requests, timeouts, retries, reversals and refunds.

## Safeguards before live lending
Before launch:
1. Keep the Nexus Pay secret only in server environment secrets; never expose it to browser code or commit it to Git.
2. Confirm production account activation and business/provider onboarding.
3. Do not enable live payouts until legal, compliance, security and operational approvals are complete.

The `MPESA_*` and `REAL_DISBURSEMENTS_ENABLED` environment variables are placeholders. They do not activate a real payment integration.

## Security and launch work still required
- HTTPS, secure secret management, CSRF protection appropriate to cookie auth, stronger session/revocation strategy, MFA for admins and login-specific rate limiting.
- Email/phone verification, identity checks via lawful providers, age/eligibility validation, consent/version records, data retention/deletion, encrypted backups and restricted access.
- Complete audit trail and tamper-resistant logs, alerting, monitoring, recovery tests, dependency scanning and penetration testing.
- Formal lending policy, affordability and model validation, fair-lending review, complete loan agreements and cost disclosures.
- Kenyan counsel/compliance review for CBK digital credit requirements, Data Protection Act 2019/ODPC requirements, consumer protection, credit reporting and payment provider contracts.
- Add automated tests and migrations before production.

## Main routes
- `POST /api/auth/register`, `POST /api/auth/login`, `POST /api/auth/forgot-password`, `POST /api/auth/reset-password`, `POST /api/auth/logout`
- `GET /api/me`, `GET /api/dashboard`
- `PUT /api/profile`
- `POST /api/applications`, `GET /api/applications`
- `GET /api/admin/summary`, `PATCH /api/admin/applications/:id`
- `POST /api/payments/nexus/stkpush` (initiates STK Push; response remains pending until verified)
- `POST /api/payments/nexus/webhook` (signed Nexus Pay event receiver)
- `GET /api/applications/:id/fee-payment` (owner/admin payment status)
- `GET /api/health`, `GET /api/config`

## Notes
- SQLite is suitable for a local starter/demo. Use PostgreSQL and migrations for production.
- Browser forms and UI are responsive for desktop and small screens.
- This project is provided as a starting point, not legal, financial or security advice.



## Latest demo updates (October 2026)
- Profile now asks for the full 7–8 digit Kenyan national ID number, date of birth, county, residential address, education, employment/business details, employment duration, dependants, loan purpose, other income, monthly income/expenses/debt, and Safaricom contact number.
- The affordability estimate uses the server-side declared-income calculation and is only a preliminary demo estimate. Final approval remains an authorized admin decision.
- After an authorized approval result, the customer sees the fee/amount prompt after five seconds. The customer enters a Safaricom number, confirms the exact 5% illustrative fee, then the server requests Nexus Pay STK Push using the server-side API key.
- The customer payment screen clearly says payment is not a guarantee of loan disbursement. An HTTP success from Nexus Pay is not treated as proof of payment; the configured signed webhook is required for reconciliation.
- Optional payment link for manual provider-side demonstration: https://makamescopay.com/pay/727f007eb557765b (variable amount; the customer must enter only the fee shown by the application). This static link does not confirm payment back to the app.

## Personal-data warning
This demo stores the full national ID number in its SQLite profile table to satisfy the requested form flow. Do not use real customer ID numbers until storage encryption, access logging, retention/deletion controls, a privacy impact assessment, and Kenyan data-protection/legal review are completed. Use synthetic test details in the demo. Never put Nexus Pay API keys in browser code or commit a populated `.env` file.
