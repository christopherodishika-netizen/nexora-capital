# NEXORA CAPITAL — Flask starter

A responsive investor-account application with registration/login, a personal dashboard, transaction history, deposit requests, withdrawal requests, and a protected administrator console.

## Important before accepting real money
This is a strong **starter application**, not a legally approved investment business or a completed production financial platform. Do not advertise investment returns or accept public investment funds until the business, product, custody arrangements, disclosures, and required Nigerian regulatory approvals have been reviewed by qualified professionals. This app does not execute trades, invest funds, calculate investment returns, or automatically pay withdrawals.

## Run locally on Windows
1. Install Python 3.11+.
2. Open PowerShell in this folder.
3. Run:
   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   $env:NEXORA_ADMIN_EMAIL="your-admin-email@example.com"
   $env:NEXORA_ADMIN_PASSWORD="Use-A-Strong-Unique-Password-Here"
   $env:FLASK_SECRET_KEY="replace-with-a-long-random-secret"
   python app.py
   ```
4. Open `http://127.0.0.1:5000`.
5. Register a normal account. To access `/admin`, sign in using the admin email and password set before the first run. The first admin is created automatically when both environment variables are set and the database is initialized.

If `python` is not recognized, use the full path to your Python executable with `-m pip` and `app.py`.

## Currency and Paystack
The default display/payment currency is USD (`NEXORA_CURRENCY=USD`). Amounts are stored in minor units (cents for USD, kobo for NGN). Before enabling USD payments, confirm that your specific Paystack business account and settlement setup support USD transactions. If your account only supports NGN, set `NEXORA_CURRENCY=NGN` and use the matching account configuration; changing a symbol alone does not convert money.

Set `PAYSTACK_SECRET_KEY` as a **server environment variable** on your hosting provider. Never commit the secret key to GitHub or put it in HTML/JavaScript. The app initializes payments server-side and verifies the returned reference with Paystack before approving a deposit. Test in Paystack's test environment first. Configure and verify signed webhooks, reconciliation, alerting, backups, HTTPS, rate limits, CSRF protection, and a production database before a public financial launch.

## Deployment notes
- Use a host that supports Python/Flask (not a static-only host if you need the backend).
- Set a persistent database volume or migrate to PostgreSQL before production; the included SQLite database is suitable only for local development/small testing.
- Set `COOKIE_SECURE=1` on HTTPS hosting.
- Set `FLASK_DEBUG=0` in production.
- Create admin credentials using hosting environment variables before the first database initialization. Never share the admin login.
- This starter currently allows an admin to approve withdrawal requests but does not send payouts. Mark a withdrawal as paid only after the payout is actually sent and reconciled through the authorized provider/bank.
