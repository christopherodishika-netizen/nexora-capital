import os
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

try:
    import requests
except ImportError:
    requests = None

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, os.getenv('NEXORA_DB', 'nexora.db'))
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'CHANGE-THIS-BEFORE-DEPLOYMENT-' + secrets.token_hex(16))
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', '0') == '1'

CURRENCY = os.getenv('NEXORA_CURRENCY', 'USD').strip().upper()
if CURRENCY not in ('USD', 'NGN'):
    CURRENCY = 'USD'
CURRENCY_SYMBOL = '$' if CURRENCY == 'USD' else '₦'
MIN_DEPOSIT = 10 if CURRENCY == 'USD' else 1000
MIN_WITHDRAWAL = 10 if CURRENCY == 'USD' else 1000
PAYSTACK_SECRET_KEY = os.getenv('PAYSTACK_SECRET_KEY', '')
PAYSTACK_PUBLIC_KEY = os.getenv('PAYSTACK_PUBLIC_KEY', '')
ADMIN_EMAIL = os.getenv('NEXORA_ADMIN_EMAIL', '').strip().lower()
ADMIN_PASSWORD = os.getenv('NEXORA_ADMIN_PASSWORD', '')


def now():
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn


def init_db():
    with db() as con:
        con.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'investor',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL REFERENCES users(id),
            kind TEXT NOT NULL CHECK(kind IN ('deposit','withdrawal')),
            amount_kobo INTEGER NOT NULL CHECK(amount_kobo > 0),
            status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected','paid')),
            reference TEXT UNIQUE,
            note TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL,
            reviewed_at TEXT,
            reviewed_by INTEGER REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id),
            action TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        ''')
        # Create the first admin only when credentials are supplied in the environment.
        if ADMIN_EMAIL and ADMIN_PASSWORD:
            existing = con.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,)).fetchone()
            if not existing:
                con.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                            ('NEXORA Administrator', ADMIN_EMAIL, generate_password_hash(ADMIN_PASSWORD), 'admin', now()))


def audit(actor_id, action, details=''):
    with db() as con:
        con.execute('INSERT INTO audit_log(actor_id,action,details,created_at) VALUES(?,?,?,?)',
                    (actor_id, action, details[:500], now()))


def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please sign in to continue.', 'warning')
            return redirect(url_for('login'))
        return fn(*args, **kwargs)
    return wrapped


def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            abort(403)
        return fn(*args, **kwargs)
    return wrapped


def current_user():
    if not session.get('user_id'):
        return None
    with db() as con:
        return con.execute('SELECT id,name,email,role,created_at FROM users WHERE id=?', (session['user_id'],)).fetchone()


def balance_for(user_id):
    with db() as con:
        deposits = con.execute("SELECT COALESCE(SUM(amount_kobo),0) n FROM transactions WHERE user_id=? AND kind='deposit' AND status='approved'", (user_id,)).fetchone()['n']
        withdrawals = con.execute("SELECT COALESCE(SUM(amount_kobo),0) n FROM transactions WHERE user_id=? AND kind='withdrawal' AND status IN ('approved','paid')", (user_id,)).fetchone()['n']
        return max(0, deposits - withdrawals)


def money(minor_units):
    return f"{CURRENCY_SYMBOL}{int(minor_units or 0) / 100:,.2f}"

app.jinja_env.filters['money'] = money


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.before_request
def protect_post_requests():
    if request.method == 'POST':
        supplied = request.form.get('csrf_token', '')
        expected = session.get('_csrf_token', '')
        if not supplied or not expected or not secrets.compare_digest(supplied, expected):
            abort(400, description='Security token missing or expired. Refresh the page and try again.')


@app.context_processor
def inject_globals():
    return {'current_user': current_user(), 'currency': CURRENCY, 'currency_symbol': CURRENCY_SYMBOL, 'min_deposit': MIN_DEPOSIT, 'min_withdrawal': MIN_WITHDRAWAL, 'paystack_public_key': PAYSTACK_PUBLIC_KEY, 'csrf_token': csrf_token}


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if len(name) < 2 or '@' not in email or len(password) < 10:
            flash('Enter your name, a valid email, and a password of at least 10 characters.', 'error')
            return render_template('register.html')
        try:
            with db() as con:
                con.execute('INSERT INTO users(name,email,password_hash,role,created_at) VALUES(?,?,?,?,?)',
                            (name, email, generate_password_hash(password), 'investor', now()))
                uid = con.execute('SELECT id FROM users WHERE email=?', (email,)).fetchone()['id']
            session.clear()
            session.update(user_id=uid, role='investor')
            audit(uid, 'account_registered', email)
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('An account with that email already exists.', 'error')
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        with db() as con:
            user = con.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_password_hash(user['password_hash'], password):
            flash('Email or password is incorrect.', 'error')
            return render_template('login.html')
        session.clear()
        session.update(user_id=user['id'], role=user['role'])
        audit(user['id'], 'login', email)
        return redirect(url_for('admin_dashboard' if user['role'] == 'admin' else 'dashboard'))
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    uid = session.get('user_id')
    audit(uid, 'logout')
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    uid = session['user_id']
    with db() as con:
        transactions = con.execute('SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 10', (uid,)).fetchall()
    return render_template('dashboard.html', balance=balance_for(uid), transactions=transactions)


@app.route('/deposit', methods=['POST'])
@login_required
def deposit():
    try:
        amount = float(request.form.get('amount', '0'))
        if amount < MIN_DEPOSIT or amount > 1000000:
            raise ValueError
        amount_kobo = round(amount * 100)
    except (ValueError, TypeError):
        flash(f'Enter a valid deposit amount of at least {CURRENCY_SYMBOL}{MIN_DEPOSIT:,.2f}.', 'error')
        return redirect(url_for('dashboard'))
    ref = 'NX-' + secrets.token_hex(12).upper()
    with db() as con:
        con.execute("INSERT INTO transactions(user_id,kind,amount_kobo,status,reference,note,created_at) VALUES(?,?,?,?,?,?,?)",
                    (session['user_id'], 'deposit', amount_kobo, 'pending', ref, 'Awaiting verified payment', now()))
    audit(session['user_id'], 'deposit_intent_created', f'{ref} {amount_kobo}')
    if not PAYSTACK_SECRET_KEY or requests is None:
        flash('Deposit request recorded, but online payments are not enabled yet. An administrator must configure Paystack securely.', 'warning')
        return redirect(url_for('dashboard'))
    # Initialize Paystack server-side. The balance is NOT credited until the callback is verified.
    with db() as con:
        user = con.execute('SELECT email FROM users WHERE id=?', (session['user_id'],)).fetchone()
    try:
        response = requests.post('https://api.paystack.co/transaction/initialize',
            headers={'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}', 'Content-Type': 'application/json'},
            json={'email': user['email'], 'amount': amount_kobo, 'reference': ref,
                  'callback_url': url_for('paystack_callback', _external=True)}, timeout=15)
        data = response.json()
        if response.ok and data.get('status') and data.get('data', {}).get('authorization_url'):
            return redirect(data['data']['authorization_url'])
    except Exception:
        app.logger.exception('Paystack initialization failed')
    flash('We could not start the payment. No balance has been credited. Please try again later.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/paystack/callback')
@login_required
def paystack_callback():
    ref = request.args.get('reference', '').strip()
    if not ref or not PAYSTACK_SECRET_KEY or requests is None:
        flash('Payment could not be verified. Contact support before trying again.', 'error')
        return redirect(url_for('dashboard'))
    try:
        response = requests.get(f'https://api.paystack.co/transaction/verify/{ref}',
            headers={'Authorization': f'Bearer {PAYSTACK_SECRET_KEY}'}, timeout=15)
        data = response.json()
        payment = data.get('data', {})
        if response.ok and data.get('status') and payment.get('status') == 'success':
            with db() as con:
                txn = con.execute('SELECT * FROM transactions WHERE reference=? AND user_id=?', (ref, session['user_id'])).fetchone()
                if txn and txn['kind'] == 'deposit' and txn['status'] == 'pending' and payment.get('amount') == txn['amount_kobo'] and payment.get('currency') == CURRENCY:
                    con.execute("UPDATE transactions SET status='approved', note='Payment verified with Paystack', reviewed_at=? WHERE id=?", (now(), txn['id']))
                    audit(session['user_id'], 'deposit_payment_verified', ref)
                    flash('Payment verified. Your account balance has been updated.', 'success')
                else:
                    flash('Payment was returned but could not be matched safely. Contact support.', 'error')
        else:
            flash('Payment is not verified as successful. Your balance has not changed.', 'error')
    except Exception:
        app.logger.exception('Paystack verification failed')
        flash('Verification is temporarily unavailable. Your balance has not changed.', 'error')
    return redirect(url_for('dashboard'))


@app.route('/withdraw', methods=['POST'])
@login_required
def withdraw():
    try:
        amount = float(request.form.get('amount', '0'))
        amount_kobo = round(amount * 100)
        if amount_kobo < MIN_WITHDRAWAL * 100 or amount_kobo > balance_for(session['user_id']):
            raise ValueError
    except (ValueError, TypeError):
        flash(f'Enter a valid amount (minimum {CURRENCY_SYMBOL}{MIN_WITHDRAWAL:,.2f}) within your available balance.', 'error')
        return redirect(url_for('dashboard'))
    ref = 'NXW-' + secrets.token_hex(12).upper()
    with db() as con:
        con.execute("INSERT INTO transactions(user_id,kind,amount_kobo,status,reference,note,created_at) VALUES(?,?,?,?,?,?,?)",
                    (session['user_id'], 'withdrawal', amount_kobo, 'pending', ref, 'Awaiting admin review; not yet paid', now()))
    audit(session['user_id'], 'withdrawal_requested', f'{ref} {amount_kobo}')
    flash('Withdrawal request submitted for review. This does not mean a payout has been sent.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/admin')
@admin_required
def admin_dashboard():
    with db() as con:
        stats = {
            'users': con.execute("SELECT COUNT(*) n FROM users WHERE role='investor'").fetchone()['n'],
            'pending': con.execute("SELECT COUNT(*) n FROM transactions WHERE status='pending'").fetchone()['n'],
            'deposits': con.execute("SELECT COALESCE(SUM(amount_kobo),0) n FROM transactions WHERE kind='deposit' AND status='approved'").fetchone()['n'],
            'withdrawals': con.execute("SELECT COALESCE(SUM(amount_kobo),0) n FROM transactions WHERE kind='withdrawal' AND status IN ('approved','paid')").fetchone()['n'],
        }
        transactions = con.execute('SELECT t.*,u.name,u.email FROM transactions t JOIN users u ON u.id=t.user_id ORDER BY t.id DESC LIMIT 100').fetchall()
        users = con.execute('SELECT id,name,email,role,created_at FROM users ORDER BY id DESC LIMIT 100').fetchall()
        logs = con.execute('SELECT a.*,u.email FROM audit_log a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 60').fetchall()
    return render_template('admin.html', stats=stats, transactions=transactions, users=users, logs=logs)


@app.route('/admin/transaction/<int:transaction_id>', methods=['POST'])
@admin_required
def review_transaction(transaction_id):
    action = request.form.get('action')
    if action not in ('approve', 'reject', 'paid'):
        abort(400)
    with db() as con:
        txn = con.execute('SELECT * FROM transactions WHERE id=?', (transaction_id,)).fetchone()
        if not txn:
            flash('Transaction not found.', 'warning')
            return redirect(url_for('admin_dashboard'))
        if txn['kind'] == 'deposit':
            if txn['status'] != 'pending':
                flash('This deposit is no longer pending.', 'warning')
                return redirect(url_for('admin_dashboard'))
            # Deposits must be verified by Paystack before approval. Manual approval is not permitted.
            if action == 'approve' or action == 'paid':
                flash('Deposits cannot be manually approved or marked paid. Verify payment with Paystack first.', 'error')
                return redirect(url_for('admin_dashboard'))
            new_status = 'rejected'
            note = 'Rejected by administrator'
        else:
            if action == 'approve' and txn['status'] == 'pending':
                new_status = 'approved'
                note = 'Withdrawal approved by admin; payout still needs to be sent and recorded.'
            elif action == 'paid' and txn['status'] == 'approved':
                new_status = 'paid'
                note = 'Admin marked payout as sent. Reconcile against bank/payment provider records.'
            elif action == 'reject' and txn['status'] == 'pending':
                new_status = 'rejected'
                note = 'Rejected by administrator'
            else:
                flash('Invalid action for the current transaction status.', 'warning')
                return redirect(url_for('admin_dashboard'))
        con.execute('UPDATE transactions SET status=?,note=?,reviewed_at=?,reviewed_by=? WHERE id=?',
                    (new_status, note, now(), session['user_id'], transaction_id))
    audit(session['user_id'], 'transaction_reviewed', f'id={transaction_id}; action={action}')
    flash('Transaction updated.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'app': 'NEXORA CAPITAL', 'payments_configured': bool(PAYSTACK_SECRET_KEY and requests)})


@app.errorhandler(403)
def forbidden(_):
    return render_template('error.html', code=403, message='You do not have permission to access this page.'), 403


@app.errorhandler(404)
def not_found(_):
    return render_template('error.html', code=404, message='That page could not be found.'), 404


@app.errorhandler(400)
def bad_request(_):
    return render_template('error.html', code=400, message='Your request could not be validated. Refresh the page and try again.'), 400


init_db()

if __name__ == '__main__':
    app.run(debug=os.getenv('FLASK_DEBUG', '0') == '1')
