from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import json
import os
import io
import csv
import re

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change_this_to_any_random_string")

db = {
    "users": {},
    "transactions": [],
    "alerts": []
}

STAFF_INVITE_CODE = os.environ.get("STAFF_INVITE_CODE", "BANKSTAFF2026")
LARGE_WITHDRAWAL = 5000
LARGE_TRANSFER = 8000

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
PHONE_RE = re.compile(r"^\d{10}$")
UPI_RE = re.compile(r"^[a-z0-9.\-_]{2,}@[a-z]{2,}$")


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def _normalize_loaded_db(loaded):
    if not isinstance(loaded, dict):
        return {"users": {}, "transactions": [], "alerts": []}

    loaded.setdefault("users", {})
    loaded.setdefault("transactions", [])
    loaded.setdefault("alerts", [])

    if not isinstance(loaded["users"], dict):
        loaded["users"] = {}
    if not isinstance(loaded["transactions"], list):
        loaded["transactions"] = []
    if not isinstance(loaded["alerts"], list):
        loaded["alerts"] = []

    for uid, u in list(loaded["users"].items()):
        if not isinstance(u, dict):
            loaded["users"].pop(uid, None)
            continue
        u.setdefault("user_id", uid)
        u.setdefault("role", "customer")
        u.setdefault("balance", 0.0)
        try:
            u["balance"] = float(u.get("balance", 0.0))
        except Exception:
            u["balance"] = 0.0
        loaded["users"][uid] = u

    for t in loaded["transactions"]:
        if isinstance(t, dict):
            try:
                t["amount"] = round(float(t.get("amount", 0)), 2)
            except Exception:
                t["amount"] = 0.0

    return loaded

def is_logged_in():
    return "user_id" in session


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return db["users"].get(uid)


def require_role(role):
    u = current_user()
    return u and u.get("role") == role


def create_user(name, email, phone, upi, password, role="customer"):
    user_id = str(uuid.uuid4())
    user = {
        "user_id": user_id,
        "name": name.strip(),
        "email": email.strip().lower(),
        "phone": phone.strip(),
        "upi": upi.strip().lower(),
        "password_hash": generate_password_hash(password),
        "role": role,
        "balance": 0.0,
        "created_at": now_str()
    }
    db["users"][user_id] = user
    return user


def find_user_by_email(email):
    email = email.strip().lower()
    for u in db["users"].values():
        if u.get("email") == email:
            return u
    return None


def find_user_by_phone(phone):
    phone = phone.strip()
    for u in db["users"].values():
        if u.get("phone") == phone:
            return u
    return None


def find_user_by_upi(upi):
    upi = upi.strip().lower()
    if not upi:
        return None
    for u in db["users"].values():
        if u.get("upi") == upi:
            return u
    return None


def log_tx(tx_type, actor_user_id, amount, to_user_id=None, meta=None):
    tx = {
        "tx_id": str(uuid.uuid4())[:8],
        "type": tx_type,
        "amount": round(float(amount), 2),
        "from_user_id": actor_user_id,
        "to_user_id": to_user_id,
        "timestamp": now_str(),
        "meta": meta or {}
    }
    db["transactions"].append(tx)
    return tx


def create_alert(title, severity, details, tx_id=None):
    alert = {
        "alert_id": str(uuid.uuid4())[:8],
        "title": title,
        "severity": severity,
        "details": details,
        "tx_id": tx_id,
        "status": "active",
        "created_at": now_str(),
        "resolved_at": None
    }
    db["alerts"].append(alert)
    return alert


def customer_transactions(user_id):
    return [
        t for t in db["transactions"]
        if t.get("from_user_id") == user_id or t.get("to_user_id") == user_id
    ]


def customer_only_users():
    return [u for u in db["users"].values() if u.get("role") == "customer"]


def sum_amount(tx_list, tx_type, user_id=None):
    total = 0.0
    for t in tx_list:
        if t.get("type") != tx_type:
            continue

        if user_id:
            if tx_type in ("deposit", "withdraw") and t.get("from_user_id") != user_id:
                continue
            if tx_type == "transfer" and t.get("from_user_id") != user_id:
                continue

        try:
            total += float(t.get("amount", 0))
        except Exception:
            pass

    return round(total, 2)


def parse_ts(ts: str):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None

def format_inr(amount):
    try:
        amt = float(amount)
    except Exception:
        amt = 0.0
    return f"₹{amt:,.2f}"

app.jinja_env.filters["inr"] = format_inr


@app.route("/")
def index():
    return render_template("index.html", logged_in=is_logged_in(), user=current_user())


@app.route("/about")
def about():
    return render_template("about.html", logged_in=is_logged_in(), user=current_user())


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        upi = request.form.get("upi", "").strip().lower()
        password = request.form.get("password", "")

        if not (name and email and phone and password):
            flash("❌ Please fill all required fields.", "error")
            return redirect(url_for("signup"))

        if not EMAIL_RE.match(email):
            flash("❌ Enter a valid email address.", "error")
            return redirect(url_for("signup"))

        if not PHONE_RE.match(phone):
            flash("❌ Enter a valid 10-digit phone number.", "error")
            return redirect(url_for("signup"))

        if len(password) < 6:
            flash("❌ Password must be at least 6 characters.", "error")
            return redirect(url_for("signup"))

        if upi and not UPI_RE.match(upi):
            flash("❌ Enter a valid UPI ID (e.g., name@bank).", "error")
            return redirect(url_for("signup"))

        if find_user_by_email(email):
            flash("❌ Email already registered. Please login.", "error")
            return redirect(url_for("login"))
        if find_user_by_phone(phone):
            flash("❌ Phone number already registered. Use another number.", "error")
            return redirect(url_for("signup"))
        if upi and find_user_by_upi(upi):
            flash("❌ UPI ID already registered. Use another UPI.", "error")
            return redirect(url_for("signup"))

        create_user(name, email, phone, upi, password, role="customer")
        flash("✅ Account created successfully! Please login to continue.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", user=current_user())


@app.route("/staff-signup", methods=["GET", "POST"])
def staff_signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        invite = request.form.get("invite", "").strip()

        if invite != STAFF_INVITE_CODE:
            flash("❌ Invalid staff invite code.", "error")
            return redirect(url_for("staff_signup"))

        if not (name and email and phone and password):
            flash("❌ Please fill all required fields.", "error")
            return redirect(url_for("staff_signup"))

        if not EMAIL_RE.match(email):
            flash("❌ Enter a valid email address.", "error")
            return redirect(url_for("staff_signup"))

        if not PHONE_RE.match(phone):
            flash("❌ Enter a valid 10-digit phone number.", "error")
            return redirect(url_for("staff_signup"))

        if len(password) < 6:
            flash("❌ Password must be at least 6 characters.", "error")
            return redirect(url_for("staff_signup"))

        if find_user_by_email(email) or find_user_by_phone(phone):
            flash("❌ Email/Phone already registered.", "error")
            return redirect(url_for("staff_signup"))

        create_user(name, email, phone, upi="", password=password, role="staff")
        flash("✅ Staff account created! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html", staff_mode=True, user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        role = request.form.get("role", "customer")
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not (email and password):
            flash("❌ Please enter email and password.", "error")
            return redirect(url_for("login"))

        if not EMAIL_RE.match(email):
            flash("❌ Enter a valid email address.", "error")
            return redirect(url_for("login"))

        user = find_user_by_email(email)
        if not user:
            flash("❌ Account not found. Please sign up.", "error")
            return redirect(url_for("signup"))

        if user.get("role") != role:
            flash("❌ Role mismatch. Choose the correct login type.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(user.get("password_hash", ""), password):
            flash("❌ Invalid password.", "error")
            return redirect(url_for("login"))

        session["user_id"] = user["user_id"]
        flash("✅ Login successful.", "success")
        return redirect(url_for("staff_dashboard" if role == "staff" else "customer_dashboard"))

    return render_template("login.html", role_selected="customer", user=current_user())


@app.route("/logout")
def logout():
    session.clear()
    flash("✅ Logged out successfully.", "success")
    return redirect(url_for("index"))


@app.route("/customer/dashboard")
def customer_dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("customer"):
        return "Access Denied", 403

    user = current_user()
    txs_sorted = sorted(customer_transactions(user["user_id"]), key=lambda x: x.get("timestamp", ""), reverse=True)

    total_deposits = sum_amount(txs_sorted, "deposit", user_id=user["user_id"])
    total_withdrawals = sum_amount(txs_sorted, "withdraw", user_id=user["user_id"])
    total_transfers = sum_amount(txs_sorted, "transfer", user_id=user["user_id"])

    return render_template(
        "customer_dashboard.html",
        user=user,
        txs=txs_sorted[:5],
        totals={
            "deposits": total_deposits,
            "withdrawals": total_withdrawals,
            "transfers": total_transfers,
            "transactions": len(txs_sorted)
        }
    )


@app.route("/customer/transactions", methods=["GET", "POST"])
def customer_transactions_page():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("customer"):
        return "Access Denied", 403

    user = current_user()
    mode = request.args.get("mode", "deposit")

    if request.method == "POST":
        action = request.form.get("action")

        if action == "deposit":
            try:
                amount = float(request.form.get("amount", "0"))
            except ValueError:
                amount = 0

            if amount <= 0:
                flash("❌ Deposit must be greater than zero.", "error")
                return redirect(url_for("customer_transactions_page", mode="deposit"))

            user["balance"] = round(float(user.get("balance", 0)) + amount, 2)
            db["users"][user["user_id"]] = user
            log_tx("deposit", user["user_id"], amount)

            flash(f"✅ Deposited {format_inr(amount)} successfully.", "success")
            return redirect(url_for("customer_transactions_page", mode="deposit"))

        elif action == "withdraw":
            try:
                amount = float(request.form.get("amount", "0"))
            except ValueError:
                amount = 0

            if amount <= 0:
                flash("❌ Withdrawal must be greater than zero.", "error")
                return redirect(url_for("customer_transactions_page", mode="withdraw"))

            if amount > float(user.get("balance", 0)):
                flash("❌ Insufficient balance.", "error")
                return redirect(url_for("customer_transactions_page", mode="withdraw"))

            user["balance"] = round(float(user.get("balance", 0)) - amount, 2)
            db["users"][user["user_id"]] = user
            tx = log_tx("withdraw", user["user_id"], amount)

            if amount >= LARGE_WITHDRAWAL:
                create_alert(
                    title="Large cash withdrawal flagged",
                    severity="medium",
                    details=f"User {user['name']} withdrew {format_inr(amount)}.",
                    tx_id=tx["tx_id"]
                )

            flash(f"✅ Withdrawn {format_inr(amount)} successfully.", "success")
            return redirect(url_for("customer_transactions_page", mode="withdraw"))

        elif action == "transfer":
            identifier_type = request.form.get("identifier_type", "phone")
            identifier_value = request.form.get("identifier_value", "").strip()
            note = request.form.get("note", "").strip()

            try:
                amount = float(request.form.get("amount", "0"))
            except ValueError:
                amount = 0

            if amount <= 0:
                flash("❌ Transfer must be greater than zero.", "error")
                return redirect(url_for("customer_transactions_page", mode="transfer"))

            if amount > float(user.get("balance", 0)):
                flash("❌ Insufficient balance.", "error")
                return redirect(url_for("customer_transactions_page", mode="transfer"))

            if not identifier_value:
                flash("❌ Enter receiver phone/UPI.", "error")
                return redirect(url_for("customer_transactions_page", mode="transfer"))

            receiver = None

            if identifier_type == "phone":
                if not PHONE_RE.match(identifier_value):
                    flash("❌ Enter a valid 10-digit receiver phone number.", "error")
                    return redirect(url_for("customer_transactions_page", mode="transfer"))
                receiver = find_user_by_phone(identifier_value)

            elif identifier_type == "upi":
                if not UPI_RE.match(identifier_value.lower()):
                    flash("❌ Enter a valid receiver UPI ID.", "error")
                    return redirect(url_for("customer_transactions_page", mode="transfer"))
                receiver = find_user_by_upi(identifier_value)

            if not receiver or receiver.get("role") != "customer":
                flash("❌ Receiver not found.", "error")
                return redirect(url_for("customer_transactions_page", mode="transfer"))

            if receiver["user_id"] == user["user_id"]:
                flash("❌ Cannot transfer to your own account.", "error")
                return redirect(url_for("customer_transactions_page", mode="transfer"))

            user["balance"] = round(float(user.get("balance", 0)) - amount, 2)
            receiver["balance"] = round(float(receiver.get("balance", 0)) + amount, 2)

            db["users"][user["user_id"]] = user
            db["users"][receiver["user_id"]] = receiver

            tx = log_tx(
                "transfer",
                actor_user_id=user["user_id"],
                amount=amount,
                to_user_id=receiver["user_id"],
                meta={
                    "to_phone": receiver.get("phone", ""),
                    "to_upi": receiver.get("upi", ""),
                    "note": note
                }
            )

            if amount >= LARGE_TRANSFER:
                create_alert(
                    title="Unusual transfer amount flagged",
                    severity="high",
                    details=f"Transfer of {format_inr(amount)} from {user['name']} to {receiver['name']} flagged.",
                    tx_id=tx["tx_id"]
                )

            flash(f"✅ Transferred {format_inr(amount)} to {receiver['name']} successfully.", "success")
            return redirect(url_for("customer_transactions_page", mode="transfer"))

    return render_template("customer_transactions.html", user=user, mode=mode)


@app.route("/customer/history")
def customer_history():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("customer"):
        return "Access Denied", 403

    user = current_user()
    q = request.args.get("q", "").strip().lower()

    txs_sorted = sorted(customer_transactions(user["user_id"]), key=lambda x: x.get("timestamp", ""), reverse=True)

    if q:
        def tx_matches(t):
            s = f"{t.get('type','')} {t.get('amount','')} {t.get('timestamp','')} {t.get('tx_id','')} {json.dumps(t.get('meta',{}))}"
            return q in s.lower()
        txs_sorted = [t for t in txs_sorted if tx_matches(t)]

    def tx_view(t):
        from_u = db["users"].get(t.get("from_user_id"))
        to_u = db["users"].get(t.get("to_user_id")) if t.get("to_user_id") else None
        return {
            **t,
            "from_name": from_u.get("name") if from_u else "-",
            "to_name": to_u.get("name") if to_u else "-",
        }

    txs_view = [tx_view(t) for t in txs_sorted]
    return render_template("customer_history.html", user=user, txs=txs_view, q=q)


@app.route("/customer/export-csv")
def customer_export_csv():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("customer"):
        return "Access Denied", 403

    user = current_user()
    txs = sorted(customer_transactions(user["user_id"]), key=lambda x: x.get("timestamp", ""), reverse=True)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["TX_ID", "TYPE", "AMOUNT", "FROM", "TO", "TIMESTAMP", "NOTE/DETAILS"])

    for t in txs:
        from_u = db["users"].get(t.get("from_user_id"))
        to_u = db["users"].get(t.get("to_user_id")) if t.get("to_user_id") else None
        writer.writerow([
            t.get("tx_id"), t.get("type"), t.get("amount"),
            from_u.get("name") if from_u else "-",
            to_u.get("name") if to_u else "-",
            t.get("timestamp"),
            json.dumps(t.get("meta", {}), ensure_ascii=False)
        ])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    filename = f"transactions_{user['name'].replace(' ', '_')}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=filename)


@app.route("/staff/dashboard")
def staff_dashboard():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    customers = customer_only_users()
    customer_count = len(customers)

    total_volume = round(sum(float(t.get("amount", 0)) for t in db["transactions"]), 2)
    total_txs = len(db["transactions"])
    active_alerts_count = len([a for a in db["alerts"] if a.get("status") == "active"])

    txs_sorted = sorted(db["transactions"], key=lambda x: x.get("timestamp", ""), reverse=True)
    alerts_sorted = sorted(db["alerts"], key=lambda x: x.get("created_at", ""), reverse=True)

    last_tx_time = txs_sorted[0].get("timestamp") if txs_sorted else None
    last_alert_time = alerts_sorted[0].get("created_at") if alerts_sorted else None

    flagged_count = len([
        a for a in db["alerts"]
        if a.get("status") == "active" and a.get("tx_id")
    ])

    top_customers = sorted(customers, key=lambda u: float(u.get("balance", 0)), reverse=True)[:5]
    active_alerts_preview = [a for a in alerts_sorted if a.get("status") == "active"][:3]
    recent_txs = txs_sorted[:6]

    return render_template(
        "staff_dashboard.html",
        user=current_user(),
        stats={
            "customers": customer_count,
            "total_volume": total_volume,
            "transactions": total_txs,
            "active_alerts": active_alerts_count
        },
        snapshot={
            "last_tx_time": last_tx_time,
            "last_alert_time": last_alert_time,
            "flagged_count": flagged_count
        },
        top_customers=top_customers,
        active_alerts_preview=active_alerts_preview,
        recent_txs=recent_txs
    )


@app.route("/staff/analytics")
def staff_analytics():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    customers = customer_only_users()
    total_balance = round(sum(float(u.get("balance", 0)) for u in customers), 2)
    active_users = len(customers)

    deposits = sum_amount(db["transactions"], "deposit")
    withdrawals = sum_amount(db["transactions"], "withdraw")
    transfers = sum_amount(db["transactions"], "transfer")

    flagged = len([a for a in db["alerts"] if a.get("status") == "active"])

    now = datetime.now()
    month_keys = []
    for i in range(5, -1, -1):
        y = now.year
        m = now.month - i
        while m <= 0:
            m += 12
            y -= 1
        month_keys.append(f"{y}-{m:02d}")

    month_labels = [datetime.strptime(k, "%Y-%m").strftime("%b") for k in month_keys]
    monthly = {k: {"deposit": 0.0, "withdraw": 0.0, "transfer": 0.0} for k in month_keys}

    for t in db["transactions"]:
        ts = parse_ts(t.get("timestamp", ""))
        if not ts:
            continue
        key = f"{ts.year}-{ts.month:02d}"
        if key not in monthly:
            continue
        typ = t.get("type")
        if typ in monthly[key]:
            monthly[key][typ] += float(t.get("amount", 0))

    monthly_deposits = [round(monthly[k]["deposit"], 2) for k in month_keys]
    monthly_withdrawals = [round(monthly[k]["withdraw"], 2) for k in month_keys]
    monthly_transfers = [round(monthly[k]["transfer"], 2) for k in month_keys]

    return render_template(
        "staff_analytics.html",
        user=current_user(),
        cards={
            "total_balance": total_balance,
            "active_users": active_users,
            "total_volume": round(deposits + withdrawals + transfers, 2),
            "transactions": len(db["transactions"]),
            "flagged": flagged
        },
        dist={"deposits": deposits, "withdrawals": withdrawals, "transfers": transfers},
        monthly_labels=month_labels,
        monthly_deposits=monthly_deposits,
        monthly_withdrawals=monthly_withdrawals,
        monthly_transfers=monthly_transfers,
    )


@app.route("/staff/alerts", methods=["GET", "POST"])
def staff_alerts():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    if request.method == "POST":
        alert_id = request.form.get("alert_id")
        for a in db["alerts"]:
            if a.get("alert_id") == alert_id and a.get("status") == "active":
                a["status"] = "resolved"
                a["resolved_at"] = now_str()
                break
        flash("✅ Alert resolved.", "success")
        return redirect(url_for("staff_alerts"))

    alerts_sorted = sorted(db["alerts"], key=lambda x: x.get("created_at", ""), reverse=True)
    active = [a for a in alerts_sorted if a.get("status") == "active"]
    resolved = [a for a in alerts_sorted if a.get("status") == "resolved"]

    return render_template("staff_alerts.html", user=current_user(), active=active, resolved=resolved)


@app.route("/staff/compliance")
def staff_compliance():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    customers = customer_only_users()

    kyc_completed = len([u for u in customers if u.get("phone") and u.get("upi")])
    kyc_rate = int((kyc_completed / max(len(customers), 1)) * 100)

    active_alerts = len([a for a in db["alerts"] if a.get("status") == "active"])
    aml_score = max(0, 100 - active_alerts * 10)

    reporting_compliance = 85 if active_alerts > 0 else 95
    overall = int((kyc_rate + aml_score + reporting_compliance) / 3)

    scores = {
        "overall": overall,
        "aml": aml_score,
        "kyc": kyc_rate,
        "reporting": reporting_compliance
    }

    monitoring = 100

    return render_template(
        "staff_compliance.html",
        user=current_user(),
        scores=scores,
        monitoring=monitoring
    )


@app.route("/staff/reports", methods=["GET", "POST"])
def staff_reports():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    report = None
    if request.method == "POST":
        report_type = request.form.get("report_type", "quarterly")

        customers = customer_only_users()
        total_users = len(customers)
        total_balance = round(sum(float(u.get("balance", 0)) for u in customers), 2)

        deposits = sum_amount(db["transactions"], "deposit")
        withdrawals = sum_amount(db["transactions"], "withdraw")
        transfers = sum_amount(db["transactions"], "transfer")

        report = {
            "type": report_type,
            "generated_at": now_str(),
            "total_users": total_users,
            "total_balance": total_balance,
            "deposits": deposits,
            "withdrawals": withdrawals,
            "transfers": transfers,
            "active_alerts": len([a for a in db["alerts"] if a.get("status") == "active"])
        }

        flash("✅ Report generated.", "success")

    return render_template("staff_reports.html", user=current_user(), report=report)


@app.route("/staff/export-report-csv")
def staff_export_report_csv():
    if not is_logged_in():
        return redirect(url_for("login"))
    if not require_role("staff"):
        return "Access Denied", 403

    customers = customer_only_users()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["CUSTOMER_NAME", "EMAIL", "PHONE", "UPI", "BALANCE", "CREATED_AT"])

    for u in customers:
        writer.writerow([
            u.get("name", ""),
            u.get("email", ""),
            u.get("phone", ""),
            u.get("upi", ""),
            u.get("balance", 0),
            u.get("created_at", "")
        ])

    mem = io.BytesIO(output.getvalue().encode("utf-8"))
    mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name="customers_report.csv")

if __name__ == "__main__":
    app.run(debug=True)