from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import uuid
import boto3
from boto3.dynamodb.conditions import Attr
from decimal import Decimal
import os
import io
import csv
import json
import re

app = Flask(__name__)
app.secret_key = "cloud-bank-secret"

REGION = "us-east-1"

USERS_TABLE = "CloudBankUsers"
TX_TABLE = "CloudBankTransactions"
ALERTS_TABLE = "CloudBankAlerts"

dynamodb = boto3.resource("dynamodb", region_name=REGION)
users_table = dynamodb.Table(USERS_TABLE)
tx_table = dynamodb.Table(TX_TABLE)
alerts_table = dynamodb.Table(ALERTS_TABLE)

STAFF_INVITE_CODE = "BANKSTAFF2026"
LARGE_WITHDRAWAL = 5000
LARGE_TRANSFER = 8000

EMAIL_RE = re.compile(r"^[^@]+@[^@]+\.[^@]+$")
PHONE_RE = re.compile(r"^\d{10}$")
UPI_RE = re.compile(r"^[a-z0-9.\-_]{2,}@[a-z]{2,}$")

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def d(x):
    return Decimal(str(round(float(x), 2)))

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    res = users_table.get_item(Key={"user_id": uid})
    return res.get("Item")

def login_required(role=None):
    user = current_user()
    if not user:
        return False
    if role and user["role"] != role:
        return False
    return True

def find_user_by_email(email):
    res = users_table.scan(FilterExpression=Attr("email").eq(email))
    return res["Items"][0] if res["Items"] else None

def find_user_by_phone(phone):
    res = users_table.scan(FilterExpression=Attr("phone").eq(phone))
    return res["Items"][0] if res["Items"] else None

def find_user_by_upi(upi):
    res = users_table.scan(FilterExpression=Attr("upi").eq(upi))
    return res["Items"][0] if res["Items"] else None


@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method == "POST":
        user = {
            "user_id": str(uuid.uuid4()),
            "name": request.form["name"],
            "email": request.form["email"].lower(),
            "phone": request.form["phone"],
            "upi": request.form.get("upi","").lower(),
            "password_hash": generate_password_hash(request.form["password"]),
            "role": "customer",
            "balance": d(0),
            "created_at": now()
        }
        users_table.put_item(Item=user)
        flash("Account created")
        return redirect(url_for("login"))
    return render_template("signup.html")

@app.route("/staff-signup", methods=["GET","POST"])
def staff_signup():
    if request.method == "POST":
        if request.form["invite"] != STAFF_INVITE_CODE:
            flash("Invalid staff code")
            return redirect(url_for("staff_signup"))

        user = {
            "user_id": str(uuid.uuid4()),
            "name": request.form["name"],
            "email": request.form["email"].lower(),
            "phone": request.form["phone"],
            "upi": "",
            "password_hash": generate_password_hash(request.form["password"]),
            "role": "staff",
            "balance": d(0),
            "created_at": now()
        }
        users_table.put_item(Item=user)
        flash("Staff account created")
        return redirect(url_for("login"))
    return render_template("signup.html", staff_mode=True)

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        user = find_user_by_email(request.form["email"].lower())
        if not user or not check_password_hash(user["password_hash"], request.form["password"]):
            flash("Invalid login")
            return redirect(url_for("login"))
        session["user_id"] = user["user_id"]
        return redirect(url_for("staff_dashboard" if user["role"]=="staff" else "customer_dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- CUSTOMER ----------------
@app.route("/customer/dashboard")
def customer_dashboard():
    if not login_required("customer"):
        return redirect(url_for("login"))
    user = current_user()
    return render_template("customer_dashboard.html", user=user)

@app.route("/customer/transactions", methods=["GET","POST"])
def customer_transactions():
    if not login_required("customer"):
        return redirect(url_for("login"))
    user = current_user()
    action = request.form.get("action")

    if request.method == "POST":
        amount = float(request.form["amount"])
        balance = float(user["balance"])

        if action == "deposit":
            new_balance = balance + amount

        elif action == "withdraw":
            if amount > balance:
                flash("Insufficient balance")
                return redirect(url_for("customer_transactions"))
            new_balance = balance - amount

        elif action == "transfer":
            receiver = find_user_by_phone(request.form["identifier"]) or find_user_by_upi(request.form["identifier"])
            if not receiver:
                flash("Receiver not found")
                return redirect(url_for("customer_transactions"))
            if amount > balance:
                flash("Insufficient balance")
                return redirect(url_for("customer_transactions"))

            users_table.update_item(
                Key={"user_id": receiver["user_id"]},
                UpdateExpression="SET balance = :b",
                ExpressionAttributeValues={":b": d(float(receiver["balance"]) + amount)}
            )
            new_balance = balance - amount

        users_table.update_item(
            Key={"user_id": user["user_id"]},
            UpdateExpression="SET balance = :b",
            ExpressionAttributeValues={":b": d(new_balance)}
        )

        tx_table.put_item(Item={
            "tx_id": str(uuid.uuid4())[:8],
            "type": action,
            "amount": d(amount),
            "from_user_id": user["user_id"],
            "to_user_id": receiver["user_id"] if action=="transfer" else "",
            "timestamp": now(),
            "meta": {}
        })

        flash("Transaction successful")
        return redirect(url_for("customer_transactions"))

    return render_template("customer_transactions.html", user=user)

# ---------------- STAFF ----------------
@app.route("/staff/dashboard")
def staff_dashboard():
    if not login_required("staff"):
        return redirect(url_for("login"))
    users = users_table.scan(FilterExpression=Attr("role").eq("customer"))["Items"]
    txs = tx_table.scan()["Items"]
    alerts = alerts_table.scan()["Items"]
    return render_template("staff_dashboard.html", users=users, txs=txs, alerts=alerts)

@app.route("/staff/alerts", methods=["GET","POST"])
def staff_alerts():
    if not login_required("staff"):
        return redirect(url_for("login"))
    if request.method == "POST":
        alerts_table.update_item(
            Key={"alert_id": request.form["alert_id"]},
            UpdateExpression="SET #s='resolved'",
            ExpressionAttributeNames={"#s":"status"}
        )
    alerts = alerts_table.scan()["Items"]
    return render_template("staff_alerts.html", alerts=alerts)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)