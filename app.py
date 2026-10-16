import csv
import io
import re
import secrets
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from functools import wraps

from flask import (
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from sqlalchemy import create_engine, func, inspect, or_, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import IntegrityError

from config import Config
from extensions import db
from models import AuditLog, LeakAlert, RecoveryCase, Transaction, User
from services.detector import detect_transaction


def _ensure_database_exists(database_uri: str) -> None:
    """Create the configured MySQL database on first run when permitted."""
    url = make_url(database_uri)
    if url.get_backend_name() != "mysql" or not url.database:
        return
    if not re.fullmatch(r"[A-Za-z0-9_$-]+", url.database):
        raise RuntimeError("DB_NAME contains unsupported characters.")
    server_engine = create_engine(url.set(database=None), pool_pre_ping=True)
    try:
        with server_engine.begin() as connection:
            connection.execute(
                text(
                    f"CREATE DATABASE IF NOT EXISTS `{url.database}` "
                    "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
                )
            )
    finally:
        server_engine.dispose()


app = Flask(__name__)
app.config.from_object(Config)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
_ensure_database_exists(app.config["SQLALCHEMY_DATABASE_URI"])
db.init_app(app)


PAYMENT_STATUSES = {"Pending", "Partially Paid", "Paid", "Overdue", "Refunded"}
ALERT_STATUSES = {"Open", "In Review", "Confirmed", "Recovered", "False Positive", "Resolved"}
OPEN_ALERT_STATUSES = {"Open", "In Review", "Confirmed"}
USER_ROLES = {"Admin", "Analyst", "Viewer"}
ACCOUNT_STATUSES = {"Pending", "Active", "Disabled"}
RECOVERY_STATUSES = {"Planned", "In Progress", "Recovered", "Closed"}
RECOVERY_PRIORITIES = {"Low", "Medium", "High", "Critical"}
RECOVERY_ACTIONS = {
    "Review invoice",
    "Correct billing",
    "Contact customer",
    "Adjust discount",
    "Escalate to finance",
}
CSV_HEADERS = [
    "transaction_code",
    "customer_name",
    "transaction_date",
    "expected_amount",
    "billed_amount",
    "paid_amount",
    "discount_percent",
    "payment_status",
    "due_date",
    "service_active",
]


def _ensure_default_admin() -> None:
    if User.query.filter_by(role="Admin").first() is None:
        admin = User(
            name=app.config["ADMIN_NAME"],
            email=app.config["ADMIN_EMAIL"].strip().lower(),
            company="RevenueLeak AI",
            role="Admin",
            approval_status="Active",
            active=True,
        )
        admin.set_password(app.config["ADMIN_PASSWORD"])
        db.session.add(admin)
        db.session.commit()


def _ensure_user_columns() -> None:
    """Add account fields when upgrading an older project database."""
    columns = {column["name"] for column in inspect(db.engine).get_columns("users")}
    statements = []
    if "company" not in columns:
        statements.append("ALTER TABLE users ADD COLUMN company VARCHAR(120) NOT NULL DEFAULT ''")
    if "approval_status" not in columns:
        statements.append(
            "ALTER TABLE users ADD COLUMN approval_status VARCHAR(20) NOT NULL DEFAULT 'Active'"
        )
    for statement in statements:
        db.session.execute(text(statement))
    if statements:
        db.session.commit()


with app.app_context():
    db.create_all()
    _ensure_user_columns()
    _ensure_default_admin()


@app.template_filter("money")
def money_filter(value) -> str:
    return f"₹{Decimal(value or 0):,.2f}"


@app.before_request
def load_user_and_protect_forms():
    user_id = session.get("user_id")
    g.user = db.session.get(User, user_id) if user_id else None
    if g.user and (not g.user.active or g.user.approval_status != "Active"):
        session.clear()
        g.user = None

    if "_csrf_token" not in session:
        session["_csrf_token"] = secrets.token_hex(24)

    if request.method == "POST":
        submitted = request.form.get("_csrf_token", "")
        expected = session.get("_csrf_token", "")
        if not submitted or not secrets.compare_digest(submitted, expected):
            abort(400, "The form expired. Refresh the page and try again.")


@app.context_processor
def inject_navigation_context():
    return {
        "current_user": g.get("user"),
        "csrf_token": session.get("_csrf_token", ""),
    }


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if g.user is None:
                return redirect(url_for("login", next=request.path))
            if g.user.role not in roles:
                abort(403)
            return view(*args, **kwargs)

        return wrapped

    return decorator


def _safe_next(default_endpoint: str) -> str:
    target = request.form.get("next", "")
    if target.startswith("/") and not target.startswith("//"):
        return target
    return url_for(default_endpoint)


def _audit(action: str, entity_type: str, entity_id=None, detail: str = "") -> None:
    db.session.add(
        AuditLog(
            actor_id=g.user.id if g.get("user") else None,
            action=action,
            entity_type=entity_type,
            entity_id=entity_id,
            detail=detail[:255],
        )
    )


def _money(value, field_name: str) -> Decimal:
    try:
        amount = Decimal(value)
    except (InvalidOperation, TypeError):
        raise ValueError(f"{field_name} must be a valid number.")
    if amount < 0:
        raise ValueError(f"{field_name} cannot be negative.")
    return amount.quantize(Decimal("0.01"))


def _parse_date(value: str, field_name: str, required=False):
    value = (value or "").strip()
    if not value and not required:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"{field_name} must use YYYY-MM-DD.")


def _fill_transaction(transaction: Transaction) -> None:
    transaction_code = request.form.get("transaction_code", "").strip()
    customer_name = request.form.get("customer_name", "").strip()
    if not transaction_code or not customer_name:
        raise ValueError("Transaction code and customer name are required.")

    transaction.transaction_code = transaction_code
    transaction.customer_name = customer_name
    transaction.transaction_date = _parse_date(
        request.form.get("transaction_date"), "Transaction date", required=True
    )
    transaction.expected_amount = _money(request.form.get("expected_amount"), "Expected amount")
    transaction.billed_amount = _money(request.form.get("billed_amount"), "Billed amount")
    transaction.paid_amount = _money(request.form.get("paid_amount"), "Paid amount")
    transaction.discount_percent = _money(
        request.form.get("discount_percent", "0"), "Discount"
    )
    if transaction.discount_percent > 100:
        raise ValueError("Discount cannot exceed 100%.")

    payment_status = request.form.get("payment_status", "Pending")
    if payment_status not in PAYMENT_STATUSES:
        raise ValueError("Choose a valid payment status.")
    transaction.payment_status = payment_status
    transaction.due_date = _parse_date(request.form.get("due_date"), "Due date")
    transaction.service_active = request.form.get("service_active") == "on"


def _transaction_from_csv(row: dict, row_number: int) -> Transaction:
    code = (row.get("transaction_code") or "").strip()
    customer = (row.get("customer_name") or "").strip()
    if not code or not customer:
        raise ValueError(f"Row {row_number}: transaction_code and customer_name are required.")

    transaction_date = _parse_date(
        row.get("transaction_date"), f"Row {row_number} transaction_date", required=True
    )
    due_date = _parse_date(row.get("due_date"), f"Row {row_number} due_date")
    expected = _money(row.get("expected_amount"), f"Row {row_number} expected_amount")
    billed = _money(row.get("billed_amount"), f"Row {row_number} billed_amount")
    paid = _money(row.get("paid_amount"), f"Row {row_number} paid_amount")
    discount = _money(row.get("discount_percent", "0"), f"Row {row_number} discount_percent")
    if discount > 100:
        raise ValueError(f"Row {row_number}: discount_percent cannot exceed 100.")

    payment_status = (row.get("payment_status") or "Pending").strip()
    if payment_status not in PAYMENT_STATUSES:
        allowed = ", ".join(sorted(PAYMENT_STATUSES))
        raise ValueError(f"Row {row_number}: payment_status must be one of: {allowed}.")

    active_value = (row.get("service_active") or "yes").strip().lower()
    if active_value not in {"yes", "no", "true", "false", "1", "0", "y", "n"}:
        raise ValueError(f"Row {row_number}: service_active must be yes or no.")

    return Transaction(
        transaction_code=code,
        customer_name=customer,
        transaction_date=transaction_date,
        expected_amount=expected,
        billed_amount=billed,
        paid_amount=paid,
        discount_percent=discount,
        payment_status=payment_status,
        due_date=due_date,
        service_active=active_value in {"yes", "true", "1", "y"},
    )


def _transaction_query():
    query = Transaction.query
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip()
    date_from = _parse_date(request.args.get("date_from", ""), "From date")
    date_to = _parse_date(request.args.get("date_to", ""), "To date")

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(Transaction.transaction_code.ilike(like), Transaction.customer_name.ilike(like))
        )
    if status in PAYMENT_STATUSES:
        query = query.filter(Transaction.payment_status == status)
    if date_from:
        query = query.filter(Transaction.transaction_date >= date_from)
    if date_to:
        query = query.filter(Transaction.transaction_date <= date_to)
    if risk == "flagged":
        query = query.join(LeakAlert).filter(LeakAlert.status.in_(OPEN_ALERT_STATUSES)).distinct()
    if risk == "clear":
        flagged_ids = db.session.query(LeakAlert.transaction_id).filter(
            LeakAlert.status.in_(OPEN_ALERT_STATUSES)
        )
        query = query.filter(~Transaction.id.in_(flagged_ids))
    return query.order_by(Transaction.transaction_date.desc(), Transaction.id.desc())


def _alert_query():
    query = LeakAlert.query.join(Transaction)
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    severity = request.args.get("severity", "").strip()
    leak_type = request.args.get("type", "").strip()
    date_from = _parse_date(request.args.get("date_from", ""), "From date")
    date_to = _parse_date(request.args.get("date_to", ""), "To date")

    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(
                Transaction.transaction_code.ilike(like),
                Transaction.customer_name.ilike(like),
                LeakAlert.leak_type.ilike(like),
            )
        )
    if status in ALERT_STATUSES:
        query = query.filter(LeakAlert.status == status)
    if severity in {"Low", "Medium", "High", "Critical"}:
        query = query.filter(LeakAlert.severity == severity)
    if leak_type:
        query = query.filter(LeakAlert.leak_type == leak_type)
    if date_from:
        query = query.filter(func.date(LeakAlert.detected_at) >= date_from)
    if date_to:
        query = query.filter(func.date(LeakAlert.detected_at) <= date_to)
    return query.order_by(LeakAlert.risk_score.desc(), LeakAlert.detected_at.desc())


def _scan_all_transactions() -> int:
    transactions = Transaction.query.all()
    detected_count = 0
    for transaction in transactions:
        detected = detect_transaction(transaction, transactions)
        detected_types = {item["leak_type"] for item in detected}
        for item in detected:
            alert = LeakAlert.query.filter_by(
                transaction_id=transaction.id, leak_type=item["leak_type"]
            ).first()
            if alert is None:
                alert = LeakAlert(transaction_id=transaction.id, leak_type=item["leak_type"])
                db.session.add(alert)
            alert.estimated_loss = item["estimated_loss"]
            alert.risk_score = item["risk_score"]
            alert.severity = item["severity"]
            alert.explanation = item["explanation"]
            if alert.status == "Resolved":
                alert.status = "Open"
            alert.detected_at = datetime.now(timezone.utc).replace(tzinfo=None)
            detected_count += 1

        for alert in LeakAlert.query.filter_by(transaction_id=transaction.id).all():
            if alert.leak_type not in detected_types and alert.status not in {"Recovered", "False Positive"}:
                alert.status = "Resolved"
    return detected_count


def _seed_demo_transactions() -> int:
    today = date.today()
    records = [
        ("DEMO-1001", "Axion Corp", -175, 120000, 120000, 120000, 5, "Paid", -145, True),
        ("DEMO-1002", "Vanguard Dynamics", -150, 180000, 176000, 176000, 8, "Paid", -120, True),
        ("DEMO-1003", "Meridian Capital", -125, 95000, 95000, 95000, 10, "Paid", -95, True),
        ("DEMO-1004", "Stratos Financial", -100, 210000, 205000, 205000, 6, "Paid", -70, True),
        ("DEMO-1005", "Northstar Retail", -75, 150000, 118000, 70000, 24, "Overdue", -35, True),
        ("DEMO-1006", "BluePeak Telecom", -62, 260000, 260000, 155000, 9, "Overdue", -24, True),
        ("DEMO-1007", "Orbit Health", -48, 80000, 54000, 54000, 32, "Partially Paid", -18, True),
        ("DEMO-1008", "Cedar Logistics", -35, 140000, 140000, 112000, 12, "Partially Paid", -5, True),
        ("DEMO-1009", "Nexa Manufacturing", -22, 320000, 0, 0, 0, "Pending", 8, True),
        ("DEMO-1010", "Vertex Labs", -16, 70000, 68000, 68000, 5, "Paid", 14, True),
        ("DEMO-1011", "Solace Energy", -9, 110000, 107000, 30000, 18, "Pending", 21, True),
        ("DEMO-1012", "Harbor Foods", -3, 90000, 89000, 0, 7, "Pending", 27, True),
    ]
    existing = {code for (code,) in db.session.query(Transaction.transaction_code).all()}
    added = 0
    for code, customer, txn_offset, expected, billed, paid, discount, status, due_offset, active in records:
        if code in existing:
            continue
        db.session.add(
            Transaction(
                transaction_code=code,
                customer_name=customer,
                transaction_date=today + timedelta(days=txn_offset),
                expected_amount=expected,
                billed_amount=billed,
                paid_amount=paid,
                discount_percent=discount,
                payment_status=status,
                due_date=today + timedelta(days=due_offset),
                service_active=active,
            )
        )
        added += 1
    db.session.flush()
    return added


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    try:
        db.session.execute(text("SELECT 1"))
        return {"status": "healthy", "service": "RevenueLeak AI"}
    except Exception:
        return {"status": "unhealthy", "service": "RevenueLeak AI"}, 503


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        company = request.form.get("company", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not company or not email:
            flash("Name, company and email are required.", "error")
        elif "@" not in email or "." not in email.rsplit("@", 1)[-1]:
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        elif User.query.filter_by(email=email).first():
            flash("An account with that email already exists.", "error")
        else:
            user = User(
                name=name,
                company=company,
                email=email,
                role="Viewer",
                active=False,
                approval_status="Pending",
            )
            user.set_password(password)
            db.session.add(user)
            try:
                db.session.commit()
                flash(
                    "Account created. An administrator must approve it before you can sign in.",
                    "success",
                )
                return redirect(url_for("login"))
            except IntegrityError:
                db.session.rollback()
                flash("An account with that email already exists.", "error")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            if user.approval_status == "Pending":
                flash("Your account is waiting for administrator approval.", "error")
                return render_template("login.html")
            if not user.active or user.approval_status == "Disabled":
                flash("Your account has been disabled. Contact an administrator.", "error")
                return render_template("login.html")
            session.clear()
            session["user_id"] = user.id
            session["_csrf_token"] = secrets.token_hex(24)
            session.permanent = True
            g.user = user
            _audit("Signed in", "User", user.id, user.email)
            db.session.commit()
            next_url = request.args.get("next", "")
            if not next_url.startswith("/") or next_url.startswith("//"):
                next_url = url_for("dashboard")
            return redirect(next_url)
        flash("Incorrect email or password.", "error")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    _audit("Signed out", "User", g.user.id, g.user.email)
    db.session.commit()
    session.clear()
    flash("You have been signed out.", "success")
    return redirect(url_for("login"))


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        company = request.form.get("company", "").strip()
        password = request.form.get("password", "")
        if not name or not company:
            flash("Name and company are required.", "error")
        elif password and len(password) < 8:
            flash("A new password must contain at least 8 characters.", "error")
        else:
            g.user.name = name
            g.user.company = company
            if password:
                g.user.set_password(password)
            _audit("Updated profile", "User", g.user.id, g.user.email)
            db.session.commit()
            flash("Profile updated.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html")


@app.route("/dashboard")
@login_required
def dashboard():
    total_collected = db.session.query(func.coalesce(func.sum(Transaction.paid_amount), 0)).scalar()
    potential_leakage = db.session.query(func.coalesce(func.sum(LeakAlert.estimated_loss), 0)).filter(
        LeakAlert.status.in_(OPEN_ALERT_STATUSES)
    ).scalar()
    recovered = db.session.query(func.coalesce(func.sum(RecoveryCase.recovered_amount), 0)).scalar()
    open_alerts = db.session.query(func.count(LeakAlert.id)).filter(
        LeakAlert.status.in_(OPEN_ALERT_STATUSES)
    ).scalar()
    total_transactions = db.session.query(func.count(Transaction.id)).scalar()
    recent_alerts = LeakAlert.query.order_by(LeakAlert.detected_at.desc()).limit(6).all()
    priority_recoveries = RecoveryCase.query.filter(
        RecoveryCase.status.in_(["Planned", "In Progress"])
    ).order_by(RecoveryCase.target_date.asc(), RecoveryCase.updated_at.desc()).limit(5).all()
    stats = [
        {"label": "Total Collected", "value": money_filter(total_collected), "tone": "blue"},
        {"label": "Potential Leakage", "value": money_filter(potential_leakage), "tone": "amber"},
        {"label": "Recovered Revenue", "value": money_filter(recovered), "tone": "violet"},
        {"label": "Open Alerts", "value": f"{open_alerts:,}", "tone": "red"},
    ]
    return render_template(
        "dashboard.html",
        stats=stats,
        recent_alerts=recent_alerts,
        priority_recoveries=priority_recoveries,
        transaction_count=total_transactions,
    )


@app.route("/database-test")
@roles_required("Admin")
def database_test():
    try:
        db.session.execute(text("SELECT 1"))
        return "Database connection successful."
    except Exception as error:
        return f"Database connection failed: {error}", 500


@app.route("/transactions")
@login_required
def transaction_list():
    try:
        transactions = _transaction_query().all()
    except ValueError as error:
        flash(str(error), "error")
        transactions = []
    return render_template(
        "transactions.html", transactions=transactions, payment_statuses=sorted(PAYMENT_STATUSES)
    )


@app.route("/transactions/export.csv")
@login_required
def transaction_export():
    transactions = _transaction_query().all()
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(CSV_HEADERS)
    for item in transactions:
        writer.writerow(
            [
                item.transaction_code,
                item.customer_name,
                item.transaction_date.isoformat(),
                item.expected_amount,
                item.billed_amount,
                item.paid_amount,
                item.discount_percent,
                item.payment_status,
                item.due_date.isoformat() if item.due_date else "",
                "yes" if item.service_active else "no",
            ]
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=revenueleak_transactions.csv"},
    )


@app.route("/transactions/template.csv")
@login_required
def transaction_csv_template():
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=CSV_HEADERS, lineterminator="\n")
    writer.writeheader()
    writer.writerow(
        {
            "transaction_code": "TXN-DEMO-001",
            "customer_name": "Demo Industries",
            "transaction_date": date.today().isoformat(),
            "expected_amount": "100000",
            "billed_amount": "78000",
            "paid_amount": "30000",
            "discount_percent": "25",
            "payment_status": "Overdue",
            "due_date": date.today().isoformat(),
            "service_active": "yes",
        }
    )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=revenueleak_transactions_template.csv"},
    )


@app.route("/transactions/import", methods=["GET", "POST"])
@roles_required("Admin", "Analyst")
def import_transactions():
    errors = []
    if request.method == "POST":
        upload = request.files.get("csv_file")
        if upload is None or not upload.filename:
            errors.append("Choose a CSV file before importing.")
        elif not upload.filename.lower().endswith(".csv"):
            errors.append("The selected file must end with .csv.")
        else:
            try:
                content = upload.read().decode("utf-8-sig")
                reader = csv.DictReader(io.StringIO(content))
                missing = [header for header in CSV_HEADERS if header not in (reader.fieldnames or [])]
                if missing:
                    errors.append("Missing columns: " + ", ".join(missing))
                else:
                    existing_codes = {
                        code for (code,) in db.session.query(Transaction.transaction_code).all()
                    }
                    batch_codes = set()
                    transactions = []
                    for row_number, row in enumerate(reader, start=2):
                        if row_number > 5001:
                            errors.append("The CSV can contain a maximum of 5,000 transactions.")
                            break
                        try:
                            transaction = _transaction_from_csv(row, row_number)
                            if transaction.transaction_code in existing_codes:
                                raise ValueError(
                                    f"Row {row_number}: transaction code {transaction.transaction_code} already exists."
                                )
                            if transaction.transaction_code in batch_codes:
                                raise ValueError(
                                    f"Row {row_number}: transaction code {transaction.transaction_code} is duplicated in the CSV."
                                )
                            batch_codes.add(transaction.transaction_code)
                            transactions.append(transaction)
                        except ValueError as error:
                            errors.append(str(error))
                            if len(errors) >= 12:
                                errors.append("More errors exist. Fix these first and upload again.")
                                break

                    if not transactions and not errors:
                        errors.append("The CSV contains no transaction rows.")
                    if not errors:
                        db.session.add_all(transactions)
                        db.session.flush()
                        _audit("Imported transactions", "Transaction", detail=f"{len(transactions)} rows")
                        db.session.commit()
                        flash(f"Successfully imported {len(transactions)} transactions.", "success")
                        return redirect(url_for("transaction_list"))
            except UnicodeDecodeError:
                errors.append("The CSV must be saved using UTF-8 encoding.")
            except Exception as error:
                db.session.rollback()
                errors.append(f"Import failed: {error}")
        if errors:
            db.session.rollback()
    return render_template("import_transactions.html", errors=errors, csv_headers=CSV_HEADERS)


@app.route("/transactions/add", methods=["GET", "POST"])
@roles_required("Admin", "Analyst")
def add_transaction():
    transaction = Transaction(service_active=True, transaction_date=date.today())
    if request.method == "POST":
        try:
            _fill_transaction(transaction)
            db.session.add(transaction)
            db.session.flush()
            _audit("Created transaction", "Transaction", transaction.id, transaction.transaction_code)
            db.session.commit()
            flash("Transaction added successfully.", "success")
            return redirect(url_for("transaction_list"))
        except (ValueError, TypeError) as error:
            db.session.rollback()
            flash(str(error), "error")
        except IntegrityError:
            db.session.rollback()
            flash("That transaction code already exists.", "error")
    return render_template(
        "add_transaction.html",
        transaction=transaction,
        page_title="Add transaction",
        submit_label="Save transaction",
    )


@app.route("/transactions/<int:transaction_id>/edit", methods=["GET", "POST"])
@roles_required("Admin", "Analyst")
def edit_transaction(transaction_id):
    transaction = db.get_or_404(Transaction, transaction_id)
    if request.method == "POST":
        try:
            _fill_transaction(transaction)
            _audit("Updated transaction", "Transaction", transaction.id, transaction.transaction_code)
            db.session.commit()
            flash("Transaction updated successfully.", "success")
            return redirect(url_for("transaction_list"))
        except (ValueError, TypeError) as error:
            db.session.rollback()
            flash(str(error), "error")
        except IntegrityError:
            db.session.rollback()
            flash("That transaction code already exists.", "error")
    return render_template(
        "add_transaction.html",
        transaction=transaction,
        page_title="Edit transaction",
        submit_label="Update transaction",
    )


@app.route("/transactions/<int:transaction_id>/delete", methods=["POST"])
@roles_required("Admin")
def delete_transaction(transaction_id):
    transaction = db.get_or_404(Transaction, transaction_id)
    code = transaction.transaction_code
    db.session.delete(transaction)
    _audit("Deleted transaction", "Transaction", transaction_id, code)
    db.session.commit()
    flash("Transaction and its alerts were deleted.", "success")
    return redirect(url_for("transaction_list"))


@app.route("/scan", methods=["POST"])
@roles_required("Admin", "Analyst")
def run_scan():
    detected_count = _scan_all_transactions()
    _audit("Ran AI leak scan", "Alert", detail=f"{detected_count} signals")
    db.session.commit()
    flash(f"AI leak scan complete. {detected_count} issue(s) detected or refreshed.", "success")
    return redirect(_safe_next("dashboard"))


@app.route("/alerts")
@login_required
def alert_list():
    try:
        alerts = _alert_query().all()
    except ValueError as error:
        flash(str(error), "error")
        alerts = []
    leak_types = [value for (value,) in db.session.query(LeakAlert.leak_type).distinct().all()]
    return render_template(
        "alerts.html",
        alerts=alerts,
        alert_statuses=sorted(ALERT_STATUSES),
        leak_types=sorted(leak_types),
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
@roles_required("Admin", "Analyst")
def update_alert_status(alert_id):
    alert = db.get_or_404(LeakAlert, alert_id)
    status = request.form.get("status")
    if status not in ALERT_STATUSES:
        flash("Choose a valid alert status.", "error")
    else:
        alert.status = status
        _audit("Updated alert status", "Alert", alert.id, status)
        db.session.commit()
        flash("Alert status updated.", "success")
    return redirect(_safe_next("alert_list"))


@app.route("/alerts/<int:alert_id>/recovery", methods=["GET", "POST"])
@roles_required("Admin", "Analyst")
def manage_recovery(alert_id):
    alert = db.get_or_404(LeakAlert, alert_id)
    recovery = alert.recovery
    if request.method == "POST":
        try:
            status = request.form.get("status", "Planned")
            priority = request.form.get("priority", "Medium")
            action_type = request.form.get("action_type", "Review invoice")
            if status not in RECOVERY_STATUSES:
                raise ValueError("Choose a valid recovery status.")
            if priority not in RECOVERY_PRIORITIES:
                raise ValueError("Choose a valid priority.")
            if action_type not in RECOVERY_ACTIONS:
                raise ValueError("Choose a valid recovery action.")
            recovered_amount = _money(request.form.get("recovered_amount", "0"), "Recovered amount")
            if recovered_amount > Decimal(alert.estimated_loss or 0):
                raise ValueError("Recovered amount cannot exceed the estimated loss.")
            owner_value = request.form.get("owner_id", "").strip()
            owner = db.session.get(User, int(owner_value)) if owner_value else None
            if owner_value and (owner is None or not owner.active):
                raise ValueError("Choose an active recovery owner.")

            if recovery is None:
                recovery = RecoveryCase(alert_id=alert.id)
                db.session.add(recovery)
            recovery.owner = owner
            recovery.priority = priority
            recovery.action_type = action_type
            recovery.status = status
            recovery.target_date = _parse_date(request.form.get("target_date"), "Target date")
            recovery.recovered_amount = recovered_amount
            recovery.notes = request.form.get("notes", "").strip()[:4000]

            if status == "Recovered":
                alert.status = "Recovered"
            elif status == "In Progress":
                alert.status = "In Review"
            elif status == "Closed":
                alert.status = "Recovered" if recovered_amount > 0 else "Resolved"
            elif alert.status == "Open":
                alert.status = "Confirmed"

            db.session.flush()
            _audit("Updated recovery case", "RecoveryCase", recovery.id, status)
            db.session.commit()
            flash("Recovery plan saved.", "success")
            return redirect(url_for("recovery_list"))
        except (ValueError, TypeError) as error:
            db.session.rollback()
            flash(str(error), "error")

    users = User.query.filter_by(active=True).order_by(User.name).all()
    return render_template(
        "recovery_form.html",
        alert=alert,
        recovery=recovery,
        users=users,
        recovery_statuses=sorted(RECOVERY_STATUSES),
        recovery_priorities=["Critical", "High", "Medium", "Low"],
        recovery_actions=sorted(RECOVERY_ACTIONS),
    )


@app.route("/recoveries")
@login_required
def recovery_list():
    query = RecoveryCase.query.join(LeakAlert).join(Transaction)
    status = request.args.get("status", "").strip()
    owner_id = request.args.get("owner", "").strip()
    search = request.args.get("q", "").strip()
    if status in RECOVERY_STATUSES:
        query = query.filter(RecoveryCase.status == status)
    if owner_id.isdigit():
        query = query.filter(RecoveryCase.owner_id == int(owner_id))
    if search:
        like = f"%{search}%"
        query = query.filter(
            or_(Transaction.transaction_code.ilike(like), Transaction.customer_name.ilike(like))
        )
    recoveries = query.order_by(RecoveryCase.updated_at.desc()).all()
    users = User.query.filter_by(active=True).order_by(User.name).all()
    return render_template(
        "recoveries.html",
        recoveries=recoveries,
        users=users,
        recovery_statuses=sorted(RECOVERY_STATUSES),
    )


@app.route("/analytics")
@login_required
def analytics():
    transactions = Transaction.query.order_by(Transaction.transaction_date).all()
    alerts = LeakAlert.query.all()
    recoveries = RecoveryCase.query.all()
    month_starts = []
    cursor = date.today().replace(day=1)
    for offset in range(5, -1, -1):
        year = cursor.year
        month = cursor.month - offset
        while month <= 0:
            year -= 1
            month += 12
        month_starts.append(date(year, month, 1))

    monthly = []
    for month_start in month_starts:
        next_month = (
            date(month_start.year + 1, 1, 1)
            if month_start.month == 12
            else date(month_start.year, month_start.month + 1, 1)
        )
        items = [t for t in transactions if month_start <= t.transaction_date < next_month]
        monthly.append(
            {
                "label": month_start.strftime("%b %Y"),
                "expected": sum((Decimal(t.expected_amount or 0) for t in items), Decimal("0")),
                "collected": sum((Decimal(t.paid_amount or 0) for t in items), Decimal("0")),
            }
        )
    month_max = max([item["expected"] for item in monthly] + [Decimal("1")])
    for item in monthly:
        item["expected_width"] = float(item["expected"] / month_max * 100)
        item["collected_width"] = float(item["collected"] / month_max * 100)

    type_totals = {}
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for alert in alerts:
        if alert.status != "False Positive":
            type_totals[alert.leak_type] = type_totals.get(alert.leak_type, Decimal("0")) + Decimal(
                alert.estimated_loss or 0
            )
        severity_counts[alert.severity] = severity_counts.get(alert.severity, 0) + 1
    type_max = max(list(type_totals.values()) + [Decimal("1")])
    leak_types = [
        {"label": label, "value": value, "width": float(value / type_max * 100)}
        for label, value in sorted(type_totals.items(), key=lambda item: item[1], reverse=True)
    ]

    detected_loss = sum(
        (Decimal(a.estimated_loss or 0) for a in alerts if a.status != "False Positive"), Decimal("0")
    )
    recovered_total = sum((Decimal(r.recovered_amount or 0) for r in recoveries), Decimal("0"))
    recovery_rate = float(recovered_total / detected_loss * 100) if detected_loss else 0
    open_loss = sum(
        (Decimal(a.estimated_loss or 0) for a in alerts if a.status in OPEN_ALERT_STATUSES), Decimal("0")
    )
    return render_template(
        "analytics.html",
        monthly=monthly,
        leak_types=leak_types,
        severity_counts=severity_counts,
        detected_loss=detected_loss,
        recovered_total=recovered_total,
        recovery_rate=recovery_rate,
        open_loss=open_loss,
    )


@app.route("/reports")
@login_required
def reports():
    try:
        alerts = _alert_query().all()
    except ValueError as error:
        flash(str(error), "error")
        alerts = []
    leak_types = [value for (value,) in db.session.query(LeakAlert.leak_type).distinct().all()]
    filtered_loss = sum((Decimal(item.estimated_loss or 0) for item in alerts), Decimal("0"))
    filtered_recovered = sum(
        (Decimal(item.recovery.recovered_amount or 0) for item in alerts if item.recovery), Decimal("0")
    )
    return render_template(
        "reports.html",
        alerts=alerts,
        filtered_loss=filtered_loss,
        filtered_recovered=filtered_recovered,
        alert_statuses=sorted(ALERT_STATUSES),
        leak_types=sorted(leak_types),
    )


@app.route("/reports/export.csv")
@login_required
def report_export():
    alerts = _alert_query().all()
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        [
            "transaction_code",
            "customer_name",
            "leak_type",
            "severity",
            "risk_score",
            "estimated_loss",
            "alert_status",
            "recovery_status",
            "recovered_amount",
            "owner",
            "detected_at",
            "explanation",
        ]
    )
    for alert in alerts:
        recovery = alert.recovery
        writer.writerow(
            [
                alert.transaction.transaction_code,
                alert.transaction.customer_name,
                alert.leak_type,
                alert.severity,
                alert.risk_score,
                alert.estimated_loss,
                alert.status,
                recovery.status if recovery else "",
                recovery.recovered_amount if recovery else "0",
                recovery.owner.name if recovery and recovery.owner else "",
                alert.detected_at.isoformat(),
                alert.explanation,
            ]
        )
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=revenueleak_alert_report.csv"},
    )


@app.route("/users", methods=["GET", "POST"])
@roles_required("Admin")
def user_list():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        company = request.form.get("company", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        role = request.form.get("role", "Analyst")
        if not name or not company or not email:
            flash("Name, company and email are required.", "error")
        elif len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif role not in USER_ROLES:
            flash("Choose a valid user role.", "error")
        else:
            user = User(
                name=name,
                company=company,
                email=email,
                role=role,
                active=True,
                approval_status="Active",
            )
            user.set_password(password)
            db.session.add(user)
            try:
                db.session.flush()
                _audit("Created user", "User", user.id, f"{email} · {role}")
                db.session.commit()
                flash("Team member created.", "success")
                return redirect(url_for("user_list"))
            except IntegrityError:
                db.session.rollback()
                flash("A user with that email already exists.", "error")
    users = User.query.order_by(
        (User.approval_status == "Pending").desc(), User.created_at.desc()
    ).all()
    audit_logs = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(15).all()
    return render_template("users.html", users=users, roles=sorted(USER_ROLES), audit_logs=audit_logs)


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@roles_required("Admin")
def toggle_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == g.user.id:
        flash("You cannot disable your own account.", "error")
    else:
        role = request.form.get("role", user.role)
        action = request.form.get("action", "toggle")
        if role not in USER_ROLES:
            flash("Choose a valid user role.", "error")
            return redirect(url_for("user_list"))
        user.role = role
        if action == "approve":
            user.active = True
            user.approval_status = "Active"
        elif action == "disable":
            user.active = False
            user.approval_status = "Disabled"
        elif action == "enable":
            user.active = True
            user.approval_status = "Active"
        else:
            user.active = not user.active
            user.approval_status = "Active" if user.active else "Disabled"
        _audit("Changed user access", "User", user.id, f"{user.approval_status} · {user.role}")
        db.session.commit()
        flash("User access updated.", "success")
    return redirect(url_for("user_list"))


@app.route("/demo-data", methods=["POST"])
@roles_required("Admin")
def seed_demo_data():
    added = _seed_demo_transactions()
    detected = _scan_all_transactions()
    _audit("Loaded portfolio demo data", "Transaction", detail=f"{added} rows, {detected} signals")
    db.session.commit()
    flash(f"Demo workspace ready: {added} transaction(s) added and {detected} signal(s) scanned.", "success")
    return redirect(url_for("dashboard"))


@app.errorhandler(400)
@app.errorhandler(403)
@app.errorhandler(404)
@app.errorhandler(413)
def friendly_error(error):
    messages = {
        400: "That request could not be completed.",
        403: "Your account does not have permission for that action.",
        404: "The page you requested does not exist.",
        413: "The uploaded file is larger than 5 MB.",
    }
    return render_template(
        "error.html",
        error_code=error.code,
        error_message=messages.get(error.code, "Something went wrong."),
    ), error.code


if __name__ == "__main__":
    app.run(debug=app.config.get("DEBUG", False))
