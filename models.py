from datetime import datetime, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(180), unique=True, nullable=False, index=True)
    company = db.Column(db.String(120), nullable=False, default="")
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="Analyst")
    active = db.Column(db.Boolean, nullable=False, default=True)
    approval_status = db.Column(db.String(20), nullable=False, default="Active")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    recoveries = db.relationship("RecoveryCase", back_populates="owner", lazy=True)

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(db.Integer, primary_key=True)
    transaction_code = db.Column(db.String(50), unique=True, nullable=False, index=True)
    customer_name = db.Column(db.String(120), nullable=False)
    transaction_date = db.Column(db.Date, nullable=False)
    expected_amount = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    billed_amount = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    paid_amount = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    discount_percent = db.Column(db.Numeric(5, 2), nullable=False, default=0)
    payment_status = db.Column(db.String(30), nullable=False, default="Pending")
    due_date = db.Column(db.Date, nullable=True)
    service_active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    alerts = db.relationship(
        "LeakAlert",
        back_populates="transaction",
        cascade="all, delete-orphan",
        lazy=True,
    )


class LeakAlert(db.Model):
    __tablename__ = "leak_alerts"
    __table_args__ = (
        db.UniqueConstraint("transaction_id", "leak_type", name="uq_transaction_leak_type"),
    )

    id = db.Column(db.Integer, primary_key=True)
    transaction_id = db.Column(
        db.Integer,
        db.ForeignKey("transactions.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    leak_type = db.Column(db.String(80), nullable=False)
    estimated_loss = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    severity = db.Column(db.String(20), nullable=False, default="Low")
    explanation = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(30), nullable=False, default="Open")
    detected_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    transaction = db.relationship("Transaction", back_populates="alerts")
    recovery = db.relationship(
        "RecoveryCase",
        back_populates="alert",
        cascade="all, delete-orphan",
        uselist=False,
    )


class RecoveryCase(db.Model):
    __tablename__ = "recovery_cases"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(
        db.Integer,
        db.ForeignKey("leak_alerts.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    owner_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    priority = db.Column(db.String(20), nullable=False, default="Medium")
    action_type = db.Column(db.String(50), nullable=False, default="Review invoice")
    status = db.Column(db.String(30), nullable=False, default="Planned")
    target_date = db.Column(db.Date, nullable=True)
    recovered_amount = db.Column(db.Numeric(12, 2), nullable=False, default=0)
    notes = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utcnow,
        onupdate=utcnow,
    )

    alert = db.relationship("LeakAlert", back_populates="recovery")
    owner = db.relationship("User", back_populates="recoveries")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    entity_type = db.Column(db.String(40), nullable=False)
    entity_id = db.Column(db.Integer, nullable=True)
    detail = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    actor = db.relationship("User")
