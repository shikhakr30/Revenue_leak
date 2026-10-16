from datetime import date
from decimal import Decimal
from statistics import median, pstdev


ZERO = Decimal("0")


def _decimal(value) -> Decimal:
    return Decimal(value or 0)


def _severity(loss: Decimal, score: int) -> str:
    if score >= 80 or loss >= Decimal("50000"):
        return "Critical"
    if score >= 60 or loss >= Decimal("15000"):
        return "High"
    if score >= 35 or loss >= Decimal("5000"):
        return "Medium"
    return "Low"


def _features(transaction) -> dict[str, float]:
    expected = _decimal(transaction.expected_amount)
    billed = _decimal(transaction.billed_amount)
    paid = _decimal(transaction.paid_amount)
    discount = _decimal(transaction.discount_percent)
    overdue_days = 0
    if transaction.due_date and transaction.due_date < date.today():
        overdue_days = (date.today() - transaction.due_date).days

    return {
        "underbilling ratio": float(max(expected - billed, ZERO) / expected) if expected else 0.0,
        "unpaid ratio": float(max(billed - paid, ZERO) / billed) if billed else 0.0,
        "discount rate": float(discount / 100),
        "overdue duration": min(overdue_days / 90, 3.0),
    }


def _robust_z(value: float, values: list[float]) -> tuple[float, float]:
    """Return a robust anomaly distance and the peer median."""
    center = median(values)
    deviations = [abs(item - center) for item in values]
    mad = median(deviations)
    if mad > 0:
        return abs(0.6745 * (value - center) / mad), center

    spread = pstdev(values)
    if spread > 0:
        return abs((value - center) / spread), center
    return 0.0, center


def detect_transaction(transaction, peer_transactions=None) -> list[dict]:
    """Run explainable rules plus an unsupervised peer-anomaly model."""
    alerts = []
    expected = _decimal(transaction.expected_amount)
    billed = _decimal(transaction.billed_amount)
    paid = _decimal(transaction.paid_amount)
    discount = _decimal(transaction.discount_percent)

    underbilling_loss = max(expected - billed, ZERO)
    if expected > 0 and billed == 0 and transaction.service_active:
        score = 98
        alerts.append(
            {
                "leak_type": "Unbilled Active Service",
                "estimated_loss": expected,
                "risk_score": score,
                "severity": _severity(expected, score),
                "explanation": (
                    "Rule signal: the service is active but no amount was billed against the expected value."
                ),
            }
        )
    elif expected > 0 and underbilling_loss > 0:
        gap_percent = (underbilling_loss / expected) * 100
        score = min(95, 45 + int(gap_percent))
        alerts.append(
            {
                "leak_type": "Underbilling",
                "estimated_loss": underbilling_loss,
                "risk_score": score,
                "severity": _severity(underbilling_loss, score),
                "explanation": (
                    f"Rule signal: billed amount is {gap_percent:.1f}% below the expected contract amount."
                ),
            }
        )

    overdue_loss = max(billed - paid, ZERO)
    if (
        transaction.due_date
        and transaction.due_date < date.today()
        and overdue_loss > 0
        and transaction.payment_status not in {"Paid", "Refunded"}
    ):
        overdue_days = (date.today() - transaction.due_date).days
        score = min(98, 50 + overdue_days)
        alerts.append(
            {
                "leak_type": "Overdue Payment",
                "estimated_loss": overdue_loss,
                "risk_score": score,
                "severity": _severity(overdue_loss, score),
                "explanation": (
                    f"Rule signal: ₹{overdue_loss:,.2f} remains unpaid {overdue_days} day(s) after the due date."
                ),
            }
        )

    if discount > Decimal("20") and billed > 0:
        standard_value = billed / max(Decimal("0.01"), Decimal("1") - discount / 100)
        discount_loss = max(standard_value - billed, ZERO)
        score = min(90, 35 + int(discount))
        alerts.append(
            {
                "leak_type": "Excessive Discount",
                "estimated_loss": discount_loss,
                "risk_score": score,
                "severity": _severity(discount_loss, score),
                "explanation": (
                    f"Rule signal: the {discount:.1f}% discount is above the 20% review threshold."
                ),
            }
        )

    peers = list(peer_transactions or [])
    if len(peers) >= 5:
        current_features = _features(transaction)
        peer_features = [_features(item) for item in peers]
        distances = []
        for feature_name, current_value in current_features.items():
            values = [features[feature_name] for features in peer_features]
            distance, center = _robust_z(current_value, values)
            distances.append((distance, feature_name, current_value, center))

        distance, feature_name, current_value, center = max(distances)
        if distance >= 2.5 and current_value > center:
            model_loss = max(underbilling_loss, overdue_loss)
            if model_loss <= 0:
                model_loss = max(expected * Decimal(str(current_value - center)), ZERO)
            score = min(99, 52 + int(distance * 9))
            alerts.append(
                {
                    "leak_type": "AI Anomaly",
                    "estimated_loss": model_loss,
                    "risk_score": score,
                    "severity": _severity(model_loss, score),
                    "explanation": (
                        "Unsupervised model signal: "
                        f"{feature_name} is {distance:.1f} robust deviations above the peer baseline "
                        f"({current_value * 100:.1f}% versus {center * 100:.1f}% typical)."
                    ),
                }
            )

    return alerts
