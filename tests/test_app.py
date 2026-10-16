import io
import os
import unittest


os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["SECRET_KEY"] = "automated-test-key"
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "AdminTest123"

from app import app, db
from models import LeakAlert, RecoveryCase, Transaction, User


class RevenueLeakAppTests(unittest.TestCase):
    def setUp(self):
        app.config.update(TESTING=True)
        self.client = app.test_client()
        with app.app_context():
            db.drop_all()
            db.create_all()
            admin = User(name="Admin", email="admin@test.local", role="Admin")
            admin.set_password("AdminTest123")
            viewer = User(name="Viewer", email="viewer@test.local", role="Viewer")
            viewer.set_password("ViewerTest123")
            db.session.add_all([admin, viewer])
            db.session.commit()

    def csrf(self, path="/login"):
        self.client.get(path)
        with self.client.session_transaction() as session:
            return session["_csrf_token"]

    def login(self, email="admin@test.local", password="AdminTest123"):
        token = self.csrf()
        return self.client.post(
            "/login",
            data={"_csrf_token": token, "email": email, "password": password},
            follow_redirects=True,
        )

    def post(self, path, data=None, **kwargs):
        token = self.csrf(path if path == "/login" else "/dashboard")
        payload = dict(data or {})
        payload["_csrf_token"] = token
        return self.client.post(path, data=payload, **kwargs)

    def test_authentication_and_permissions(self):
        self.assertEqual(self.client.get("/dashboard").status_code, 302)
        response = self.login("viewer@test.local", "ViewerTest123")
        self.assertIn(b"Revenue dashboard", response.data)
        self.assertEqual(self.client.get("/transactions/add").status_code, 403)
        self.assertEqual(self.client.post("/scan", data={}).status_code, 400)

    def test_signup_requires_admin_approval(self):
        token = self.csrf("/register")
        response = self.client.post(
            "/register",
            data={
                "_csrf_token": token,
                "name": "New Analyst",
                "company": "Example Finance",
                "email": "new@example.com",
                "password": "StrongPass123",
                "confirm_password": "StrongPass123",
            },
            follow_redirects=True,
        )
        self.assertIn(b"administrator must approve", response.data)

        response = self.login("new@example.com", "StrongPass123")
        self.assertIn(b"waiting for administrator approval", response.data)

        self.login()
        with app.app_context():
            user = User.query.filter_by(email="new@example.com").one()
            user_id = user.id
            self.assertEqual(user.approval_status, "Pending")

        response = self.post(
            f"/users/{user_id}/toggle",
            data={"action": "approve", "role": "Analyst"},
            follow_redirects=True,
        )
        self.assertIn(b"User access updated", response.data)

        self.post("/logout")
        response = self.login("new@example.com", "StrongPass123")
        self.assertIn(b"Revenue dashboard", response.data)

    def test_complete_admin_workflow_and_all_pages(self):
        self.login()
        response = self.post("/demo-data", follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        with app.app_context():
            self.assertEqual(Transaction.query.count(), 12)
            self.assertGreater(LeakAlert.query.count(), 0)
            self.assertIsNotNone(LeakAlert.query.filter_by(leak_type="AI Anomaly").first())
            alert = LeakAlert.query.order_by(LeakAlert.estimated_loss.desc()).first()
            alert_id = alert.id
            recovery_amount = min(float(alert.estimated_loss), 1000)

        response = self.post(
            f"/alerts/{alert_id}/recovery",
            data={
                "action_type": "Correct billing",
                "priority": "High",
                "status": "In Progress",
                "target_date": "2030-01-15",
                "recovered_amount": str(recovery_amount),
                "notes": "Automated workflow test",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Recovery pipeline", response.data)
        with app.app_context():
            self.assertEqual(RecoveryCase.query.count(), 1)

        for path in [
            "/dashboard",
            "/transactions",
            "/alerts",
            "/recoveries",
            "/analytics",
            "/reports",
            "/users",
            "/profile",
            "/database-test",
        ]:
            with self.subTest(path=path):
                response = self.client.get(path)
                self.assertEqual(response.status_code, 200)

        csv_response = self.client.get("/reports/export.csv")
        self.assertEqual(csv_response.status_code, 200)
        self.assertIn(b"transaction_code", csv_response.data)

    def test_transaction_csv_import_and_duplicate_protection(self):
        self.login()
        content = (
            "transaction_code,customer_name,transaction_date,expected_amount,billed_amount,"
            "paid_amount,discount_percent,payment_status,due_date,service_active\n"
            "CSV-001,CSV Customer,2026-08-01,10000,8000,4000,5,Overdue,2026-08-10,yes\n"
        )
        token = self.csrf("/transactions/import")
        response = self.client.post(
            "/transactions/import",
            data={"_csrf_token": token, "csv_file": (io.BytesIO(content.encode()), "data.csv")},
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertIn(b"Successfully imported 1 transactions", response.data)

        token = self.csrf("/transactions/import")
        response = self.client.post(
            "/transactions/import",
            data={"_csrf_token": token, "csv_file": (io.BytesIO(content.encode()), "data.csv")},
            content_type="multipart/form-data",
        )
        self.assertIn(b"already exists", response.data)
        with app.app_context():
            self.assertEqual(Transaction.query.count(), 1)

    def test_csrf_rejects_untrusted_posts(self):
        response = self.client.post(
            "/login", data={"email": "admin@test.local", "password": "AdminTest123"}
        )
        self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
